use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use ethers::{
    providers::{HttpRateLimitRetryPolicy, Provider, RetryClientBuilder},
    types::Address,
};
use jsonrpsee::{
    server::{middleware::proxy_get_request::ProxyGetRequestLayer, ServerBuilder},
    RpcModule,
};
use reqwest_middleware::ClientBuilder;
use reqwest_tracing::TracingMiddleware;
use tokio::{
    select,
    sync::{broadcast, mpsc},
    try_join,
};
use tonic::transport::{Channel, Uri};
use tonic_health::pb::health_client::HealthClient;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::info;
use url::Url;

use super::ApiNamespace;
use crate::{
    common::{
        precheck,
        protos::{builder::builder_client::BuilderClient, op_pool::op_pool_client::OpPoolClient},
        server::{self, format_socket_addr},
        simulation,
    },
    rpc::{
        debug::{DebugApi, DebugApiServer},
        eth::{estimation, EthApi, EthApiServer},
        health::{SystemApi, SystemApiServer},
        metrics::RpcMetricsLogger,
        provider::MiddlewareProvider,
    },
};

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub host: String,
    pub pool_url: String,
    pub builder_url: String,
    pub entry_points: Vec<Address>,
    pub chain_id: u64,
    pub api_namespaces: Vec<ApiNamespace>,
    pub rpc_url: String,
    pub precheck_settings: precheck::Settings,
    pub sim_settings: simulation::Settings,
    pub estimation_settings: estimation::Settings,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format_socket_addr(&args.host, args.port).parse()?;
    tracing::info!("Starting server on {}", addr);

    let mut module = RpcModule::new(());

    let parsed_url = Url::parse(&args.rpc_url).context("Invalid RPC URL")?;
    let reqwest_client = reqwest::Client::builder().build()?;
    let client = ClientBuilder::new(reqwest_client)
        .with(TracingMiddleware::default())
        .build();
    let http = MiddlewareProvider::new_with_client(parsed_url, client);

    // right now this retry policy will retry only on 429ish errors OR connectivity errors
    let client = RetryClientBuilder::default()
        // these retries are if the server returns a 429
        .rate_limit_retries(10)
        // these retries are if the connection is dubious
        .timeout_retries(3)
        .initial_backoff(Duration::from_millis(500))
        .build(http, Box::<HttpRateLimitRetryPolicy>::default());

    let provider = Arc::new(Provider::new(client));

    let op_pool_uri = Uri::from_str(&args.pool_url).context("should be a valid URI for op_pool")?;
    let builder_uri =
        Uri::from_str(&args.builder_url).context("should be a valid URI for op_pool")?;
    let (op_pool_client, builder_client) =
        connect_clients_with_shutdown(&args.pool_url, &args.builder_url, shutdown_rx.resubscribe())
            .await?;

    let op_pool_health_client = HealthClient::new(
        Channel::builder(op_pool_uri)
            .connect()
            .await
            .context("should have connected to op_pool health service channel")?,
    );
    let builder_health_client = HealthClient::new(
        Channel::builder(builder_uri)
            .connect()
            .await
            .context("should have connected to builder health service channel")?,
    );
    info!("Connected to op_pool service at {}", args.pool_url);
    info!("Connected to builder service at {}", args.builder_url);

    if args.entry_points.is_empty() {
        bail!("No entry points provided");
    }

    for api in args.api_namespaces {
        match api {
            ApiNamespace::Eth => module.merge(
                EthApi::new(
                    provider.clone(),
                    args.entry_points.clone(),
                    args.chain_id,
                    // NOTE: this clone is cheap according to the docs because all it's doing is copying the reference to the channel
                    op_pool_client.clone(),
                    args.precheck_settings,
                    args.sim_settings,
                    args.estimation_settings,
                )
                .into_rpc(),
            )?,
            ApiNamespace::Debug => module
                .merge(DebugApi::new(op_pool_client.clone(), builder_client.clone()).into_rpc())?,
        }
    }

    // Set up health check endpoint via GET /health and add a tracing layer
    module.merge(SystemApi::new(op_pool_health_client, builder_health_client).into_rpc())?;
    let service_builder = tower::ServiceBuilder::new()
        .layer(
            TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::new().include_headers(true)),
        )
        // Proxy `GET /health` requests to internal `system_health` method.
        .layer(ProxyGetRequestLayer::new("/health", "system_health")?)
        .timeout(Duration::from_secs(2));

    let server = ServerBuilder::default()
        .set_logger(RpcMetricsLogger)
        .set_middleware(service_builder)
        .http_only()
        .build(addr)
        .await?;
    let handle = server.start(module)?;

    info!("Started rpc server");

    tokio::select! {
        _ = handle.stopped() => {
            tracing::error!("Server stopped unexpectedly");
            bail!("RPC server stopped unexpectedly")
        }
        _ = shutdown_rx.recv() => {
            tracing::info!("Server shutdown");
            Ok(())
        }
    }
}

async fn connect_clients_with_shutdown(
    op_pool_url: &str,
    builder_url: &str,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> anyhow::Result<(OpPoolClient<Channel>, BuilderClient<Channel>)> {
    select! {
        _ = shutdown_rx.recv() => {
            tracing::error!("bailing from conneting client, server shutting down");
            bail!("Server shutting down")
        }
        res = async {
            try_join!(
                server::connect_with_retries(op_pool_url, OpPoolClient::connect),
                server::connect_with_retries(builder_url, BuilderClient::connect)
            )
            .context("should connect to op pool and builder")
        } => {
            res
        }
    }
}
