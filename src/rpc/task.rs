use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use ethers::{
    providers::{Http, HttpRateLimitRetryPolicy, Provider, RetryClientBuilder},
    types::{Address, H256},
};
use jsonrpsee::{
    server::{middleware::proxy_get_request::ProxyGetRequestLayer, ServerBuilder},
    RpcModule,
};
use tokio::{select, try_join};
use tokio_util::sync::CancellationToken;
use tonic::{
    async_trait,
    transport::{Channel, Uri},
};
use tonic_health::pb::health_client::HealthClient;
use tracing::info;
use url::Url;

use super::ApiNamespace;
use crate::{
    common::{
        contracts::i_entry_point::IEntryPoint,
        handle::Task,
        mempool::MempoolConfig,
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
        rundler::{RundlerApi, RundlerApiServer},
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
    pub rpc_timeout: Duration,
    pub max_connections: u32,
    pub mempool_configs: HashMap<H256, MempoolConfig>,
}

#[derive(Debug)]
pub struct RpcTask {
    args: Args,
}

#[async_trait]
impl Task for RpcTask {
    async fn run(&self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let addr: SocketAddr = format_socket_addr(&self.args.host, self.args.port).parse()?;
        tracing::info!("Starting rpc server on {}", addr);
        tracing::info!("Mempool config: {:?}", self.args.mempool_configs);

        let mut module = RpcModule::new(());

        let parsed_url = Url::parse(&self.args.rpc_url).context("Invalid RPC URL")?;
        let http = Http::new(parsed_url);

        // right now this retry policy will retry only on 429ish errors OR connectivity errors
        let client = RetryClientBuilder::default()
            // these retries are if the server returns a 429
            .rate_limit_retries(10)
            // these retries are if the connection is dubious
            .timeout_retries(3)
            .initial_backoff(Duration::from_millis(500))
            .build(http, Box::<HttpRateLimitRetryPolicy>::default());

        let provider = Arc::new(Provider::new(client));

        let op_pool_uri =
            Uri::from_str(&self.args.pool_url).context("should be a valid URI for op_pool")?;
        let builder_uri =
            Uri::from_str(&self.args.builder_url).context("should be a valid URI for op_pool")?;
        let (op_pool_client, builder_client) = Self::connect_clients_with_shutdown(
            &self.args.pool_url,
            &self.args.builder_url,
            shutdown_token.clone(),
        )
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
        info!("Connected to op_pool service at {}", self.args.pool_url);
        info!("Connected to builder service at {}", self.args.builder_url);

        if self.args.entry_points.is_empty() {
            bail!("No entry points provided");
        }

        let entry_point_addrs = &self.args.entry_points;
        let mut entry_points = vec![];

        for entry in entry_point_addrs {
            let entry = IEntryPoint::new(*entry, provider.clone());
            entry_points.push(entry);
        }

        for api in &self.args.api_namespaces {
            match api {
                ApiNamespace::Eth => module.merge(
                    EthApi::new(
                        provider.clone(),
                        entry_points.clone(),
                        self.args.chain_id,
                        op_pool_client.clone(),
                        self.args.precheck_settings,
                        self.args.sim_settings,
                        self.args.estimation_settings,
                        self.args.mempool_configs.clone(),
                    )
                    .into_rpc(),
                )?,
                ApiNamespace::Debug => module.merge(
                    DebugApi::new(op_pool_client.clone(), builder_client.clone()).into_rpc(),
                )?,
                ApiNamespace::Rundler => module.merge(
                    RundlerApi::new(
                        provider.clone(),
                        self.args.chain_id,
                        self.args.precheck_settings,
                    )
                    .into_rpc(),
                )?,
            }
        }

        // Set up health check endpoint via GET /health
        // registers the jsonrpc handler
        // NOTE: I couldn't use module.register_async_method because it requires async move
        // and neither the clients or the args.*_url are copyable
        module.merge(SystemApi::new(op_pool_health_client, builder_health_client).into_rpc())?;
        let service_builder = tower::ServiceBuilder::new()
            // Proxy `GET /health` requests to internal `system_health` method.
            .layer(ProxyGetRequestLayer::new("/health", "system_health")?)
            .timeout(self.args.rpc_timeout);

        let server = ServerBuilder::default()
            .set_logger(RpcMetricsLogger)
            .set_middleware(service_builder)
            .max_connections(self.args.max_connections)
            .http_only()
            .build(addr)
            .await?;
        let handle = server.start(module)?;

        info!("Started RPC server");

        tokio::select! {
            _ = handle.stopped() => {
                tracing::error!("RPC server stopped unexpectedly");
                bail!("RPC server stopped unexpectedly")
            }
            _ = shutdown_token.cancelled() => {
                tracing::info!("Server shutdown");
                Ok(())
            }
        }
    }
}

impl RpcTask {
    pub fn new(args: Args) -> RpcTask {
        Self { args }
    }

    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }

    async fn connect_clients_with_shutdown(
        op_pool_url: &str,
        builder_url: &str,
        shutdown_token: CancellationToken,
    ) -> anyhow::Result<(OpPoolClient<Channel>, BuilderClient<Channel>)> {
        select! {
            _ = shutdown_token.cancelled() => {
                tracing::error!("bailing from conneting client, server shutting down");
                bail!("Server shutting down")
            }
            res = async {
                try_join!(
                    server::connect_with_retries("op pool from common", op_pool_url, OpPoolClient::connect),
                    server::connect_with_retries("builder from common", builder_url, BuilderClient::connect)
                )
                .context("should connect to op pool and builder")
            } => {
                res
            }
        }
    }
}
