use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use ethers::{
    providers::{Http, HttpRateLimitRetryPolicy, Provider, RetryClient, RetryClientBuilder},
    types::Address,
};
use jsonrpsee::{
    server::{middleware::proxy_get_request::ProxyGetRequestLayer, ServerBuilder},
    RpcModule,
};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tonic::{
    async_trait,
    transport::{Channel, Uri},
};
use tonic_health::pb::health_client::HealthClient;
use tracing::info;
use url::Url;

use super::{eth::EthApiServer, ApiNamespace};
use crate::{
    common::{
        contracts::i_entry_point::IEntryPoint,
        eth,
        handle::Task,
        precheck,
        protos::builder::builder_client::BuilderClient,
        server::{self, format_socket_addr},
        types::EntryPointLike,
    },
    op_pool::{connect_remote_pool_client, LocalPoolClient, PoolClient, PoolClientMode},
    rpc::{
        debug::{DebugApi, DebugApiServer},
        eth::{estimation, EthApi},
        health::{LocalHealthCheck, RemoteHealthCheck, SystemApiServer},
        metrics::RpcMetricsLogger,
        rundler::{RundlerApi, RundlerApiServer},
    },
};

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub host: String,
    pub builder_url: String,
    pub entry_points: Vec<Address>,
    pub chain_id: u64,
    pub api_namespaces: Vec<ApiNamespace>,
    pub rpc_url: String,
    pub precheck_settings: precheck::Settings,
    pub eth_api_settings: eth::Settings,
    pub estimation_settings: estimation::Settings,
    pub rpc_timeout: Duration,
    pub max_connections: u32,
    pub pool_client_mode: PoolClientMode,
}

#[derive(Debug)]
pub struct RpcTask {
    args: Args,
}

#[async_trait]
impl Task for RpcTask {
    async fn run(&mut self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let addr: SocketAddr = format_socket_addr(&self.args.host, self.args.port).parse()?;
        tracing::info!("Starting rpc server on {}", addr);

        if self.args.entry_points.is_empty() {
            bail!("No entry points provided");
        }

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
        let entry_points = self
            .args
            .entry_points
            .iter()
            .map(|addr| IEntryPoint::new(*addr, provider.clone()))
            .collect();

        // TODO(danc) local builder client
        let builder_client =
            Self::connect_remote_builder_client(&self.args.builder_url, shutdown_token.clone())
                .await?;
        info!("Connected to builder service at {}", self.args.builder_url);

        let mut module = RpcModule::new(());
        match &self.args.pool_client_mode {
            PoolClientMode::Local {
                req_sender,
                new_heads_receiver,
            } => {
                let pool_client =
                    LocalPoolClient::new(req_sender.clone(), new_heads_receiver.resubscribe());
                self.attach_namespaces(
                    provider,
                    entry_points,
                    pool_client.clone(),
                    builder_client,
                    &mut module,
                )?;

                module.merge(LocalHealthCheck::new(pool_client).into_rpc())?;
            }
            PoolClientMode::Remote { url } => {
                let pool_client = connect_remote_pool_client(url, shutdown_token.clone()).await?;
                info!("Connected to op_pool service at {}", url);
                self.attach_namespaces(
                    provider,
                    entry_points,
                    pool_client,
                    builder_client,
                    &mut module,
                )?;

                let builder_uri = Uri::from_str(&self.args.builder_url)
                    .context("should be a valid URI for op_pool")?;
                let op_pool_uri =
                    Uri::from_str(url).context("should be a valid URI for op_pool")?;

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
                module.merge(
                    RemoteHealthCheck::new(op_pool_health_client, builder_health_client).into_rpc(),
                )?;
            }
        }

        // Set up health check endpoint via GET /health registers the jsonrpc handler
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

    async fn connect_remote_builder_client(
        url: &str,
        shutdown_token: CancellationToken,
    ) -> anyhow::Result<BuilderClient<Channel>> {
        select! {
            _ = shutdown_token.cancelled() => {
                tracing::error!("bailing from conneting client, server shutting down");
                bail!("Server shutting down")
            }
            res = server::connect_with_retries("builder from common", url, BuilderClient::connect) => {
                res.context("should connect to builder")
            }
        }
    }

    fn attach_namespaces<C: PoolClient + Clone, E: EntryPointLike + Clone>(
        &self,
        provider: Arc<Provider<RetryClient<Http>>>,
        entry_points: Vec<E>,
        pool_client: C,
        builder_client: BuilderClient<Channel>,
        module: &mut RpcModule<()>,
    ) -> anyhow::Result<()> {
        for api in &self.args.api_namespaces {
            match api {
                ApiNamespace::Eth => module.merge(
                    EthApi::new(
                        provider.clone(),
                        entry_points.clone(),
                        self.args.chain_id,
                        pool_client.clone(),
                        self.args.eth_api_settings,
                        self.args.estimation_settings,
                    )
                    .into_rpc(),
                )?,
                ApiNamespace::Debug => module
                    .merge(DebugApi::new(pool_client.clone(), builder_client.clone()).into_rpc())?,
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

        Ok(())
    }
}
