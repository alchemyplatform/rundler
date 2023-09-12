use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use async_trait::async_trait;
use ethers::{
    providers::{Http, HttpRateLimitRetryPolicy, Provider, RetryClient, RetryClientBuilder},
    types::Address,
};
use jsonrpsee::{
    server::{middleware::ProxyGetRequestLayer, ServerBuilder},
    RpcModule,
};
use rundler_builder::BuilderServer;
use rundler_pool::PoolServer;
use rundler_provider::EntryPoint;
use rundler_sim::{EstimationSettings, PrecheckSettings};
use rundler_task::{
    server::{format_socket_addr, HealthCheck},
    Task,
};
use rundler_types::contracts::i_entry_point::IEntryPoint;
use tokio_util::sync::CancellationToken;
use tracing::info;
use url::Url;

use crate::{
    debug::{DebugApi, DebugApiServer},
    eth::{EthApi, EthApiServer, EthApiSettings},
    health::{HealthChecker, SystemApiServer},
    metrics::RpcMetricsLogger,
    rundler::{RundlerApi, RundlerApiServer},
    types::ApiNamespace,
};

/// RPC server arguments.
#[derive(Debug)]
pub struct Args {
    /// Port to listen on.
    pub port: u16,
    /// Host to listen on.
    pub host: String,
    /// List of supported entry points.
    pub entry_points: Vec<Address>,
    /// Chain ID.
    pub chain_id: u64,
    /// List of API namespaces to enable.
    pub api_namespaces: Vec<ApiNamespace>,
    /// Full node RPC URL to use.
    pub rpc_url: String,
    /// Precheck settings.
    pub precheck_settings: PrecheckSettings,
    /// eth_ API settings.
    pub eth_api_settings: EthApiSettings,
    /// Estimation settings.
    pub estimation_settings: EstimationSettings,
    /// RPC timeout.
    pub rpc_timeout: Duration,
    /// Max number of connections.
    pub max_connections: u32,
}

/// JSON-RPC server task.
#[derive(Debug)]
pub struct RpcTask<P, B> {
    args: Args,
    pool: P,
    builder: B,
}

#[async_trait]
impl<P, B> Task for RpcTask<P, B>
where
    P: PoolServer + HealthCheck + Clone,
    B: BuilderServer + HealthCheck + Clone,
{
    async fn run(mut self: Box<Self>, shutdown_token: CancellationToken) -> anyhow::Result<()> {
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

        let mut module = RpcModule::new(());
        self.attach_namespaces(provider, entry_points, &mut module)?;

        let servers: Vec<Box<dyn HealthCheck>> =
            vec![Box::new(self.pool.clone()), Box::new(self.builder.clone())];
        let health_checker = HealthChecker::new(servers);
        module.merge(health_checker.into_rpc())?;

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
        let handle = server.start(module);

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

impl<P, B> RpcTask<P, B>
where
    P: PoolServer + HealthCheck + Clone,
    B: BuilderServer + HealthCheck + Clone,
{
    /// Creates a new RPC server task.
    pub fn new(args: Args, pool: P, builder: B) -> Self {
        Self {
            args,
            pool,
            builder,
        }
    }

    /// Converts the task into a boxed trait object.
    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }

    fn attach_namespaces<E: EntryPoint + Clone>(
        &self,
        provider: Arc<Provider<RetryClient<Http>>>,
        entry_points: Vec<E>,
        module: &mut RpcModule<()>,
    ) -> anyhow::Result<()> {
        for api in &self.args.api_namespaces {
            match api {
                ApiNamespace::Eth => module.merge(
                    EthApi::new(
                        provider.clone(),
                        entry_points.clone(),
                        self.args.chain_id,
                        self.pool.clone(),
                        self.args.eth_api_settings,
                        self.args.estimation_settings,
                    )
                    .into_rpc(),
                )?,
                ApiNamespace::Debug => module
                    .merge(DebugApi::new(self.pool.clone(), self.builder.clone()).into_rpc())?,
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
