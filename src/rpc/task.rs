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
use tokio::sync::{broadcast, mpsc};
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
    builder::{
        connect_remote_builder_client, BuilderClient, LocalBuilderClient, LocalBuilderServerRequest,
    },
    common::{handle::Task, server::format_socket_addr},
    op_pool::{
        connect_remote_pool_client, LocalPoolClient, LocalPoolServerRequest, NewBlock, PoolClient,
    },
    rpc::{
        debug::{DebugApi, DebugApiServer},
        eth::{estimation, EthApi, EthApiServer},
        health::{LocalHealthCheck, RemoteHealthCheck, SystemApiServer},
        metrics::RpcMetricsLogger,
    },
};

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub host: String,
    pub entry_points: Vec<Address>,
    pub chain_id: u64,
    pub api_namespaces: Vec<ApiNamespace>,
    pub rpc_url: String,
    pub estimation_settings: estimation::Settings,
    pub rpc_timeout: Duration,
    pub client_mode: ClientMode,
}

#[derive(Debug)]
pub enum ClientMode {
    Local {
        pool_sender: mpsc::Sender<LocalPoolServerRequest>,
        pool_block_receiver: broadcast::Receiver<NewBlock>,
        builder_sender: mpsc::Sender<LocalBuilderServerRequest>,
    },
    Remote {
        pool_url: String,
        builder_url: String,
    },
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

        let mut module = RpcModule::new(());
        match &self.args.client_mode {
            ClientMode::Local {
                pool_sender,
                pool_block_receiver,
                builder_sender,
            } => {
                let pool_client =
                    LocalPoolClient::new(pool_sender.clone(), pool_block_receiver.resubscribe());
                let builder_client = LocalBuilderClient::new(builder_sender.clone());

                self.attach_namespaces(
                    provider,
                    pool_client.clone(),
                    builder_client.clone(),
                    &mut module,
                )?;

                module.merge(LocalHealthCheck::new(pool_client, builder_client).into_rpc())?;
            }
            ClientMode::Remote {
                pool_url,
                builder_url,
            } => {
                let pool_client =
                    connect_remote_pool_client(pool_url, shutdown_token.clone()).await?;
                let builder_client =
                    connect_remote_builder_client(builder_url, shutdown_token.clone()).await?;

                self.attach_namespaces(provider, pool_client, builder_client, &mut module)?;

                let builder_uri =
                    Uri::from_str(builder_url).context("should be a valid URI for builder")?;
                let op_pool_uri =
                    Uri::from_str(pool_url).context("should be a valid URI for op_pool")?;

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

    fn attach_namespaces<P: PoolClient + Clone, B: BuilderClient + Clone>(
        &self,
        provider: Arc<Provider<RetryClient<Http>>>,
        pool_client: P,
        builder_client: B,
        module: &mut RpcModule<()>,
    ) -> anyhow::Result<()> {
        for api in &self.args.api_namespaces {
            match api {
                ApiNamespace::Eth => module.merge(
                    EthApi::new(
                        provider.clone(),
                        self.args.entry_points.clone(),
                        self.args.chain_id,
                        pool_client.clone(),
                        self.args.estimation_settings,
                    )
                    .into_rpc(),
                )?,
                ApiNamespace::Debug => module
                    .merge(DebugApi::new(pool_client.clone(), builder_client.clone()).into_rpc())?,
            }
        }

        Ok(())
    }
}
