use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context};
use futures::future;
use tokio::{task::JoinHandle, try_join};
use tokio_util::sync::CancellationToken;
use tonic::{async_trait, transport::Server};

use super::{
    event::EventProvider,
    mempool::{Mempool, PoolConfig},
};
use crate::{
    common::{
        grpc::metrics::GrpcMetricsLayer,
        handle::{flatten_handle, Task},
        protos::op_pool::{op_pool_server::OpPoolServer, OP_POOL_FILE_DESCRIPTOR_SET},
    },
    op_pool::{
        event::{EventListener, HttpBlockProviderFactory, WsBlockProviderFactory},
        mempool::uo_pool::UoPool,
        reputation::{HourlyMovingAverageReputation, ReputationParams},
        server::OpPoolImpl,
    },
};

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub host: String,
    pub ws_url: Option<String>,
    pub http_url: Option<String>,
    pub http_poll_interval: Duration,
    pub chain_id: u64,
    pub pool_configs: Vec<PoolConfig>,
}

#[derive(Debug)]
pub struct PoolTask {
    args: Args,
}

#[async_trait]
impl Task for PoolTask {
    async fn run(&self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.args.host, self.args.port).parse()?;
        let chain_id = self.args.chain_id;
        let entry_points = self.args.pool_configs.iter().map(|pc| &pc.entry_point);
        tracing::info!("Starting server on {addr}");
        tracing::info!("Chain id: {chain_id}");
        tracing::info!("Websocket url: {:?}", self.args.ws_url);
        tracing::info!("Http url: {:?}", self.args.http_url);

        // Events listener
        let event_provider: Box<dyn EventProvider> = if let Some(ws_url) = &self.args.ws_url {
            let connection_factory = WsBlockProviderFactory::new(ws_url.to_owned(), 10);
            Box::new(EventListener::new(connection_factory, entry_points))
        } else if let Some(http_url) = &self.args.http_url {
            let connection_factory = HttpBlockProviderFactory::new(
                http_url.to_owned(),
                self.args.http_poll_interval,
                10,
            );
            Box::new(EventListener::new(connection_factory, entry_points))
        } else {
            bail!("Either ws_url or http_url must be provided");
        };

        // create mempools
        let mut mempools = Vec::new();
        let mut mempool_handles = Vec::new();
        for pool_config in &self.args.pool_configs {
            let (pool, handle) = PoolTask::create_mempool(
                pool_config,
                event_provider.as_ref(),
                shutdown_token.clone(),
            )
            .await
            .context("should have created mempool")?;

            mempools.push(pool);
            mempool_handles.push(handle);
        }
        let mempool_map = mempools
            .into_iter()
            .map(|mp| (mp.entry_point(), mp))
            .collect();

        // handle to wait for mempools to terminate
        let mempool_handle = tokio::spawn(async move {
            future::join_all(mempool_handles)
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .map(|_| ())
                .context("should have joined mempool handles")
        });

        // Start events listener
        let events_provider_handle = event_provider.spawn(shutdown_token.clone());

        // gRPC server
        let op_pool_server = OpPoolServer::new(OpPoolImpl::new(chain_id, mempool_map));
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(OP_POOL_FILE_DESCRIPTOR_SET)
            .build()?;

        // health service
        let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
        health_reporter
            .set_serving::<OpPoolServer<OpPoolImpl<UoPool<HourlyMovingAverageReputation>>>>()
            .await;

        let metrics_layer = GrpcMetricsLayer::new("op_pool".to_string());
        let server_handle = tokio::spawn(async move {
            Server::builder()
                .layer(metrics_layer)
                .add_service(op_pool_server)
                .add_service(reflection_service)
                .add_service(health_service)
                .serve_with_shutdown(addr, async move { shutdown_token.cancelled().await })
                .await
                .map_err(|err| anyhow::anyhow!("Server error: {err:?}"))
        });

        tracing::info!("Started op_pool");

        match try_join!(
            flatten_handle(mempool_handle),
            flatten_handle(server_handle),
            flatten_handle(events_provider_handle)
        ) {
            Ok(_) => {
                tracing::info!("Pool server shutdown");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Pool server error: {e:?}");
                bail!("Pool server error: {e:?}")
            }
        }
    }
}

impl PoolTask {
    pub fn new(args: Args) -> PoolTask {
        Self { args }
    }

    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }

    async fn create_mempool(
        pool_config: &PoolConfig,
        event_provider: &dyn EventProvider,
        shutdown_token: CancellationToken,
    ) -> anyhow::Result<(Arc<UoPool<HourlyMovingAverageReputation>>, JoinHandle<()>)> {
        let entry_point = pool_config.entry_point;
        // Reputation manager
        let reputation = Arc::new(HourlyMovingAverageReputation::new(
            ReputationParams::bundler_default(),
            pool_config.blocklist.clone(),
            pool_config.allowlist.clone(),
        ));
        // Start reputation manager
        let reputation_runner = Arc::clone(&reputation);
        tokio::spawn(async move { reputation_runner.run().await });

        // Mempool
        let mp = Arc::new(UoPool::new(pool_config.clone(), Arc::clone(&reputation)));
        // Start mempool
        let mempool_events = event_provider
            .subscribe_by_entrypoint(entry_point)
            .context("event listener should have entrypoint subscriber")?;
        let mp_runner = Arc::clone(&mp);
        let handle =
            tokio::spawn(
                async move { mp_runner.run(mempool_events, shutdown_token.clone()).await },
            );

        Ok((mp, handle))
    }
}
