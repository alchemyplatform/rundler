use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context};
use futures::future;
use tokio::{sync::broadcast, task::JoinHandle, try_join};
use tokio_util::sync::CancellationToken;
use tonic::{async_trait, transport::Server};

use crate::{
    common::{
        emit::WithEntryPoint,
        eth,
        grpc::metrics::GrpcMetricsLayer,
        handle,
        handle::Task,
        protos::op_pool::{op_pool_server::OpPoolServer, OP_POOL_FILE_DESCRIPTOR_SET},
    },
    op_pool::{
        chain::{self, Chain, ChainUpdate},
        emit::OpPoolEvent,
        mempool::{uo_pool::UoPool, Mempool, PoolConfig},
        reputation::{HourlyMovingAverageReputation, ReputationParams},
        server::OpPoolImpl,
    },
};

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub host: String,
    pub http_url: String,
    pub http_poll_interval: Duration,
    pub chain_id: u64,
    pub chain_history_size: u64,
    pub pool_configs: Vec<PoolConfig>,
}

#[derive(Debug)]
pub struct PoolTask {
    args: Args,
    event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
}

#[async_trait]
impl Task for PoolTask {
    async fn run(&self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.args.host, self.args.port).parse()?;
        let chain_id = self.args.chain_id;
        tracing::info!("Starting server on {addr}");
        tracing::info!("Chain id: {chain_id}");
        tracing::info!("Http url: {:?}", self.args.http_url);

        // create chain
        let chain_settings = chain::Settings {
            history_size: self.args.chain_history_size,
            poll_interval: self.args.http_poll_interval,
            entry_point_addresses: self
                .args
                .pool_configs
                .iter()
                .map(|config| config.entry_point)
                .collect(),
        };
        let provider = eth::new_provider(&self.args.http_url, self.args.http_poll_interval)?;
        let chain = Chain::new(provider, chain_settings);
        let (update_sender, _) = broadcast::channel(1000);
        let chain_handle = chain.spawn_watcher(update_sender.clone(), shutdown_token.clone());

        // create mempools
        let mut mempools = Vec::new();
        let mut mempool_handles = Vec::new();
        for pool_config in &self.args.pool_configs {
            let (pool, handle) = PoolTask::create_mempool(
                pool_config,
                update_sender.subscribe(),
                self.event_sender.clone(),
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
            handle::flatten_handle(mempool_handle),
            handle::flatten_handle(server_handle),
            handle::as_anyhow_handle(chain_handle),
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
    pub fn new(
        args: Args,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
    ) -> PoolTask {
        Self { args, event_sender }
    }

    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }

    async fn create_mempool(
        pool_config: &PoolConfig,
        update_rx: broadcast::Receiver<Arc<ChainUpdate>>,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        shutdown_token: CancellationToken,
    ) -> anyhow::Result<(Arc<UoPool<HourlyMovingAverageReputation>>, JoinHandle<()>)> {
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
        let mp = Arc::new(UoPool::new(
            pool_config.clone(),
            Arc::clone(&reputation),
            event_sender,
        ));
        let mp_runner = Arc::clone(&mp);
        let handle =
            tokio::spawn(async move { mp_runner.run(update_rx, shutdown_token.clone()).await });

        Ok((mp, handle))
    }
}
