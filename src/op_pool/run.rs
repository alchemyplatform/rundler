use std::sync::Arc;

use anyhow::{bail, Context};
use tokio::{
    sync::{broadcast, mpsc},
    try_join,
};
use tonic::transport::Server;

use super::{
    event::EventProvider,
    mempool::{Mempool, PoolConfig},
};
use crate::{
    common::{
        grpc::metrics::GrpcMetricsLayer,
        handle::flatten_handle,
        protos::op_pool::{op_pool_server::OpPoolServer, OP_POOL_FILE_DESCRIPTOR_SET},
    },
    op_pool::{
        event::{EventListener, WsBlockProviderFactory},
        mempool::uo_pool::UoPool,
        reputation::{HourlyMovingAverageReputation, ReputationParams},
        server::OpPoolImpl,
    },
};

pub struct Args {
    pub port: u16,
    pub host: String,
    pub ws_url: String,
    pub chain_id: u64,
    pub pool_configs: Vec<PoolConfig>,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", args.host, args.port).parse()?;
    let chain_id = args.chain_id;
    let entry_points = args.pool_configs.iter().map(|pc| &pc.entry_point);
    tracing::info!("Starting server on {}", addr);
    tracing::info!("Chain id: {}", chain_id);
    tracing::info!("Websocket url: {}", args.ws_url);

    // Events listener
    let connection_factory = WsBlockProviderFactory::new(args.ws_url.clone(), 10);
    let event_listener = EventListener::new(connection_factory, entry_points);

    // create mempools
    let mut mempools = Vec::new();
    for pool_config in args.pool_configs {
        mempools.push(
            create_mempool(pool_config, &event_listener, &shutdown_rx)
                .await
                .context("should have created mempool")?,
        );
    }
    let mempool_map = mempools
        .into_iter()
        .map(|mp| (mp.entry_point(), mp))
        .collect();

    // Start events listener
    let event_listener_shutdown = shutdown_rx.resubscribe();
    let events_listener_handle = tokio::spawn(async move {
        event_listener
            .listen_with_shutdown(event_listener_shutdown)
            .await
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
            .serve_with_shutdown(addr, async move {
                shutdown_rx
                    .recv()
                    .await
                    .expect("should have received shutdown signal")
            })
            .await
            .map_err(|err| anyhow::anyhow!("Server error: {err:?}"))
    });

    match try_join!(
        flatten_handle(server_handle),
        flatten_handle(events_listener_handle)
    ) {
        Ok(_) => {
            tracing::info!("Server shutdown");
            Ok(())
        }
        Err(e) => {
            tracing::error!("OP Pool server error: {e:?}");
            bail!("Server error: {e:?}")
        }
    }
}

async fn create_mempool<P>(
    pool_config: PoolConfig,
    event_provider: &P,
    shutdown_rx: &broadcast::Receiver<()>,
) -> anyhow::Result<Arc<UoPool<HourlyMovingAverageReputation>>>
where
    P: EventProvider,
{
    let entry_point = pool_config.entry_point;
    // Reputation manager
    let reputation = Arc::new(HourlyMovingAverageReputation::new(
        ReputationParams::bundler_default(),
    ));
    // Start reputation manager
    let reputation_runner = Arc::clone(&reputation);
    tokio::spawn(async move { reputation_runner.run().await });

    // Mempool
    let mp = Arc::new(UoPool::new(pool_config, Arc::clone(&reputation)));
    // Start mempool
    let mempool_shutdown = shutdown_rx.resubscribe();
    let mempool_events = event_provider
        .subscribe_by_entrypoint(entry_point)
        .context("event listener should have entrypoint subscriber")?;
    let mp_runner = Arc::clone(&mp);
    tokio::spawn(async move { mp_runner.run(mempool_events, mempool_shutdown).await });

    Ok(mp)
}
