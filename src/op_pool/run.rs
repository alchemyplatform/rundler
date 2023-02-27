use std::sync::Arc;

use ethers::types::{Address, U256};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::try_join;
use tonic::transport::Server;

use crate::common::protos::op_pool::op_pool_server::OpPoolServer;
use crate::common::protos::op_pool::OP_POOL_FILE_DESCRIPTOR_SET;
use crate::op_pool::events::EventListener;
use crate::op_pool::mempool::uo_pool::UoPool;
use crate::op_pool::mempool::Mempool;
use crate::op_pool::server::OpPoolImpl;

pub struct Args {
    pub port: u16,
    pub host: String,
    pub entry_point: Address,
    pub chain_id: U256,
    pub ws_url: String,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", args.host, args.port).parse()?;
    tracing::info!("Starting server on {}", addr);
    tracing::info!("Entry point: {}", args.entry_point);
    tracing::info!("Chain id: {}", args.chain_id);
    tracing::info!("Websocket url: {}", args.ws_url);

    // Mempool
    let mp = Arc::new(UoPool::new(args.entry_point, args.chain_id));

    // Events listener
    let event_listener = match EventListener::connect(args.ws_url, args.entry_point).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("Failed to connect to events listener: {:?}", e);
            return Err(anyhow::anyhow!(
                "Failed to connect to events listener: {:?}",
                e
            ));
        }
    };
    tracing::info!("Connected to events listener");
    let callback_mp = Arc::clone(&mp);
    event_listener.subscribe(move |new_block| {
        callback_mp.on_new_block(new_block);
    });

    let event_listener_shutdown = shutdown_rx.resubscribe();
    let events_listener_handle = tokio::spawn(async move {
        event_listener
            .listen_with_shutdown(event_listener_shutdown)
            .await
    });

    // gRPC server
    let op_pool_server = OpPoolServer::new(OpPoolImpl::new(args.chain_id, mp));
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(OP_POOL_FILE_DESCRIPTOR_SET)
        .build()?;

    let server_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(op_pool_server)
            .add_service(reflection_service)
            .serve_with_shutdown(addr, async move {
                shutdown_rx
                    .recv()
                    .await
                    .expect("should have received shutdown signal")
            })
            .await
    });

    match try_join!(server_handle, events_listener_handle) {
        Ok(_) => {
            tracing::info!("Op pool server shutdown");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Op pool server error: {:?}", e);
            Err(anyhow::anyhow!("Op pool server error: {:?}", e))
        }
    }
}
