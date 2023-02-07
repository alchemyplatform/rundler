use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tonic::transport::Server;

use crate::common::protos::op_pool::op_pool_server::OpPoolServer;
use crate::common::protos::op_pool::OP_POOL_FILE_DESCRIPTOR_SET;
use crate::op_pool::server::OpPoolImpl;

pub struct Args {
    pub port: u16,
    pub host: String,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", args.host, args.port).parse()?;
    let op_pool_server = OpPoolServer::new(OpPoolImpl::default());
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(OP_POOL_FILE_DESCRIPTOR_SET)
        .build()?;

    Server::builder()
        .add_service(op_pool_server)
        .add_service(reflection_service)
        .serve_with_shutdown(addr, async move {
            shutdown_rx
                .recv()
                .await
                .expect("should have received shutdown signal")
        })
        .await?;
    tracing::info!("Op pool server shutdown");
    Ok(())
}
