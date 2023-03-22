use crate::builder::server::BuilderImpl;
use crate::common::protos::builder::builder_server::BuilderServer;
use crate::common::protos::builder::BUILDER_FILE_DESCRIPTOR_SET;
use crate::common::server::format_socket_addr;
use anyhow::Context;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tonic::transport::Server;

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub host: String,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let addr = format_socket_addr(&args.host, args.port).parse()?;
    tracing::info!("Starting builder server on {}", addr);

    // gRPC server
    let builder_server = BuilderServer::new(BuilderImpl::new());
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(BUILDER_FILE_DESCRIPTOR_SET)
        .build()
        .unwrap();

    let server_handle = Server::builder()
        .add_service(builder_server)
        .add_service(reflection_service)
        .serve_with_shutdown(addr, async move {
            shutdown_rx
                .recv()
                .await
                .expect("should have received shutdown signal")
        })
        .await;

    match server_handle {
        Ok(_) => {
            tracing::info!("Builder Server shutdown");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Builder Server error: {:?}", e);
            Err(e).context("Builder Server error")
        }
    }
}
