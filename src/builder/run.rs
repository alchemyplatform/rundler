use std::sync::Arc;

use anyhow::Context;
use ethers::providers::{Http, Provider};
use rusoto_core::Region;
use tokio::sync::{broadcast, mpsc};
use tonic::transport::Server;

use crate::{
    builder::{
        server::BuilderImpl,
        signer::{KmsSigner, LocalSigner, SignerLike},
    },
    common::{
        protos::builder::{builder_server::BuilderServer, BUILDER_FILE_DESCRIPTOR_SET},
        server::format_socket_addr,
    },
};

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub host: String,
    pub rpc_url: String,
    pub private_key: Option<String>,
    pub aws_kms_key_ids: Vec<String>,
    pub aws_kms_region: Region,
    pub redis_uri: String,
    pub redis_lock_ttl_millis: u64,
    pub chain_id: u64,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let addr = format_socket_addr(&args.host, args.port).parse()?;
    tracing::info!("Starting builder server on {}", addr);

    let provider =
        Arc::new(Provider::<Http>::try_from(args.rpc_url).context("should create provider")?);

    let _tx_sender: Box<dyn SignerLike> = if let Some(pk) = args.private_key {
        tracing::info!("Using local signer");
        Box::new(LocalSigner::connect(provider.clone(), args.chain_id, pk).await?)
    } else {
        tracing::info!("Using AWS KMS signer");
        Box::new(
            KmsSigner::connect(
                provider.clone(),
                args.chain_id,
                args.aws_kms_region,
                args.aws_kms_key_ids,
                args.redis_uri,
                args.redis_lock_ttl_millis,
            )
            .await?,
        )
    };

    // gRPC server
    let builder_server = BuilderServer::new(BuilderImpl::new());
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(BUILDER_FILE_DESCRIPTOR_SET)
        .build()?;

    // health service
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<BuilderServer<BuilderImpl>>()
        .await;

    let server_handle = Server::builder()
        .add_service(builder_server)
        .add_service(reflection_service)
        .add_service(health_service)
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
