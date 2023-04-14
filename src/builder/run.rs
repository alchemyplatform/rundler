use std::sync::Arc;

use anyhow::Context;
use ethers::{
    abi::Address,
    prelude::MiddlewareBuilder,
    providers::{Http, Provider},
};
use ethers_signers::{LocalWallet, Signer};
use rusoto_core::Region;
use tokio::sync::{broadcast, mpsc};
use tonic::transport::Server;
use tracing::info;

use crate::{
    builder::{
        bundle_proposer::{BundleProposer, BundleProposerImpl},
        server::BuilderImpl,
        signer::{monitor_account_balance, KmsSigner},
    },
    common::{
        contracts::i_entry_point::IEntryPoint,
        handle::SpawnGuard,
        protos::{
            builder::{builder_server::BuilderServer, BUILDER_FILE_DESCRIPTOR_SET},
            op_pool::op_pool_client::OpPoolClient,
        },
        server::format_socket_addr,
        simulation::{Settings, SimulatorImpl},
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
    pub entry_point_address: Address,
    pub pool_url: String,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let addr = format_socket_addr(&args.host, args.port).parse()?;
    tracing::info!("Starting builder server on {}", addr);

    let provider = Arc::new(
        Provider::<Http>::try_from(args.rpc_url.to_owned()).context("should create provider")?,
    );

    let pool = OpPoolClient::connect(args.pool_url.to_owned())
        .await
        .context("should connect to pool")?;
    let simulator = SimulatorImpl::new(
        provider.clone(),
        args.entry_point_address,
        Settings::default(),
    );

    let (bp, signer_addr): (Box<dyn BundleProposer>, Address) = if let Some(pk) = args.private_key {
        tracing::info!("Using local signer");
        let s = pk
            .parse::<LocalWallet>()
            .context("should parse private_key")?
            .with_chain_id(args.chain_id);
        let p = Arc::new(provider.clone().with_signer(s));
        let addr = p.address();
        let ep = IEntryPoint::new(args.entry_point_address, p.clone());

        (
            Box::new(BundleProposerImpl::new(
                100,
                args.entry_point_address,
                pool,
                simulator,
                ep,
                p,
            )),
            addr,
        )
    } else {
        tracing::info!("Using AWS KMS signer");
        let s = KmsSigner::connect(
            args.chain_id,
            args.aws_kms_region,
            args.aws_kms_key_ids,
            args.redis_uri,
            args.redis_lock_ttl_millis,
        )
        .await?;
        let p = Arc::new(provider.clone().with_signer(s));
        let addr = p.address();
        let ep = IEntryPoint::new(args.entry_point_address, p.clone());

        (
            Box::new(BundleProposerImpl::new(
                100,
                args.entry_point_address,
                pool,
                simulator,
                ep,
                p,
            )),
            addr,
        )
    };

    let _monitor_guard =
        SpawnGuard::spawn_with_guard(monitor_account_balance(signer_addr, provider.clone()));
    let bundle = bp.make_bundle().await?;
    info!("Made bundle {:?}", bundle);

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
