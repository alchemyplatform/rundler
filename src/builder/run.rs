use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context};
use ethers::{
    prelude::SignerMiddleware,
    providers::{Http, HttpRateLimitRetryPolicy, Provider, RetryClientBuilder},
    types::Address,
};
use ethers_signers::Signer;
use rusoto_core::Region;
use tokio::{
    select,
    sync::{broadcast, mpsc},
};
use tonic::transport::{Channel, Server};
use url::Url;

use crate::{
    builder::{
        bundle_proposer::BundleProposerImpl,
        pool::RemotePoolClient,
        server::{BuilderImpl, DummyBuilder},
        signer::{BundlerSigner, KmsSigner, LocalSigner},
    },
    common::{
        contracts::i_entry_point::IEntryPoint,
        handle::SpawnGuard,
        protos::{
            builder::{builder_server::BuilderServer, BUILDER_FILE_DESCRIPTOR_SET},
            op_pool::op_pool_client::OpPoolClient,
        },
        server::{self, format_socket_addr},
        simulation::{self, SimulatorImpl},
    },
};

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub host: String,
    pub rpc_url: String,
    pub pool_url: String,
    pub entry_point_address: Address,
    pub private_key: Option<String>,
    pub aws_kms_key_ids: Vec<String>,
    pub aws_kms_region: Region,
    pub redis_uri: String,
    pub redis_lock_ttl_millis: u64,
    pub chain_id: u64,
    pub max_bundle_size: u64,
    pub eth_poll_interval: Duration,
    pub sim_settings: simulation::Settings,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let addr = format_socket_addr(&args.host, args.port).parse()?;
    tracing::info!("Starting builder server on {}", addr);

    let provider = {
        let parsed_url = Url::parse(&args.rpc_url).context("Invalid RPC URL")?;
        let http = Http::new(parsed_url);
        let client = RetryClientBuilder::default()
            // these retries are if the server returns a 429
            .rate_limit_retries(10)
            // these retries are if the connection is dubious
            .timeout_retries(3)
            .initial_backoff(Duration::from_millis(500))
            .build(http, Box::<HttpRateLimitRetryPolicy>::default());
        Arc::new(Provider::new(client).interval(args.eth_poll_interval))
    };

    let signer = if let Some(pk) = args.private_key {
        tracing::info!("Using local signer");
        BundlerSigner::Local(LocalSigner::connect(Arc::clone(&provider), args.chain_id, pk).await?)
    } else {
        tracing::info!("Using AWS KMS signer");
        BundlerSigner::Kms(
            KmsSigner::connect(
                Arc::clone(&provider),
                args.chain_id,
                args.aws_kms_region,
                args.aws_kms_key_ids,
                args.redis_uri,
                args.redis_lock_ttl_millis,
            )
            .await?,
        )
    };
    let beneficiary = signer.address();
    let op_pool = connect_client_with_shutdown(&args.pool_url, shutdown_rx.resubscribe()).await?;
    let simulator = SimulatorImpl::new(
        Arc::clone(&provider),
        args.entry_point_address,
        args.sim_settings,
    );
    let signer_middleware = Arc::new(SignerMiddleware::new(Arc::clone(&provider), signer));
    let entry_point = IEntryPoint::new(args.entry_point_address, signer_middleware);
    let proposer = BundleProposerImpl::new(
        args.max_bundle_size,
        beneficiary,
        op_pool.clone(),
        simulator,
        entry_point.clone(),
        Arc::clone(&provider),
    );

    let client2 = op_pool.clone();
    let pool = RemotePoolClient::new(client2);

    let builder = Arc::new(BuilderImpl::new(
        args.chain_id,
        beneficiary,
        op_pool,
        proposer,
        entry_point,
        provider,
        pool,
    ));

    let _builder_loop_guard = {
        let builder = Arc::clone(&builder);
        SpawnGuard::spawn_with_guard(async move { builder.send_bundles_in_loop().await })
    };

    // gRPC server
    let builder_server = BuilderServer::new(builder);

    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(BUILDER_FILE_DESCRIPTOR_SET)
        .build()?;

    // health service
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<BuilderServer<DummyBuilder>>()
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

async fn connect_client_with_shutdown(
    op_pool_url: &str,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> anyhow::Result<OpPoolClient<Channel>> {
    select! {
        _ = shutdown_rx.recv() => {
            tracing::error!("bailing from connecting client, server shutting down");
            bail!("Server shutting down")
        }
        res = server::connect_with_retries(op_pool_url, OpPoolClient::connect) => {
            res
        }
    }
}
