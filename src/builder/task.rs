use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context};
use ethers::{
    prelude::SignerMiddleware,
    providers::{Http, HttpRateLimitRetryPolicy, Provider, RetryClientBuilder},
    types::Address,
};
use ethers_signers::Signer;
use rusoto_core::Region;
use tokio::{select, time::timeout};
use tokio_util::sync::CancellationToken;
use tonic::{
    async_trait,
    transport::{Channel, Server},
};
use tracing::info;
use url::Url;

use crate::{
    builder::{
        bundle_proposer::{self, BundleProposerImpl},
        server::{BuilderImpl, DummyBuilder},
        signer::{BundlerSigner, KmsSigner, LocalSigner},
    },
    common::{
        contracts::i_entry_point::IEntryPoint,
        handle::{SpawnGuard, Task},
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
    pub use_dynamic_max_priority_fee: bool,
    pub max_priority_fee_overhead_percent: u64,
    pub eth_poll_interval: Duration,
    pub sim_settings: simulation::Settings,
}

#[derive(Debug)]
pub struct BuilderTask {
    args: Args,
}

#[async_trait]
impl Task for BuilderTask {
    async fn run(&self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let addr = format_socket_addr(&self.args.host, self.args.port).parse()?;
        info!("Starting builder server on {}", addr);

        let provider = {
            let parsed_url = Url::parse(&self.args.rpc_url).context("Invalid RPC URL")?;
            let http = Http::new(parsed_url);
            let client = RetryClientBuilder::default()
                // these retries are if the server returns a 429
                .rate_limit_retries(10)
                // these retries are if the connection is dubious
                .timeout_retries(3)
                .initial_backoff(Duration::from_millis(500))
                .build(http, Box::<HttpRateLimitRetryPolicy>::default());
            Arc::new(Provider::new(client).interval(self.args.eth_poll_interval))
        };

        let signer = if let Some(pk) = &self.args.private_key {
            info!("Using local signer");
            BundlerSigner::Local(
                LocalSigner::connect(Arc::clone(&provider), self.args.chain_id, pk.to_owned())
                    .await?,
            )
        } else {
            info!("Using AWS KMS signer");
            let signer = timeout(
                // timeout must be << than the lock TTL to avoid a
                // bug in the redis lock implementation that panics if connection
                // takes longer than the TTL. Generally the TLL should be on the order of 10s of seconds
                // so this should give ample time for the connection to establish.
                Duration::from_millis(self.args.redis_lock_ttl_millis / 10),
                KmsSigner::connect(
                    Arc::clone(&provider),
                    self.args.chain_id,
                    self.args.aws_kms_region.clone(),
                    self.args.aws_kms_key_ids.clone(),
                    self.args.redis_uri.clone(),
                    self.args.redis_lock_ttl_millis,
                ),
            )
            .await
            .context("timeout connecting to KMS")?
            .context("failure connecting to KMS")?;
            let ret = BundlerSigner::Kms(signer);
            info!("Created AWS KMS signer");
            ret
        };
        let beneficiary = signer.address();
        let proposer_settings = bundle_proposer::Settings {
            max_bundle_size: self.args.max_bundle_size,
            beneficiary,
            use_dynamic_max_priority_fee: self.args.use_dynamic_max_priority_fee,
            max_priority_fee_overhead_percent: self.args.max_priority_fee_overhead_percent,
        };
        let op_pool =
            Self::connect_client_with_shutdown(&self.args.pool_url, shutdown_token.clone()).await?;
        let simulator = SimulatorImpl::new(
            Arc::clone(&provider),
            self.args.entry_point_address,
            self.args.sim_settings,
        );
        let signer_middleware = Arc::new(SignerMiddleware::new(Arc::clone(&provider), signer));
        let entry_point = IEntryPoint::new(self.args.entry_point_address, signer_middleware);
        let proposer = BundleProposerImpl::new(
            op_pool.clone(),
            simulator,
            entry_point.clone(),
            Arc::clone(&provider),
            proposer_settings,
        );
        let builder = Arc::new(BuilderImpl::new(
            self.args.chain_id,
            beneficiary,
            self.args.eth_poll_interval,
            op_pool,
            proposer,
            entry_point,
            provider,
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
            .serve_with_shutdown(addr, async move { shutdown_token.cancelled().await });

        info!("Started bundle builder");

        match server_handle.await {
            Ok(_) => {
                tracing::info!("Builder server shutdown");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Builder server error: {:?}", e);
                Err(e).context("Builder server error")
            }
        }
    }
}

impl BuilderTask {
    pub fn new(args: Args) -> BuilderTask {
        Self { args }
    }

    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }

    async fn connect_client_with_shutdown(
        op_pool_url: &str,
        shutdown_token: CancellationToken,
    ) -> anyhow::Result<OpPoolClient<Channel>> {
        select! {
            _ = shutdown_token.cancelled() => {
                tracing::error!("bailing from connecting client, server shutting down");
                bail!("Server shutting down")
            }
            res = server::connect_with_retries(op_pool_url, OpPoolClient::connect) => {
                res
            }
        }
    }
}
