use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use anyhow::Context;
use ethers::{
    providers::{Http, HttpRateLimitRetryPolicy, Provider, RetryClient, RetryClientBuilder},
    types::{Address, H256},
};
use ethers_signers::Signer;
use rusoto_core::Region;
use tokio::{sync::mpsc, time};
use tokio_util::sync::CancellationToken;
use tonic::{async_trait, transport::Server};
use tracing::info;
use url::Url;

use crate::{
    builder::{
        bundle_proposer::{self, BundleProposerImpl},
        bundle_sender::{self, BundleSender, BundleSenderImpl},
        sender::get_sender,
        server::BuilderImpl,
        signer::{BundlerSigner, KmsSigner, LocalSigner},
        transaction_tracker::{self, TransactionTrackerImpl},
    },
    common::{
        contracts::i_entry_point::IEntryPoint,
        gas::PriorityFeeMode,
        handle::{SpawnGuard, Task},
        mempool::MempoolConfig,
        protos::builder::{builder_server::BuilderServer, BUILDER_FILE_DESCRIPTOR_SET},
        server::format_socket_addr,
        simulation::{self, SimulatorImpl},
    },
    op_pool::{connect_remote_pool_client, LocalPoolClient, PoolClientMode},
};

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub host: String,
    pub rpc_url: String,
    pub entry_point_address: Address,
    pub private_key: Option<String>,
    pub aws_kms_key_ids: Vec<String>,
    pub aws_kms_region: Region,
    pub redis_uri: String,
    pub redis_lock_ttl_millis: u64,
    pub chain_id: u64,
    pub max_bundle_size: u64,
    pub submit_url: String,
    pub use_bundle_priority_fee: Option<bool>,
    pub bundle_priority_fee_overhead_percent: u64,
    pub priority_fee_mode: PriorityFeeMode,
    pub use_conditional_send_transaction: bool,
    pub eth_poll_interval: Duration,
    pub sim_settings: simulation::Settings,
    pub mempool_configs: HashMap<H256, MempoolConfig>,
    pub max_blocks_to_wait_for_mine: u64,
    pub replacement_fee_percent_increase: u64,
    pub max_fee_increases: u64,
    pub pool_client_mode: PoolClientMode,
}

#[derive(Debug)]
pub struct BuilderTask {
    args: Args,
}

#[async_trait]
impl Task for BuilderTask {
    async fn run(&mut self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let addr = format_socket_addr(&self.args.host, self.args.port).parse()?;
        info!("Starting builder server on {}", addr);
        tracing::info!("Mempool config: {:?}", self.args.mempool_configs);

        let provider = new_provider(&self.args.rpc_url, self.args.eth_poll_interval)?;
        let signer = if let Some(pk) = &self.args.private_key {
            info!("Using local signer");
            BundlerSigner::Local(
                LocalSigner::connect(Arc::clone(&provider), self.args.chain_id, pk.to_owned())
                    .await?,
            )
        } else {
            info!("Using AWS KMS signer");
            let signer = time::timeout(
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
            use_bundle_priority_fee: self.args.use_bundle_priority_fee,
            priority_fee_mode: self.args.priority_fee_mode,
            bundle_priority_fee_overhead_percent: self.args.bundle_priority_fee_overhead_percent,
        };
        let simulator = SimulatorImpl::new(
            Arc::clone(&provider),
            self.args.entry_point_address,
            self.args.sim_settings,
            self.args.mempool_configs.clone(),
        );
        let entry_point = IEntryPoint::new(self.args.entry_point_address, Arc::clone(&provider));
        let submit_provider = new_provider(&self.args.submit_url, self.args.eth_poll_interval)?;
        let transaction_sender = get_sender(
            submit_provider,
            signer,
            self.args.use_conditional_send_transaction,
            &self.args.submit_url,
        );
        let tracker_settings = transaction_tracker::Settings {
            poll_interval: self.args.eth_poll_interval,
            max_blocks_to_wait_for_mine: self.args.max_blocks_to_wait_for_mine,
            replacement_fee_percent_increase: self.args.replacement_fee_percent_increase,
        };
        let transaction_tracker = TransactionTrackerImpl::new(
            Arc::clone(&provider),
            transaction_sender,
            tracker_settings,
        )
        .await?;

        let builder_settings = bundle_sender::Settings {
            replacement_fee_percent_increase: self.args.replacement_fee_percent_increase,
            max_fee_increases: self.args.max_fee_increases,
        };
        let manual_bundling_mode = Arc::new(AtomicBool::new(false));
        let (send_bundle_tx, send_bundle_rx) = mpsc::channel(1);

        let mut builder: Box<dyn BundleSender> = match &self.args.pool_client_mode {
            PoolClientMode::Local { sender } => {
                let pool_client = LocalPoolClient::new(sender.clone());
                let proposer = BundleProposerImpl::new(
                    pool_client.clone(),
                    simulator,
                    entry_point.clone(),
                    Arc::clone(&provider),
                    self.args.chain_id,
                    proposer_settings,
                );
                Box::new(BundleSenderImpl::new(
                    manual_bundling_mode.clone(),
                    send_bundle_rx,
                    self.args.chain_id,
                    beneficiary,
                    self.args.eth_poll_interval,
                    proposer,
                    entry_point,
                    transaction_tracker,
                    pool_client,
                    provider,
                    builder_settings,
                ))
            }
            PoolClientMode::Remote { url } => {
                let pool_client = connect_remote_pool_client(url, shutdown_token.clone()).await?;
                let proposer = BundleProposerImpl::new(
                    pool_client.clone(),
                    simulator,
                    entry_point.clone(),
                    Arc::clone(&provider),
                    self.args.chain_id,
                    proposer_settings,
                );
                Box::new(BundleSenderImpl::new(
                    manual_bundling_mode.clone(),
                    send_bundle_rx,
                    self.args.chain_id,
                    beneficiary,
                    self.args.eth_poll_interval,
                    proposer,
                    entry_point,
                    transaction_tracker,
                    pool_client,
                    provider,
                    builder_settings,
                ))
            }
        };

        let _builder_loop_guard =
            { SpawnGuard::spawn_with_guard(async move { builder.send_bundles_in_loop().await }) };

        // gRPC server
        let builder_server = BuilderImpl::new(manual_bundling_mode, send_bundle_tx);
        let builder_server = BuilderServer::new(builder_server);

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
}

fn new_provider(
    url: &str,
    poll_interval: Duration,
) -> anyhow::Result<Arc<Provider<RetryClient<Http>>>> {
    let parsed_url = Url::parse(url).context("provider url should be a valid")?;
    let http = Http::new(parsed_url);
    let client = RetryClientBuilder::default()
        // these retries are if the server returns a 429
        .rate_limit_retries(10)
        // these retries are if the connection is dubious
        .timeout_retries(3)
        .initial_backoff(Duration::from_millis(500))
        .build(http, Box::<HttpRateLimitRetryPolicy>::default());
    Ok(Arc::new(Provider::new(client).interval(poll_interval)))
}
