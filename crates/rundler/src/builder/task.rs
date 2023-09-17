use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use anyhow::{bail, Context};
use ethers::types::{Address, H256};
use ethers_signers::Signer;
use rundler_sim::{
    MempoolConfig, PriorityFeeMode, SimulateValidationTracerImpl, SimulationSettings, SimulatorImpl,
};
use rundler_types::contracts::i_entry_point::IEntryPoint;
use rusoto_core::Region;
use tokio::{
    sync::{broadcast, mpsc},
    time, try_join,
};
use tokio_util::sync::CancellationToken;
use tonic::async_trait;
use tracing::info;

use super::{emit::BuilderEvent, server::LocalBuilderBuilder};
use crate::{
    builder::{
        bundle_proposer::{self, BundleProposerImpl},
        bundle_sender::{self, BundleSender, BundleSenderImpl},
        sender::get_sender,
        server::spawn_remote_builder_server,
        signer::{BundlerSigner, KmsSigner, LocalSigner},
        transaction_tracker::{self, TransactionTrackerImpl},
    },
    common::{
        emit::WithEntryPoint,
        eth,
        handle::{self, SpawnGuard, Task},
    },
    op_pool::PoolServer,
};

#[derive(Debug)]
pub struct Args {
    pub rpc_url: String,
    pub entry_point_address: Address,
    pub private_key: Option<String>,
    pub aws_kms_key_ids: Vec<String>,
    pub aws_kms_region: Region,
    pub redis_uri: String,
    pub redis_lock_ttl_millis: u64,
    pub chain_id: u64,
    pub max_bundle_size: u64,
    pub max_bundle_gas: u64,
    pub submit_url: String,
    pub use_bundle_priority_fee: Option<bool>,
    pub bundle_priority_fee_overhead_percent: u64,
    pub priority_fee_mode: PriorityFeeMode,
    pub use_conditional_send_transaction: bool,
    pub eth_poll_interval: Duration,
    pub sim_settings: SimulationSettings,
    pub mempool_configs: HashMap<H256, MempoolConfig>,
    pub max_blocks_to_wait_for_mine: u64,
    pub replacement_fee_percent_increase: u64,
    pub max_fee_increases: u64,
    pub remote_address: Option<SocketAddr>,
}

#[derive(Debug)]
pub struct BuilderTask<P> {
    args: Args,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    builder_builder: LocalBuilderBuilder,
    pool: P,
}

#[async_trait]
impl<P> Task for BuilderTask<P>
where
    P: PoolServer + Clone,
{
    async fn run(mut self: Box<Self>, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        tracing::info!("Mempool config: {:?}", self.args.mempool_configs);

        let provider = eth::new_provider(&self.args.rpc_url, self.args.eth_poll_interval)?;
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
            chain_id: self.args.chain_id,
            max_bundle_size: self.args.max_bundle_size,
            max_bundle_gas: self.args.max_bundle_gas,
            beneficiary,
            use_bundle_priority_fee: self.args.use_bundle_priority_fee,
            priority_fee_mode: self.args.priority_fee_mode,
            bundle_priority_fee_overhead_percent: self.args.bundle_priority_fee_overhead_percent,
        };

        let entry_point = IEntryPoint::new(self.args.entry_point_address, Arc::clone(&provider));
        let simulate_validation_tracer =
            SimulateValidationTracerImpl::new(Arc::clone(&provider), entry_point.clone());
        let simulator = SimulatorImpl::new(
            Arc::clone(&provider),
            entry_point.address(),
            simulate_validation_tracer,
            self.args.sim_settings,
            self.args.mempool_configs.clone(),
        );

        let submit_provider =
            eth::new_provider(&self.args.submit_url, self.args.eth_poll_interval)?;
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

        let proposer = BundleProposerImpl::new(
            self.pool.clone(),
            simulator,
            entry_point.clone(),
            Arc::clone(&provider),
            proposer_settings,
            self.event_sender.clone(),
        );
        let mut builder = BundleSenderImpl::new(
            manual_bundling_mode.clone(),
            send_bundle_rx,
            self.args.chain_id,
            beneficiary,
            self.args.eth_poll_interval,
            proposer,
            entry_point,
            transaction_tracker,
            self.pool,
            builder_settings,
            self.event_sender.clone(),
        );

        let _builder_loop_guard =
            { SpawnGuard::spawn_with_guard(async move { builder.send_bundles_in_loop().await }) };

        let builder_handle = self.builder_builder.get_handle();
        let builder_runnder_handle = self.builder_builder.run(
            manual_bundling_mode,
            send_bundle_tx,
            vec![self.args.entry_point_address],
            shutdown_token.clone(),
        );

        let remote_handle = match self.args.remote_address {
            Some(addr) => {
                spawn_remote_builder_server(
                    addr,
                    self.args.chain_id,
                    builder_handle,
                    shutdown_token,
                )
                .await?
            }
            None => tokio::spawn(async { Ok(()) }),
        };

        info!("Started bundle builder");

        match try_join!(
            handle::flatten_handle(builder_runnder_handle),
            handle::flatten_handle(remote_handle),
        ) {
            Ok(_) => {
                tracing::info!("Builder server shutdown");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Builder server error: {e:?}");
                bail!("Builder server error: {e:?}")
            }
        }
    }
}

impl<P> BuilderTask<P>
where
    P: PoolServer + Clone,
{
    pub fn new(
        args: Args,
        event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
        builder_builder: LocalBuilderBuilder,
        pool: P,
    ) -> Self {
        Self {
            args,
            event_sender,
            builder_builder,
            pool,
        }
    }

    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }
}
