// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use anyhow::{bail, Context};
use async_trait::async_trait;
use ethers::{
    providers::{JsonRpcClient, Provider},
    types::{Address, H256},
};
use ethers_signers::Signer;
use futures::future;
use futures_util::TryFutureExt;
use rundler_pool::PoolServer;
use rundler_sim::{
    MempoolConfig, PriorityFeeMode, SimulateValidationTracerImpl, SimulationSettings, SimulatorImpl,
};
use rundler_task::Task;
use rundler_types::contracts::i_entry_point::IEntryPoint;
use rundler_utils::{emit::WithEntryPoint, eth, handle};
use rusoto_core::Region;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinHandle,
    time, try_join,
};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    bundle_proposer::{self, BundleProposerImpl},
    bundle_sender::{self, BundleSender, BundleSenderImpl, SendBundleRequest},
    emit::BuilderEvent,
    sender::TransactionSenderType,
    server::{spawn_remote_builder_server, LocalBuilderBuilder},
    signer::{BundlerSigner, KmsSigner, LocalSigner},
    transaction_tracker::{self, TransactionTrackerImpl},
};

/// Builder task arguments
#[derive(Debug)]
pub struct Args {
    /// Full node RPC url
    pub rpc_url: String,
    /// Address of the entry point contract this builder targets
    pub entry_point_address: Address,
    /// Private key to use for signing transactions
    /// If not provided, AWS KMS will be used
    pub private_key: Option<String>,
    /// AWS KMS key ids to use for signing transactions
    /// Only used if private_key is not provided
    pub aws_kms_key_ids: Vec<String>,
    /// AWS KMS region
    pub aws_kms_region: Region,
    /// Redis URI for key leasing
    pub redis_uri: String,
    /// Redis lease TTL in milliseconds
    pub redis_lock_ttl_millis: u64,
    /// Chain ID
    pub chain_id: u64,
    /// Maximum bundle size in number of operations
    pub max_bundle_size: u64,
    /// Maximum bundle size in gas limit
    pub max_bundle_gas: u64,
    /// URL to submit bundles too
    pub submit_url: String,
    /// Whether to use bundle priority fee
    /// If unset, will use the default value of true for known EIP-1559 chains
    pub use_bundle_priority_fee: Option<bool>,
    /// Percentage to add to the the network priority fee for the bundle priority fee
    pub bundle_priority_fee_overhead_percent: u64,
    /// Priority fee mode to use for operation priority fee minimums
    pub priority_fee_mode: PriorityFeeMode,
    /// Sender to be used by the builder
    pub sender_type: TransactionSenderType,
    /// RPC node poll interval
    pub eth_poll_interval: Duration,
    /// Operation simulation settings
    pub sim_settings: SimulationSettings,
    /// Alt-mempool configs
    pub mempool_configs: HashMap<H256, MempoolConfig>,
    /// Maximum number of blocks to wait for a transaction to be mined
    pub max_blocks_to_wait_for_mine: u64,
    /// Percentage to increase the fees by when replacing a bundle transaction
    pub replacement_fee_percent_increase: u64,
    /// Maximum number of times to increase the fees when replacing a bundle transaction
    pub max_fee_increases: u64,
    /// Address to bind the remote builder server to, if any. If none, no server is starter.
    pub remote_address: Option<SocketAddr>,
    /// Optional Bloxroute auth header
    ///
    /// This is only used for Polygon.
    ///
    /// Checked ~after~ checking for conditional sender or Flashbots sender.
    pub bloxroute_auth_header: Option<String>,
    /// Number of bundle builders to start
    pub num_bundle_builders: u64,
    /// Index offset for bundle builders
    pub bundle_builder_index_offset: u64,
}

/// Builder task
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
        info!("Mempool config: {:?}", self.args.mempool_configs);

        let provider = eth::new_provider(&self.args.rpc_url, self.args.eth_poll_interval)?;
        let manual_bundling_mode = Arc::new(AtomicBool::new(false));

        let mut sender_handles = vec![];
        let mut send_bundle_txs = vec![];
        for i in 0..self.args.num_bundle_builders {
            let (spawn_guard, send_bundle_tx) = self
                .create_bundle_builder(
                    i + self.args.bundle_builder_index_offset,
                    Arc::clone(&manual_bundling_mode),
                    Arc::clone(&provider),
                )
                .await?;
            sender_handles.push(spawn_guard);
            send_bundle_txs.push(send_bundle_tx);
        }
        // flatten the senders handles to one handle, short-circuit on errors
        let sender_handle = tokio::spawn(
            future::try_join_all(sender_handles)
                .map_ok(|_| ())
                .map_err(|e| anyhow::anyhow!(e)),
        );

        let builder_handle = self.builder_builder.get_handle();
        let builder_runnder_handle = self.builder_builder.run(
            manual_bundling_mode,
            send_bundle_txs,
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
            handle::flatten_handle(sender_handle),
            handle::flatten_handle(builder_runnder_handle),
            handle::flatten_handle(remote_handle),
        ) {
            Ok(_) => {
                info!("Builder server shutdown");
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
    /// Create a new builder task
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

    /// Convert this task into a boxed task
    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }

    async fn create_bundle_builder<C: JsonRpcClient + 'static>(
        &self,
        index: u64,
        manual_bundling_mode: Arc<AtomicBool>,
        provider: Arc<Provider<C>>,
    ) -> anyhow::Result<(
        JoinHandle<anyhow::Result<()>>,
        mpsc::Sender<SendBundleRequest>,
    )> {
        let (send_bundle_tx, send_bundle_rx) = mpsc::channel(1);

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

        let transaction_sender = self.args.sender_type.into_sender(
            submit_provider,
            signer,
            self.args.chain_id,
            self.args.eth_poll_interval,
            &self.args.bloxroute_auth_header,
        )?;

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

        let proposer = BundleProposerImpl::new(
            index,
            self.pool.clone(),
            simulator,
            entry_point.clone(),
            Arc::clone(&provider),
            proposer_settings,
            self.event_sender.clone(),
        );
        let builder = BundleSenderImpl::new(
            index,
            manual_bundling_mode.clone(),
            send_bundle_rx,
            self.args.chain_id,
            beneficiary,
            proposer,
            entry_point,
            transaction_tracker,
            self.pool.clone(),
            builder_settings,
            self.event_sender.clone(),
        );

        // Spawn each sender as its own independent task
        Ok((tokio::spawn(builder.send_bundles_in_loop()), send_bundle_tx))
    }
}
