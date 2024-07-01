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

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use async_trait::async_trait;
use ethers::{
    providers::{JsonRpcClient, Provider as EthersProvider},
    types::{Address, H256},
};
use ethers_signers::Signer;
use futures::future;
use futures_util::TryFutureExt;
use rundler_provider::{EntryPointProvider, EthersEntryPointV0_6, EthersEntryPointV0_7};
use rundler_sim::{
    simulation::{self, UnsafeSimulator},
    MempoolConfig, PriorityFeeMode, SimulationSettings, Simulator,
};
use rundler_task::Task;
use rundler_types::{
    chain::ChainSpec, pool::Pool, v0_6, v0_7, EntryPointVersion, UserOperation,
    UserOperationVariant,
};
use rundler_utils::{emit::WithEntryPoint, handle};
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
    bundle_sender::{self, BundleSender, BundleSenderAction, BundleSenderImpl},
    emit::BuilderEvent,
    sender::TransactionSenderArgs,
    server::{spawn_remote_builder_server, LocalBuilderBuilder},
    signer::{BundlerSigner, KmsSigner, LocalSigner},
    transaction_tracker::{self, TransactionTrackerImpl},
};

/// Builder task arguments
#[derive(Debug)]
pub struct Args {
    /// Chain spec
    pub chain_spec: ChainSpec,
    /// Full node RPC url
    pub rpc_url: String,
    /// True if using unsafe mode
    pub unsafe_mode: bool,
    /// Private key to use for signing transactions
    /// If empty, AWS KMS will be used
    pub private_keys: Vec<String>,
    /// AWS KMS key ids to use for signing transactions
    /// Only used if private_key is not provided
    pub aws_kms_key_ids: Vec<String>,
    /// AWS KMS region
    pub aws_kms_region: Region,
    /// Redis URI for key leasing
    pub redis_uri: String,
    /// Redis lease TTL in milliseconds
    pub redis_lock_ttl_millis: u64,
    /// Maximum bundle size in number of operations
    pub max_bundle_size: u64,
    /// Maximum bundle size in gas limit
    pub max_bundle_gas: u64,
    /// Percentage to add to the network priority fee for the bundle priority fee
    pub bundle_priority_fee_overhead_percent: u64,
    /// Priority fee mode to use for operation priority fee minimums
    pub priority_fee_mode: PriorityFeeMode,
    /// Sender to be used by the builder
    pub sender_args: TransactionSenderArgs,
    /// Operation simulation settings
    pub sim_settings: SimulationSettings,
    /// Maximum number of blocks to wait for a transaction to be mined
    pub max_blocks_to_wait_for_mine: u64,
    /// Percentage to increase the fees by when replacing a bundle transaction
    pub replacement_fee_percent_increase: u64,
    /// Maximum number of times to increase the fee when cancelling a transaction
    pub max_cancellation_fee_increases: u64,
    /// Maximum amount of blocks to spend in a replacement underpriced state before moving to cancel
    pub max_replacement_underpriced_blocks: u64,
    /// Address to bind the remote builder server to, if any. If none, no server is starter.
    pub remote_address: Option<SocketAddr>,
    /// Entry points to start builders for
    pub entry_points: Vec<EntryPointBuilderSettings>,
}

/// Builder settings for an entrypoint
#[derive(Debug)]
pub struct EntryPointBuilderSettings {
    /// Entry point address
    pub address: Address,
    /// Entry point version
    pub version: EntryPointVersion,
    /// Number of bundle builders to start
    pub num_bundle_builders: u64,
    /// Index offset for bundle builders
    pub bundle_builder_index_offset: u64,
    /// Mempool configs
    pub mempool_configs: HashMap<H256, MempoolConfig>,
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
    P: Pool + Clone,
{
    async fn run(mut self: Box<Self>, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let provider = rundler_provider::new_provider(&self.args.rpc_url, None)?;
        let submit_provider = if let TransactionSenderArgs::Raw(args) = &self.args.sender_args {
            Some(rundler_provider::new_provider(&args.submit_url, None)?)
        } else {
            None
        };

        let ep_v0_6 = EthersEntryPointV0_6::new(
            self.args.chain_spec.entry_point_address_v0_6,
            &self.args.chain_spec,
            self.args.sim_settings.max_simulate_handle_ops_gas,
            Arc::clone(&provider),
        );
        let ep_v0_7 = EthersEntryPointV0_7::new(
            self.args.chain_spec.entry_point_address_v0_7,
            &self.args.chain_spec,
            self.args.sim_settings.max_simulate_handle_ops_gas,
            Arc::clone(&provider),
        );

        let mut sender_handles = vec![];
        let mut bundle_sender_actions = vec![];
        let mut pk_iter = self.args.private_keys.clone().into_iter();

        for ep in &self.args.entry_points {
            match ep.version {
                EntryPointVersion::V0_6 => {
                    let (handles, actions) = self
                        .create_builders_v0_6(
                            ep,
                            Arc::clone(&provider),
                            submit_provider.clone(),
                            ep_v0_6.clone(),
                            &mut pk_iter,
                        )
                        .await?;
                    sender_handles.extend(handles);
                    bundle_sender_actions.extend(actions);
                }
                EntryPointVersion::V0_7 => {
                    let (handles, actions) = self
                        .create_builders_v0_7(
                            ep,
                            Arc::clone(&provider),
                            submit_provider.clone(),
                            ep_v0_7.clone(),
                            &mut pk_iter,
                        )
                        .await?;
                    sender_handles.extend(handles);
                    bundle_sender_actions.extend(actions);
                }
                EntryPointVersion::Unspecified => {
                    panic!("Unspecified entry point version")
                }
            }
        }

        // flatten the senders handles to one handle, short-circuit on errors
        let sender_handle = tokio::spawn(
            future::try_join_all(sender_handles)
                .map_ok(|_| ())
                .map_err(|e| anyhow::anyhow!(e)),
        );

        let builder_handle = self.builder_builder.get_handle();
        let builder_runnder_handle = self.builder_builder.run(
            bundle_sender_actions,
            vec![self.args.chain_spec.entry_point_address_v0_6],
            shutdown_token.clone(),
        );

        let remote_handle = match self.args.remote_address {
            Some(addr) => {
                spawn_remote_builder_server(
                    addr,
                    self.args.chain_spec.id,
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
    P: Pool + Clone,
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

    async fn create_builders_v0_6<C, E, I>(
        &self,
        ep: &EntryPointBuilderSettings,
        provider: Arc<EthersProvider<C>>,
        submit_provider: Option<Arc<EthersProvider<C>>>,
        ep_v0_6: E,
        pk_iter: &mut I,
    ) -> anyhow::Result<(
        Vec<JoinHandle<anyhow::Result<()>>>,
        Vec<mpsc::Sender<BundleSenderAction>>,
    )>
    where
        C: JsonRpcClient + 'static,
        E: EntryPointProvider<v0_6::UserOperation> + Clone,
        I: Iterator<Item = String>,
    {
        info!("Mempool config for ep v0.6: {:?}", ep.mempool_configs);
        let mut sender_handles = vec![];
        let mut bundle_sender_actions = vec![];
        for i in 0..ep.num_bundle_builders {
            let (spawn_guard, bundle_sender_action) = if self.args.unsafe_mode {
                self.create_bundle_builder(
                    i + ep.bundle_builder_index_offset,
                    Arc::clone(&provider),
                    submit_provider.clone(),
                    ep_v0_6.clone(),
                    UnsafeSimulator::new(
                        Arc::clone(&provider),
                        ep_v0_6.clone(),
                        self.args.sim_settings.clone(),
                    ),
                    pk_iter,
                )
                .await?
            } else {
                self.create_bundle_builder(
                    i + ep.bundle_builder_index_offset,
                    Arc::clone(&provider),
                    submit_provider.clone(),
                    ep_v0_6.clone(),
                    simulation::new_v0_6_simulator(
                        Arc::clone(&provider),
                        ep_v0_6.clone(),
                        self.args.sim_settings.clone(),
                        ep.mempool_configs.clone(),
                    ),
                    pk_iter,
                )
                .await?
            };
            sender_handles.push(spawn_guard);
            bundle_sender_actions.push(bundle_sender_action);
        }
        Ok((sender_handles, bundle_sender_actions))
    }

    async fn create_builders_v0_7<C, E, I>(
        &self,
        ep: &EntryPointBuilderSettings,
        provider: Arc<EthersProvider<C>>,
        submit_provider: Option<Arc<EthersProvider<C>>>,
        ep_v0_7: E,
        pk_iter: &mut I,
    ) -> anyhow::Result<(
        Vec<JoinHandle<anyhow::Result<()>>>,
        Vec<mpsc::Sender<BundleSenderAction>>,
    )>
    where
        C: JsonRpcClient + 'static,
        E: EntryPointProvider<v0_7::UserOperation> + Clone,
        I: Iterator<Item = String>,
    {
        info!("Mempool config for ep v0.7: {:?}", ep.mempool_configs);
        let mut sender_handles = vec![];
        let mut bundle_sender_actions = vec![];
        for i in 0..ep.num_bundle_builders {
            let (spawn_guard, bundle_sender_action) = if self.args.unsafe_mode {
                self.create_bundle_builder(
                    i + ep.bundle_builder_index_offset,
                    Arc::clone(&provider),
                    submit_provider.clone(),
                    ep_v0_7.clone(),
                    UnsafeSimulator::new(
                        Arc::clone(&provider),
                        ep_v0_7.clone(),
                        self.args.sim_settings.clone(),
                    ),
                    pk_iter,
                )
                .await?
            } else {
                self.create_bundle_builder(
                    i + ep.bundle_builder_index_offset,
                    Arc::clone(&provider),
                    submit_provider.clone(),
                    ep_v0_7.clone(),
                    simulation::new_v0_7_simulator(
                        Arc::clone(&provider),
                        ep_v0_7.clone(),
                        self.args.sim_settings.clone(),
                        ep.mempool_configs.clone(),
                    ),
                    pk_iter,
                )
                .await?
            };
            sender_handles.push(spawn_guard);
            bundle_sender_actions.push(bundle_sender_action);
        }
        Ok((sender_handles, bundle_sender_actions))
    }

    async fn create_bundle_builder<UO, E, S, C, I>(
        &self,
        index: u64,
        provider: Arc<EthersProvider<C>>,
        submit_provider: Option<Arc<EthersProvider<C>>>,
        entry_point: E,
        simulator: S,
        pk_iter: &mut I,
    ) -> anyhow::Result<(
        JoinHandle<anyhow::Result<()>>,
        mpsc::Sender<BundleSenderAction>,
    )>
    where
        UO: UserOperation + From<UserOperationVariant>,
        UserOperationVariant: AsRef<UO>,
        E: EntryPointProvider<UO> + Clone,
        S: Simulator<UO = UO>,
        C: JsonRpcClient + 'static,
        I: Iterator<Item = String>,
    {
        let (send_bundle_tx, send_bundle_rx) = mpsc::channel(1);

        let signer = if let Some(pk) = pk_iter.next() {
            info!("Using local signer");
            BundlerSigner::Local(
                LocalSigner::connect(
                    Arc::clone(&provider),
                    self.args.chain_spec.id,
                    pk.to_owned(),
                )
                .await?,
            )
        } else {
            info!("Using AWS KMS signer");
            let signer = time::timeout(
                // timeout must be < than the lock TTL to avoid a
                // bug in the redis lock implementation that panics if connection
                // takes longer than the TTL. Generally the TLL should be on the order of 10s of seconds
                // so this should give ample time for the connection to establish.
                Duration::from_millis(self.args.redis_lock_ttl_millis / 4),
                KmsSigner::connect(
                    Arc::clone(&provider),
                    self.args.chain_spec.id,
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
            chain_spec: self.args.chain_spec.clone(),
            max_bundle_size: self.args.max_bundle_size,
            max_bundle_gas: self.args.max_bundle_gas,
            beneficiary,
            priority_fee_mode: self.args.priority_fee_mode,
            bundle_priority_fee_overhead_percent: self.args.bundle_priority_fee_overhead_percent,
        };

        let transaction_sender = self.args.sender_args.clone().into_sender(
            Arc::clone(&provider),
            submit_provider,
            signer,
        )?;

        let tracker_settings = transaction_tracker::Settings {
            replacement_fee_percent_increase: self.args.replacement_fee_percent_increase,
        };

        let transaction_tracker = TransactionTrackerImpl::new(
            Arc::clone(&provider),
            transaction_sender,
            tracker_settings,
            index,
        )
        .await?;

        let builder_settings = bundle_sender::Settings {
            max_replacement_underpriced_blocks: self.args.max_replacement_underpriced_blocks,
            max_cancellation_fee_increases: self.args.max_cancellation_fee_increases,
            max_blocks_to_wait_for_mine: self.args.max_blocks_to_wait_for_mine,
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
            send_bundle_rx,
            self.args.chain_spec.clone(),
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
