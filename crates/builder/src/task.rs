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

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use alloy_primitives::{Address, B256};
use anyhow::Context;
use rundler_provider::{Providers as ProvidersT, ProvidersWithEntryPointT};
use rundler_sim::{
    gas::{self, FeeEstimatorImpl},
    simulation::{self, UnsafeSimulator},
    MempoolConfig, PriorityFeeMode, SimulationSettings, Simulator,
};
use rundler_task::TaskSpawnerExt;
use rundler_types::{
    chain::ChainSpec, pool::Pool as PoolT, EntryPointVersion, UserOperation, UserOperationVariant,
};
use rundler_utils::emit::WithEntryPoint;
use tokio::{
    sync::{broadcast, mpsc},
    time,
};
use tracing::info;

use crate::{
    bundle_proposer::{self, BundleProposerImpl, BundleProposerProviders},
    bundle_sender::{self, BundleSender, BundleSenderAction, BundleSenderImpl},
    emit::BuilderEvent,
    sender::TransactionSenderArgs,
    server::{self, LocalBuilderBuilder},
    signer::{BundlerSigner, KmsSigner, LocalSigner, Signer},
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
    /// Redis URI for key leasing
    pub redis_uri: String,
    /// Redis lease TTL in milliseconds
    pub redis_lock_ttl_millis: u64,
    /// Maximum bundle size in number of operations
    pub max_bundle_size: u64,
    /// Maximum bundle size in gas limit
    pub max_bundle_gas: u128,
    /// Percentage to add to the network pending base fee for the bundle base fee
    pub bundle_base_fee_overhead_percent: u32,
    /// Percentage to add to the network priority fee for the bundle priority fee
    pub bundle_priority_fee_overhead_percent: u32,
    /// Priority fee mode to use for operation priority fee minimums
    pub priority_fee_mode: PriorityFeeMode,
    /// Sender to be used by the builder
    pub sender_args: TransactionSenderArgs,
    /// Operation simulation settings
    pub sim_settings: SimulationSettings,
    /// Maximum number of blocks to wait for a transaction to be mined
    pub max_blocks_to_wait_for_mine: u64,
    /// Percentage to increase the fees by when replacing a bundle transaction
    pub replacement_fee_percent_increase: u32,
    /// Maximum number of times to increase the fee when cancelling a transaction
    pub max_cancellation_fee_increases: u64,
    /// Maximum amount of blocks to spend in a replacement underpriced state before moving to cancel
    pub max_replacement_underpriced_blocks: u64,
    /// Address to bind the remote builder server to, if any. If none, no server is starter.
    pub remote_address: Option<SocketAddr>,
    /// Entry points to start builders for
    pub entry_points: Vec<EntryPointBuilderSettings>,
    /// Enable DA tracking
    pub da_gas_tracking_enabled: bool,
    /// Provider client timeout
    pub provider_client_timeout_seconds: u64,
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
    pub mempool_configs: HashMap<B256, MempoolConfig>,
}

/// Builder task
pub struct BuilderTask<Pool, Providers> {
    args: Args,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    builder_builder: LocalBuilderBuilder,
    pool: Pool,
    providers: Providers,
}

impl<Pool, Providers> BuilderTask<Pool, Providers> {
    /// Create a new builder task
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        args: Args,
        event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
        builder_builder: LocalBuilderBuilder,
        pool: Pool,
        providers: Providers,
    ) -> Self {
        Self {
            args,
            event_sender,
            builder_builder,
            pool,
            providers,
        }
    }
}

impl<Pool, Providers> BuilderTask<Pool, Providers>
where
    Pool: PoolT + Clone + 'static,
    Providers: ProvidersT + 'static,
{
    /// Spawn the builder task on the given task spawner
    pub async fn spawn<T: TaskSpawnerExt>(self, task_spawner: T) -> anyhow::Result<()> {
        let mut bundle_sender_actions = vec![];
        let mut pk_iter = self.args.private_keys.clone().into_iter();

        for ep in &self.args.entry_points {
            match ep.version {
                EntryPointVersion::V0_6 => {
                    let actions = self
                        .create_builders_v0_6(&task_spawner, ep, &mut pk_iter)
                        .await?;
                    bundle_sender_actions.extend(actions);
                }
                EntryPointVersion::V0_7 => {
                    let actions = self
                        .create_builders_v0_7(&task_spawner, ep, &mut pk_iter)
                        .await?;
                    bundle_sender_actions.extend(actions);
                }
                EntryPointVersion::Unspecified => {
                    panic!("Unspecified entry point version")
                }
            }
        }

        let builder_handle = self.builder_builder.get_handle();

        task_spawner.spawn_critical_with_graceful_shutdown_signal(
            "local builder server",
            |shutdown| {
                self.builder_builder.run(
                    bundle_sender_actions,
                    vec![self.args.chain_spec.entry_point_address_v0_6],
                    shutdown,
                )
            },
        );

        if let Some(addr) = self.args.remote_address {
            task_spawner.spawn_critical_with_graceful_shutdown_signal(
                "remote builder server",
                |shutdown| {
                    server::remote_builder_server_task(
                        addr,
                        self.args.chain_spec.id,
                        builder_handle,
                        shutdown,
                    )
                },
            );
        }

        info!("Started bundle builder");
        Ok(())
    }

    async fn create_builders_v0_6<T, I>(
        &self,
        task_spawner: &T,
        ep: &EntryPointBuilderSettings,
        pk_iter: &mut I,
    ) -> anyhow::Result<Vec<mpsc::Sender<BundleSenderAction>>>
    where
        T: TaskSpawnerExt,
        I: Iterator<Item = String>,
    {
        info!("Mempool config for ep v0.6: {:?}", ep.mempool_configs);
        let ep_providers = self
            .providers
            .ep_v0_6_providers()
            .clone()
            .context("entry point v0.6 not supplied")?;
        let mut bundle_sender_actions = vec![];
        for i in 0..ep.num_bundle_builders {
            let bundle_sender_action = if self.args.unsafe_mode {
                self.create_bundle_builder(
                    task_spawner,
                    i + ep.bundle_builder_index_offset,
                    ep_providers.clone(),
                    UnsafeSimulator::new(ep_providers.entry_point().clone()),
                    pk_iter,
                )
                .await?
            } else {
                self.create_bundle_builder(
                    task_spawner,
                    i + ep.bundle_builder_index_offset,
                    ep_providers.clone(),
                    simulation::new_v0_6_simulator(
                        ep_providers.evm().clone(),
                        ep_providers.entry_point().clone(),
                        self.args.sim_settings.clone(),
                        ep.mempool_configs.clone(),
                    ),
                    pk_iter,
                )
                .await?
            };
            bundle_sender_actions.push(bundle_sender_action);
        }
        Ok(bundle_sender_actions)
    }

    async fn create_builders_v0_7<T, I>(
        &self,
        task_spawner: &T,
        ep: &EntryPointBuilderSettings,
        pk_iter: &mut I,
    ) -> anyhow::Result<Vec<mpsc::Sender<BundleSenderAction>>>
    where
        T: TaskSpawnerExt,
        I: Iterator<Item = String>,
    {
        info!("Mempool config for ep v0.7: {:?}", ep.mempool_configs);
        let ep_providers = self
            .providers
            .ep_v0_7_providers()
            .clone()
            .context("entry point v0.7 not supplied")?;
        let mut bundle_sender_actions = vec![];
        for i in 0..ep.num_bundle_builders {
            let bundle_sender_action = if self.args.unsafe_mode {
                self.create_bundle_builder(
                    task_spawner,
                    i + ep.bundle_builder_index_offset,
                    ep_providers.clone(),
                    UnsafeSimulator::new(ep_providers.entry_point().clone()),
                    pk_iter,
                )
                .await?
            } else {
                self.create_bundle_builder(
                    task_spawner,
                    i + ep.bundle_builder_index_offset,
                    ep_providers.clone(),
                    simulation::new_v0_7_simulator(
                        ep_providers.evm().clone(),
                        ep_providers.entry_point().clone(),
                        self.args.sim_settings.clone(),
                        ep.mempool_configs.clone(),
                    ),
                    pk_iter,
                )
                .await?
            };
            bundle_sender_actions.push(bundle_sender_action);
        }
        Ok(bundle_sender_actions)
    }

    async fn create_bundle_builder<T, UO, EP, S, I>(
        &self,
        task_spawner: &T,
        index: u64,
        ep_providers: EP,
        simulator: S,
        pk_iter: &mut I,
    ) -> anyhow::Result<mpsc::Sender<BundleSenderAction>>
    where
        T: TaskSpawnerExt,
        UO: UserOperation + From<UserOperationVariant>,
        UserOperationVariant: AsRef<UO>,
        EP: ProvidersWithEntryPointT + 'static,
        S: Simulator<UO = UO> + 'static,
        I: Iterator<Item = String>,
    {
        let (send_bundle_tx, send_bundle_rx) = mpsc::channel(1);

        let signer = if let Some(pk) = pk_iter.next() {
            info!("Using local signer");
            BundlerSigner::Local(
                LocalSigner::connect(
                    &task_spawner,
                    self.providers.evm().clone(),
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
                    &task_spawner,
                    self.providers.evm().clone(),
                    self.args.chain_spec.id,
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
            bundle_base_fee_overhead_percent: self.args.bundle_base_fee_overhead_percent,
            bundle_priority_fee_overhead_percent: self.args.bundle_priority_fee_overhead_percent,
            da_gas_tracking_enabled: self.args.da_gas_tracking_enabled,
        };

        let transaction_sender = self.args.sender_args.clone().into_sender(
            &self.args.rpc_url,
            signer,
            self.args.provider_client_timeout_seconds,
        )?;

        let tracker_settings = transaction_tracker::Settings {
            replacement_fee_percent_increase: self.args.replacement_fee_percent_increase,
        };

        let transaction_tracker = TransactionTrackerImpl::new(
            ep_providers.evm().clone(),
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

        let fee_oracle = gas::get_fee_oracle(&self.args.chain_spec, ep_providers.evm().clone());
        let fee_estimator = FeeEstimatorImpl::new(
            ep_providers.evm().clone(),
            fee_oracle,
            proposer_settings.priority_fee_mode,
            proposer_settings.bundle_base_fee_overhead_percent,
            proposer_settings.bundle_priority_fee_overhead_percent,
        );

        let proposer = BundleProposerImpl::new(
            index,
            ep_providers.clone(),
            BundleProposerProviders::new(self.pool.clone(), simulator, fee_estimator),
            proposer_settings,
            self.event_sender.clone(),
        );

        let builder = BundleSenderImpl::new(
            index,
            send_bundle_rx,
            self.args.chain_spec.clone(),
            beneficiary,
            proposer,
            ep_providers.entry_point().clone(),
            transaction_tracker,
            self.pool.clone(),
            builder_settings,
            self.event_sender.clone(),
        );

        // Spawn each sender as its own independent task
        let ts = task_spawner.clone();
        task_spawner.spawn_critical("bundle sender", builder.send_bundles_in_loop(ts));

        Ok(send_bundle_tx)
    }
}
