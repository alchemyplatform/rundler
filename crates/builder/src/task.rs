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
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use alloy_primitives::{Address, B256};
use anyhow::Context;
use rundler_provider::{EntryPoint, Providers as ProvidersT, ProvidersWithEntryPointT};
use rundler_signer::{SignerManager, SigningScheme};
use rundler_sim::{
    simulation::{self, UnsafeSimulator},
    MempoolConfig, SimulationSettings, Simulator,
};
use rundler_task::TaskSpawnerExt;
use rundler_types::{
    chain::ChainSpec, pool::Pool as PoolT, EntryPointVersion, UserOperation, UserOperationVariant,
};
use rundler_utils::emit::WithEntryPoint;
use tokio::sync::{broadcast, mpsc};
use tracing::info;

use crate::{
    assigner::Assigner,
    bundle_proposer::{self, BundleProposerImpl, BundleProposerProviders},
    bundle_sender::{self, BundleSender, BundleSenderAction, BundleSenderImpl},
    emit::BuilderEvent,
    sender::TransactionSenderArgs,
    server::{self, LocalBuilderBuilder},
    transaction_tracker::{self, TransactionTrackerImpl},
};

const MAX_POOL_OPS_PER_REQUEST: u64 = 1024;

/// Builder task arguments
#[derive(Debug)]
pub struct Args {
    /// Chain spec
    pub chain_spec: ChainSpec,
    /// Full node RPC url
    pub rpc_url: String,
    /// True if using unsafe mode
    pub unsafe_mode: bool,
    /// Signing scheme to use
    pub signing_scheme: SigningScheme,
    /// Whether to automatically fund signers
    pub auto_fund: bool,
    /// Maximum bundle size in number of operations
    pub max_bundle_size: u64,
    /// Target bundle size in gas
    pub target_bundle_gas: u128,
    /// Maximum bundle size in gas
    pub max_bundle_gas: u128,
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
    /// Maximum number of expected storage slots in a bundle
    pub max_expected_storage_slots: usize,
    /// Rejects user operations with a verification gas limit efficiency below this threshold.
    pub verification_gas_limit_efficiency_reject_threshold: f64,
}

/// Builder settings
#[derive(Debug, Clone)]
pub struct BuilderSettings {
    /// Optional submission proxy to use for this builder
    pub submission_proxy: Option<Address>,
    /// Optional filter id to apply to this builder
    pub filter_id: Option<String>,
}

impl BuilderSettings {
    /// Unique string tag for this builder
    pub fn tag(&self, entry_point_address: &Address, builder_address: &Address) -> String {
        format!(
            "{}:{}:{}",
            entry_point_address,
            self.filter_id.as_ref().map_or("any", |v| v),
            builder_address
        )
    }
}

/// Builder settings for an entrypoint
#[derive(Debug)]
pub struct EntryPointBuilderSettings {
    /// Entry point address
    pub address: Address,
    /// Entry point version
    pub version: EntryPointVersion,
    /// Mempool configs
    pub mempool_configs: HashMap<B256, MempoolConfig>,
    /// Builder settings
    pub builders: Vec<BuilderSettings>,
}

/// Builder task
pub struct BuilderTask<Pool, Providers> {
    args: Args,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    builder_builder: LocalBuilderBuilder,
    pool: Pool,
    providers: Providers,
    signer_manager: Arc<dyn SignerManager>,
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
        signer_manager: Arc<dyn SignerManager>,
    ) -> Self {
        Self {
            args,
            event_sender,
            builder_builder,
            pool,
            providers,
            signer_manager,
        }
    }
}

impl<Pool, Providers> BuilderTask<Pool, Providers>
where
    Pool: PoolT + Clone + 'static,
    Providers: ProvidersT + 'static,
{
    /// Spawn the builder task on the given task spawner
    pub async fn spawn<T>(self, task_spawner: T) -> anyhow::Result<()>
    where
        T: TaskSpawnerExt,
    {
        let mut bundle_sender_actions = vec![];

        let num_required_signers: usize = self
            .args
            .entry_points
            .iter()
            .map(|ep| ep.builders.len())
            .sum();

        // wait 60 seconds for the signers to be available
        match tokio::time::timeout(
            Duration::from_secs(60),
            self.signer_manager.wait_for_available(num_required_signers),
        )
        .await
        {
            Ok(r) => {
                if let Err(e) = r {
                    return Err(e.into());
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to wait for {num_required_signers} signers to be available: {e}"
                ));
            }
        }

        let assigner = Arc::new(Assigner::new(
            Box::new(self.pool.clone()),
            MAX_POOL_OPS_PER_REQUEST,
            self.args.max_bundle_size,
        ));

        let mut supported_entry_points = HashSet::new();
        for ep in &self.args.entry_points {
            match ep.version {
                EntryPointVersion::V0_6 => {
                    let actions = self
                        .create_builders_v0_6(
                            &task_spawner,
                            ep,
                            &self.signer_manager,
                            assigner.clone(),
                        )
                        .await?;
                    bundle_sender_actions.extend(actions);
                    supported_entry_points.insert(self.args.chain_spec.entry_point_address_v0_6);
                }
                EntryPointVersion::V0_7 => {
                    let actions = self
                        .create_builders_v0_7(
                            &task_spawner,
                            ep,
                            &self.signer_manager,
                            assigner.clone(),
                        )
                        .await?;
                    bundle_sender_actions.extend(actions);
                    supported_entry_points.insert(self.args.chain_spec.entry_point_address_v0_7);
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
                    supported_entry_points.into_iter().collect(),
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

    async fn create_builders_v0_6<T>(
        &self,
        task_spawner: &T,
        ep: &EntryPointBuilderSettings,
        signer_manager: &Arc<dyn SignerManager>,
        assigner: Arc<Assigner>,
    ) -> anyhow::Result<Vec<mpsc::Sender<BundleSenderAction>>>
    where
        T: TaskSpawnerExt,
    {
        info!("Mempool config for ep v0.6: {:?}", ep.mempool_configs);
        let ep_providers = self
            .providers
            .ep_v0_6_providers()
            .clone()
            .context("entry point v0.6 not supplied")?;
        let mut bundle_sender_actions = vec![];
        for settings in &ep.builders {
            let bundle_sender_action = if self.args.unsafe_mode {
                self.create_bundle_builder(
                    task_spawner,
                    settings,
                    ep_providers.clone(),
                    UnsafeSimulator::new(
                        ep_providers.entry_point().clone(),
                        self.args.sim_settings.clone(),
                    ),
                    signer_manager,
                    assigner.clone(),
                )
                .await?
            } else {
                self.create_bundle_builder(
                    task_spawner,
                    settings,
                    ep_providers.clone(),
                    simulation::new_v0_6_simulator(
                        ep_providers.evm().clone(),
                        ep_providers.entry_point().clone(),
                        self.args.sim_settings.clone(),
                        ep.mempool_configs.clone(),
                    ),
                    signer_manager,
                    assigner.clone(),
                )
                .await?
            };
            bundle_sender_actions.push(bundle_sender_action);
        }
        Ok(bundle_sender_actions)
    }

    async fn create_builders_v0_7<T>(
        &self,
        task_spawner: &T,
        ep: &EntryPointBuilderSettings,
        signer_manager: &Arc<dyn SignerManager>,
        assigner: Arc<Assigner>,
    ) -> anyhow::Result<Vec<mpsc::Sender<BundleSenderAction>>>
    where
        T: TaskSpawnerExt,
    {
        info!("Mempool config for ep v0.7: {:?}", ep.mempool_configs);
        let ep_providers = self
            .providers
            .ep_v0_7_providers()
            .clone()
            .context("entry point v0.7 not supplied")?;
        let mut bundle_sender_actions = vec![];
        for settings in &ep.builders {
            let bundle_sender_action = if self.args.unsafe_mode {
                self.create_bundle_builder(
                    task_spawner,
                    settings,
                    ep_providers.clone(),
                    UnsafeSimulator::new(
                        ep_providers.entry_point().clone(),
                        self.args.sim_settings.clone(),
                    ),
                    signer_manager,
                    assigner.clone(),
                )
                .await?
            } else {
                self.create_bundle_builder(
                    task_spawner,
                    settings,
                    ep_providers.clone(),
                    simulation::new_v0_7_simulator(
                        ep_providers.evm().clone(),
                        ep_providers.entry_point().clone(),
                        self.args.sim_settings.clone(),
                        ep.mempool_configs.clone(),
                    ),
                    signer_manager,
                    assigner.clone(),
                )
                .await?
            };
            bundle_sender_actions.push(bundle_sender_action);
        }
        Ok(bundle_sender_actions)
    }

    async fn create_bundle_builder<T, UO, EP, S>(
        &self,
        task_spawner: &T,
        builder_settings: &BuilderSettings,
        ep_providers: EP,
        simulator: S,
        signer_manager: &Arc<dyn SignerManager>,
        assigner: Arc<Assigner>,
    ) -> anyhow::Result<mpsc::Sender<BundleSenderAction>>
    where
        T: TaskSpawnerExt,
        UO: UserOperation + From<UserOperationVariant>,
        UserOperationVariant: AsRef<UO>,
        EP: ProvidersWithEntryPointT + 'static,
        S: Simulator<UO = UO> + 'static,
    {
        let (send_bundle_tx, send_bundle_rx) = mpsc::channel(1);

        let Some(signer) = signer_manager.lease_signer() else {
            return Err(anyhow::anyhow!("No signer available"));
        };

        let submission_proxy = if let Some(proxy) = &builder_settings.submission_proxy {
            let Some(proxy) = self.args.chain_spec.get_submission_proxy(proxy) else {
                return Err(anyhow::anyhow!(
                    "Proxy {} is not in the known submission proxies",
                    proxy
                ));
            };
            Some(proxy)
        } else {
            None
        };

        let sender_eoa = signer.address();
        let proposer_settings = bundle_proposer::Settings {
            chain_spec: self.args.chain_spec.clone(),
            target_bundle_gas: self.args.target_bundle_gas,
            max_bundle_gas: self.args.max_bundle_gas,
            sender_eoa,
            da_gas_tracking_enabled: self.args.da_gas_tracking_enabled,
            max_expected_storage_slots: self.args.max_expected_storage_slots,
            verification_gas_limit_efficiency_reject_threshold: self
                .args
                .verification_gas_limit_efficiency_reject_threshold,
            submission_proxy: submission_proxy.cloned(),
        };

        let transaction_sender = self.args.sender_args.clone().into_sender(
            &self.args.rpc_url,
            self.args.provider_client_timeout_seconds,
        )?;

        let tracker_settings = transaction_tracker::Settings {
            replacement_fee_percent_increase: self.args.replacement_fee_percent_increase,
        };

        let transaction_tracker = TransactionTrackerImpl::new(
            ep_providers.evm().clone(),
            transaction_sender,
            signer,
            tracker_settings,
            builder_settings.tag(ep_providers.entry_point().address(), &sender_eoa),
        )
        .await?;

        let sender_settings = bundle_sender::Settings {
            max_replacement_underpriced_blocks: self.args.max_replacement_underpriced_blocks,
            max_cancellation_fee_increases: self.args.max_cancellation_fee_increases,
            max_blocks_to_wait_for_mine: self.args.max_blocks_to_wait_for_mine,
        };

        let proposer = BundleProposerImpl::new(
            builder_settings.tag(ep_providers.entry_point().address(), &sender_eoa),
            ep_providers.clone(),
            BundleProposerProviders::new(simulator),
            proposer_settings,
            self.event_sender.clone(),
        );

        let builder = BundleSenderImpl::new(
            builder_settings.clone(),
            send_bundle_rx,
            self.args.chain_spec.clone(),
            sender_eoa,
            submission_proxy.cloned(),
            proposer,
            ep_providers.clone(),
            transaction_tracker,
            assigner,
            self.pool.clone(),
            sender_settings,
            self.event_sender.clone(),
        );

        // Spawn each sender as its own independent task
        let ts = task_spawner.clone();
        task_spawner.spawn_critical("bundle sender", builder.send_bundles_in_loop(ts));

        Ok(send_bundle_tx)
    }
}
