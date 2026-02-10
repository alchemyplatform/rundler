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
use rundler_provider::{
    AlloyNetworkConfig, FeeEstimator, Providers as ProvidersT, ProvidersWithEntryPointT,
};
use rundler_signer::{SignerManager, SigningScheme};
use rundler_sim::{
    MempoolConfig, SimulationSettings,
    simulation::{self, UnsafeSimulator},
};
use rundler_task::TaskSpawnerExt;
use rundler_types::{
    EntryPointAbiVersion, EntryPointVersion, chain::ChainSpec, pool::Pool as PoolT,
    proxy::SubmissionProxy,
};
use rundler_utils::emit::WithEntryPoint;
use tokio::sync::{broadcast, mpsc};
use tracing::info;

use crate::{
    ProposerKey,
    assigner::{Assigner, EntrypointInfo},
    bundle_proposer::{self, BundleProposerImpl, BundleProposerProviders, BundleProposerT},
    bundle_sender::{self, BundleSender, BundleSenderAction, BundleSenderImpl},
    emit::BuilderEvent,
    sender::TransactionSenderArgs,
    server::{self, LocalBuilderBuilder},
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
    /// Signing scheme to use
    pub signing_scheme: SigningScheme,
    /// Number of signers (workers) to use
    pub num_signers: u64,
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
    /// Alloy network config
    pub alloy_network_config: AlloyNetworkConfig,
    /// Maximum number of expected storage slots in a bundle
    pub max_expected_storage_slots: usize,
    /// Rejects user operations with a verification gas limit efficiency below this threshold.
    pub verification_gas_limit_efficiency_reject_threshold: f64,
    /// Maximum ops requested from mempool
    pub assigner_max_ops_per_request: u64,
    /// Starvation multiplier for the assigner (applied to `num_signers` before force-selecting a starved entrypoint)
    pub assigner_starvation_ratio: f64,
}

/// Builder settings
#[derive(Debug, Clone)]
pub struct BuilderSettings {
    /// Optional submission proxy to use for this builder
    pub submission_proxy: Option<Address>,
    /// Optional filter id to apply to this builder
    pub filter_id: Option<String>,
}

fn proposer_tag(
    entry_point_address: &Address,
    filter_id: Option<&str>,
    submission_proxy: Option<Address>,
) -> String {
    let filter = filter_id.unwrap_or("any");
    let proxy = submission_proxy.map_or_else(|| "none".to_string(), |addr| addr.to_string());
    format!("proposer:{entry_point_address}:{filter}:{proxy}")
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
    /// Builder configurations (filter_id, submission_proxy combinations)
    /// Each represents a "virtual entrypoint" that workers can build for
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

        let num_required_signers = self.args.num_signers as usize;

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

        // Build entrypoint info (for assigner) and registry (for proposers) in a single pass.
        // Each (address, filter_id) combination is a separate "virtual entrypoint".
        let mut entrypoint_infos: Vec<EntrypointInfo> = vec![];
        let mut proposers: HashMap<ProposerKey, Box<dyn BundleProposerT>> = HashMap::new();
        for ep in &self.args.entry_points {
            // Enforce unique filter_ids per entrypoint
            let mut seen_filter_ids: HashSet<Option<String>> = HashSet::new();
            for builder in &ep.builders {
                if !seen_filter_ids.insert(builder.filter_id.clone()) {
                    return Err(anyhow::anyhow!(
                        "Entry point {:?} has duplicate builder config for filter_id {:?}",
                        ep.address,
                        builder.filter_id
                    ));
                }
            }

            // Create an assigner entry and proposer for each builder configuration
            for builder in &ep.builders {
                // Submission proxies are not supported for v0.9+ entrypoints
                if builder.submission_proxy.is_some() && ep.version >= EntryPointVersion::V0_9 {
                    return Err(anyhow::anyhow!(
                        "Submission proxies are not supported for entry point v0.9+ ({:?})",
                        ep.address
                    ));
                }

                let filter_id = builder.filter_id.clone();
                let proposer_key = (ep.address, filter_id.clone());

                entrypoint_infos.push(EntrypointInfo {
                    address: ep.address,
                    filter_id,
                });

                // Look up the submission proxy from chain_spec if configured
                let submission_proxy = builder
                        .submission_proxy
                        .map(|proxy_address| {
                            self.args
                                .chain_spec
                                .get_submission_proxy(&proxy_address)
                                .cloned()
                                .with_context(|| {
                                    format!(
                                        "Submission proxy {:?} configured for entry point {:?} (filter_id {:?}) was not found in chain_spec registry",
                                        proxy_address, ep.address, builder.filter_id
                                    )
                                })
                        })
                        .transpose()?;
                let builder_tag = proposer_tag(
                    &ep.address,
                    builder.filter_id.as_deref(),
                    builder.submission_proxy,
                );

                let proposer = self
                    .create_proposer_for_entrypoint(ep, submission_proxy, builder_tag)
                    .await?;
                proposers.insert(proposer_key, proposer);
                info!(
                    "Registered proposer for entrypoint {:?} (version {:?}, filter_id: {:?}, proxy: {:?})",
                    ep.address, ep.version, builder.filter_id, builder.submission_proxy
                );
            }
        }

        let assigner = Arc::new(Assigner::new(
            Box::new(self.pool.clone()),
            entrypoint_infos,
            self.args.num_signers as usize,
            self.args.assigner_max_ops_per_request,
            self.args.max_bundle_size,
            self.args.assigner_starvation_ratio,
        ));

        let proposers = Arc::new(proposers);
        let supported_entry_points: Vec<_> =
            self.args.entry_points.iter().map(|ep| ep.address).collect();

        // Create one bundle sender per signer - each handles all entrypoints via the registry
        let actions = self
            .create_builders(
                &task_spawner,
                &self.signer_manager,
                assigner.clone(),
                proposers.clone(),
            )
            .await?;
        bundle_sender_actions.extend(actions);

        let builder_handle = self.builder_builder.get_handle();

        task_spawner.spawn_critical_with_graceful_shutdown_signal(
            "local builder server",
            |shutdown| {
                self.builder_builder
                    .run(bundle_sender_actions, supported_entry_points, shutdown)
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

    /// Create a proposer for the given entrypoint and add it to the registry.
    /// The submission_proxy is used when building transactions through a proxy contract.
    async fn create_proposer_for_entrypoint(
        &self,
        ep: &EntryPointBuilderSettings,
        submission_proxy: Option<Arc<dyn SubmissionProxy>>,
        builder_tag: String,
    ) -> anyhow::Result<Box<dyn BundleProposerT>> {
        let proposer_settings = bundle_proposer::Settings {
            chain_spec: self.args.chain_spec.clone(),
            target_bundle_gas: self.args.target_bundle_gas,
            max_bundle_gas: self.args.max_bundle_gas,
            da_gas_tracking_enabled: self.args.da_gas_tracking_enabled,
            max_expected_storage_slots: self.args.max_expected_storage_slots,
            verification_gas_limit_efficiency_reject_threshold: self
                .args
                .verification_gas_limit_efficiency_reject_threshold,
            submission_proxy,
        };

        match ep.version.abi_version() {
            EntryPointAbiVersion::V0_6 => {
                let ep_providers = self
                    .providers
                    .ep_v0_6_providers()
                    .clone()
                    .context("entry point v0.6 not supplied")?;

                if self.args.unsafe_mode {
                    let simulator = UnsafeSimulator::new(
                        ep_providers.entry_point().clone(),
                        self.args.sim_settings.clone(),
                        &ep.mempool_configs,
                    );
                    let proposer = BundleProposerImpl::new(
                        builder_tag,
                        ep_providers,
                        BundleProposerProviders::new(simulator),
                        proposer_settings,
                        self.event_sender.clone(),
                    );
                    Ok(Box::new(proposer))
                } else {
                    let simulator = simulation::new_v0_6_simulator(
                        ep_providers.evm().clone(),
                        ep_providers.entry_point().clone(),
                        self.args.sim_settings.clone(),
                        ep.mempool_configs.clone(),
                    );
                    let proposer = BundleProposerImpl::new(
                        builder_tag,
                        ep_providers,
                        BundleProposerProviders::new(simulator),
                        proposer_settings,
                        self.event_sender.clone(),
                    );
                    Ok(Box::new(proposer))
                }
            }
            EntryPointAbiVersion::V0_7 => {
                let ep_providers = self
                    .providers
                    .ep_v0_7_providers(ep.version)
                    .clone()
                    .context(format!(
                        "entry point v0.7 abi providers not supplied for version: {:?}",
                        ep.version
                    ))?;

                if self.args.unsafe_mode {
                    let simulator = UnsafeSimulator::new(
                        ep_providers.entry_point().clone(),
                        self.args.sim_settings.clone(),
                        &ep.mempool_configs,
                    );
                    let proposer = BundleProposerImpl::new(
                        builder_tag,
                        ep_providers,
                        BundleProposerProviders::new(simulator),
                        proposer_settings,
                        self.event_sender.clone(),
                    );
                    Ok(Box::new(proposer))
                } else {
                    let simulator = simulation::new_v0_7_simulator(
                        ep_providers.evm().clone(),
                        ep_providers.entry_point().clone(),
                        self.args.sim_settings.clone(),
                        ep.mempool_configs.clone(),
                    );
                    let proposer = BundleProposerImpl::new(
                        builder_tag,
                        ep_providers,
                        BundleProposerProviders::new(simulator),
                        proposer_settings,
                        self.event_sender.clone(),
                    );
                    Ok(Box::new(proposer))
                }
            }
        }
    }

    /// Create one bundle sender per signer. Each sender handles all entrypoints
    /// via the shared proposers map.
    async fn create_builders<T>(
        &self,
        task_spawner: &T,
        signer_manager: &Arc<dyn SignerManager>,
        assigner: Arc<Assigner>,
        proposers: Arc<HashMap<ProposerKey, Box<dyn BundleProposerT>>>,
    ) -> anyhow::Result<Vec<mpsc::Sender<BundleSenderAction>>>
    where
        T: TaskSpawnerExt,
    {
        let mut bundle_sender_actions = vec![];

        for _ in 0..self.args.num_signers {
            let bundle_sender_action = self
                .create_bundle_builder(
                    task_spawner,
                    signer_manager,
                    assigner.clone(),
                    proposers.clone(),
                )
                .await?;
            bundle_sender_actions.push(bundle_sender_action);
        }
        Ok(bundle_sender_actions)
    }

    async fn create_bundle_builder<T>(
        &self,
        task_spawner: &T,
        signer_manager: &Arc<dyn SignerManager>,
        assigner: Arc<Assigner>,
        proposers: Arc<HashMap<ProposerKey, Box<dyn BundleProposerT>>>,
    ) -> anyhow::Result<mpsc::Sender<BundleSenderAction>>
    where
        T: TaskSpawnerExt,
    {
        let (send_bundle_tx, send_bundle_rx) = mpsc::channel(1);

        let Some(signer) = signer_manager.lease_signer() else {
            return Err(anyhow::anyhow!("No signer available"));
        };

        let sender_eoa = signer.address();

        let transaction_sender = self
            .args
            .sender_args
            .clone()
            .into_sender(&self.args.alloy_network_config)?;

        let tracker_settings = transaction_tracker::Settings {
            replacement_fee_percent_increase: self.args.replacement_fee_percent_increase,
        };

        // Builder tag now uses just the sender address since workers handle all entrypoints
        let builder_tag = format!("0x{sender_eoa:x}");

        let transaction_tracker = TransactionTrackerImpl::new(
            self.providers.evm().clone(),
            transaction_sender,
            signer,
            tracker_settings,
            builder_tag.clone(),
        )
        .await?;

        let sender_settings = bundle_sender::Settings {
            max_replacement_underpriced_blocks: self.args.max_replacement_underpriced_blocks,
            max_cancellation_fee_increases: self.args.max_cancellation_fee_increases,
            max_blocks_to_wait_for_mine: self.args.max_blocks_to_wait_for_mine,
        };

        let fee_estimator: Box<dyn FeeEstimator> = Box::new(self.providers.fee_estimator().clone());

        let builder = BundleSenderImpl::new(
            builder_tag,
            send_bundle_rx,
            self.args.chain_spec.clone(),
            sender_eoa,
            transaction_tracker,
            fee_estimator,
            assigner,
            proposers,
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
