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
use futures_util::StreamExt;
use rundler_provider::{
    AlloyNetworkConfig, FeeEstimator, Providers as ProvidersT, ProvidersWithEntryPointT,
};
use rundler_signer::{
    SignerManager, SigningScheme,
    mapping::{SignerCounts, entry_point_name},
};
use rundler_sim::{
    MempoolConfig, SimulationSettings,
    simulation::{self, UnsafeSimulator},
};
use rundler_task::TaskSpawnerExt;
use rundler_types::{
    EntryPointAbiVersion, EntryPointVersion,
    chain::ChainSpec,
    pool::{NewHead, Pool as PoolT},
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
    delegation_sender::{DelegationSenderTask, Settings as DelegationSettings},
    emit::BuilderEvent,
    sender::{ProviderEventSignal, TransactionSenderArgs},
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
    /// How bundle workers (and their signers) are laid out
    pub worker_layout: WorkerLayout,
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
    /// Initial delay a builder waits after a rate-limited submission, doubling with
    /// each consecutive rate-limited attempt
    pub rate_limit_backoff_initial: Duration,
    /// Maximum delay a builder waits between rate-limited submissions
    pub rate_limit_backoff_max: Duration,
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

/// How bundle workers are laid out across entry points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerLayout {
    /// Legacy layout: `num_signers` workers shared by all entry points. A worker leases any
    /// free signer and then picks an entry point.
    Shared {
        /// Number of workers (and signers)
        num_signers: u64,
    },
    /// Mapping layout: `counts[ep]` workers per entry point. Each worker leases only that
    /// entry point's signers and only receives that entry point's work.
    PerEntryPoint {
        /// Workers per entry point
        counts: SignerCounts,
    },
}

impl WorkerLayout {
    /// Total number of workers (and signers needed at startup).
    pub fn total(&self) -> usize {
        match self {
            WorkerLayout::Shared { num_signers } => *num_signers as usize,
            WorkerLayout::PerEntryPoint { counts } => counts.total(),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            WorkerLayout::Shared { .. } => "legacy",
            WorkerLayout::PerEntryPoint { .. } => "mapping",
        }
    }
}

/// A group of workers sharing one assigner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkerGroup {
    /// The entry point all workers in the group serve, or `None` for the legacy shared group
    pub(crate) entry_point: Option<EntryPointVersion>,
    /// The (entry point, filter id) combinations the group's assigner serves
    pub(crate) infos: Vec<EntrypointInfo>,
    /// Number of workers in the group
    pub(crate) num_workers: usize,
}

/// Split the configured entry points into worker groups.
///
/// `entry_points` lists, for each enabled entry point, the assigner entries built for it.
pub(crate) fn plan_workers(
    entry_points: &[(EntryPointVersion, Vec<EntrypointInfo>)],
    layout: &WorkerLayout,
) -> anyhow::Result<Vec<WorkerGroup>> {
    match layout {
        WorkerLayout::Shared { num_signers } => Ok(vec![WorkerGroup {
            entry_point: None,
            infos: entry_points
                .iter()
                .flat_map(|(_, infos)| infos.iter().cloned())
                .collect(),
            num_workers: *num_signers as usize,
        }]),
        WorkerLayout::PerEntryPoint { counts } => {
            for (entry_point, _) in counts.entries() {
                if !entry_points.iter().any(|(ep, _)| ep == entry_point) {
                    anyhow::bail!(
                        "signer count set for entry point {}, which is not enabled",
                        entry_point_name(*entry_point)
                    );
                }
            }
            entry_points
                .iter()
                .map(|(entry_point, infos)| {
                    let num_workers = counts.get(*entry_point).with_context(|| {
                        format!(
                            "entry point {} is enabled but has no signer count",
                            entry_point_name(*entry_point)
                        )
                    })?;
                    Ok(WorkerGroup {
                        entry_point: Some(*entry_point),
                        infos: infos.clone(),
                        num_workers,
                    })
                })
                .collect()
        }
    }
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

        let num_required_signers = self.args.worker_layout.total();
        metrics::gauge!("builder_signer_layout", "layout" => self.args.worker_layout.name())
            .set(1.0);

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
        let mut infos_by_entry_point: Vec<(EntryPointVersion, Vec<EntrypointInfo>)> = vec![];
        let mut proposers: HashMap<ProposerKey, Box<dyn BundleProposerT>> = HashMap::new();
        for ep in &self.args.entry_points {
            let mut entrypoint_infos: Vec<EntrypointInfo> = vec![];
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
            infos_by_entry_point.push((ep.version, entrypoint_infos));
        }

        // One assigner per worker group: a single shared group in the legacy layout, one
        // group per entry point in the mapping layout. In the mapping layout sender locks are
        // per entry point, so ops from the same sender on two entry points are not serialized.
        let groups = plan_workers(&infos_by_entry_point, &self.args.worker_layout)?;
        let groups: Vec<(WorkerGroup, Arc<Assigner>)> = groups
            .into_iter()
            .map(|group| {
                let mut assigner = Assigner::new(
                    Box::new(self.pool.clone()),
                    group.infos.clone(),
                    group.num_workers,
                    self.args.assigner_max_ops_per_request,
                    self.args.max_bundle_size,
                    self.args.assigner_starvation_ratio,
                );
                if let Some(entry_point) = group.entry_point {
                    assigner = assigner.with_metrics_entry_point(entry_point);
                    info!(
                        "Builder workers for entry point {}: {}",
                        entry_point_name(entry_point),
                        group.num_workers
                    );
                }
                (group, Arc::new(assigner))
            })
            .collect();

        let proposers = Arc::new(proposers);
        let supported_entry_points: Vec<_> =
            self.args.entry_points.iter().map(|ep| ep.address).collect();

        // Create the bundle senders for each worker group
        let (actions, heads_tx) = self
            .create_builders(
                &task_spawner,
                &self.signer_manager,
                &groups,
                proposers.clone(),
            )
            .await?;
        bundle_sender_actions.extend(actions);

        let builder_handle = self.builder_builder.get_handle();

        let (delegation_task, delegation_handle) = DelegationSenderTask::new(
            self.signer_manager.clone(),
            self.providers.evm().clone(),
            self.providers.fee_estimator().clone(),
            DelegationSettings {
                max_blocks_to_wait_for_mine: self.args.max_blocks_to_wait_for_mine,
                max_fee_bumps: self.args.max_cancellation_fee_increases,
                fee_bump_percent: self.args.replacement_fee_percent_increase,
                max_delegation_gas: self.args.max_bundle_gas as u64,
            },
            heads_tx.clone(),
        );
        task_spawner
            .spawn_critical_with_graceful_shutdown_signal("delegation sender", |shutdown| {
                delegation_task.run(shutdown)
            });
        task_spawner.spawn_critical_with_graceful_shutdown_signal(
            "local builder server",
            |shutdown| {
                self.builder_builder.run(
                    bundle_sender_actions,
                    supported_entry_points,
                    heads_tx.subscribe(),
                    delegation_handle,
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

    /// Create the bundle senders: `num_workers` per worker group, each using its group's
    /// assigner. In the legacy layout a single group handles all entrypoints.
    async fn create_builders<T>(
        &self,
        task_spawner: &T,
        signer_manager: &Arc<dyn SignerManager>,
        groups: &[(WorkerGroup, Arc<Assigner>)],
        proposers: Arc<HashMap<ProposerKey, Box<dyn BundleProposerT>>>,
    ) -> anyhow::Result<(
        Vec<mpsc::Sender<BundleSenderAction>>,
        broadcast::Sender<Arc<NewHead>>,
    )>
    where
        T: TaskSpawnerExt,
    {
        // One pool subscription covers all signer addresses. A single broadcast channel
        // fans out new-head events to every bundle sender, keeping pool-side work O(N)
        // instead of O(N²) (one subscription per sender × N addresses each).
        let all_signer_addresses = signer_manager.addresses();
        let shared_heads = self
            .pool
            .subscribe_new_heads(all_signer_addresses)
            .await
            .context("failed to subscribe to new heads for bundle senders")?;

        let (heads_tx, _) = broadcast::channel::<Arc<NewHead>>(16);
        let heads_tx_fwd = heads_tx.clone();
        task_spawner.spawn_critical(
            "new-heads-fanout",
            Box::pin(async move {
                let mut stream = shared_heads;
                while let Some(head) = stream.next().await {
                    tracing::debug!("new-heads-fanout: block {}", head.block_number);
                    if heads_tx_fwd.send(Arc::new(head)).is_err() {
                        // All receivers dropped — senders have shut down.
                        break;
                    }
                }
                tracing::error!("shared new-heads stream closed (shutdown)");
            }),
        );

        // All builders submit through the same route (sender_args), so they
        // share one provider-health signal.
        let provider_event_signal = Arc::new(ProviderEventSignal::default());

        let mut bundle_sender_actions = vec![];
        for (group, assigner) in groups {
            for i in 0..group.num_workers {
                // Tag identifies this sender slot since the signing address is dynamic.
                let builder_tag = match group.entry_point {
                    Some(entry_point) => format!("sender_{}_{i}", entry_point_name(entry_point)),
                    None => format!("sender_{i}"),
                };
                let bundle_sender_action = self
                    .create_bundle_builder(
                        task_spawner,
                        signer_manager,
                        assigner.clone(),
                        proposers.clone(),
                        builder_tag,
                        group.entry_point,
                        heads_tx.subscribe(),
                        provider_event_signal.clone(),
                    )
                    .await?;
                bundle_sender_actions.push(bundle_sender_action);
            }
        }
        Ok((bundle_sender_actions, heads_tx))
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_bundle_builder<T>(
        &self,
        task_spawner: &T,
        signer_manager: &Arc<dyn SignerManager>,
        assigner: Arc<Assigner>,
        proposers: Arc<HashMap<ProposerKey, Box<dyn BundleProposerT>>>,
        builder_tag: String,
        entry_point: Option<EntryPointVersion>,
        heads_rx: broadcast::Receiver<Arc<NewHead>>,
        provider_event_signal: Arc<ProviderEventSignal>,
    ) -> anyhow::Result<mpsc::Sender<BundleSenderAction>>
    where
        T: TaskSpawnerExt,
    {
        let (send_bundle_tx, send_bundle_rx) = mpsc::channel(1);

        let transaction_sender = self
            .args
            .sender_args
            .clone()
            .into_sender(&self.args.alloy_network_config)?;

        let tracker_settings = transaction_tracker::Settings {
            replacement_fee_percent_increase: self.args.replacement_fee_percent_increase,
        };

        let transaction_tracker = TransactionTrackerImpl::new(
            self.providers.evm().clone(),
            transaction_sender,
            signer_manager.clone(),
            tracker_settings,
            builder_tag.clone(),
            entry_point,
        );

        let sender_settings = bundle_sender::Settings {
            max_replacement_underpriced_blocks: self.args.max_replacement_underpriced_blocks,
            max_cancellation_fee_increases: self.args.max_cancellation_fee_increases,
            max_blocks_to_wait_for_mine: self.args.max_blocks_to_wait_for_mine,
            rate_limit_backoff_initial: self.args.rate_limit_backoff_initial,
            rate_limit_backoff_max: self.args.rate_limit_backoff_max,
        };

        let fee_estimator: Box<dyn FeeEstimator> = Box::new(self.providers.fee_estimator().clone());

        let builder = BundleSenderImpl::new(
            builder_tag,
            send_bundle_rx,
            self.args.chain_spec.clone(),
            heads_rx,
            transaction_tracker,
            fee_estimator,
            assigner,
            proposers,
            self.pool.clone(),
            sender_settings,
            self.event_sender.clone(),
            provider_event_signal,
            entry_point,
        );

        // Spawn each sender as its own independent task
        let ts = task_spawner.clone();
        task_spawner.spawn_critical("bundle sender", builder.send_bundles_in_loop(ts));

        Ok(send_bundle_tx)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;

    use super::*;

    const EP_6: Address = address!("0000000000000000000000000000000000000006");
    const EP_7: Address = address!("0000000000000000000000000000000000000007");

    fn info(address: Address, filter_id: Option<&str>) -> EntrypointInfo {
        EntrypointInfo {
            address,
            filter_id: filter_id.map(str::to_string),
        }
    }

    /// v0.6 with one builder config, v0.7 with a default and a filtered (PBH-style) config.
    fn entry_points() -> Vec<(EntryPointVersion, Vec<EntrypointInfo>)> {
        vec![
            (EntryPointVersion::V0_6, vec![info(EP_6, None)]),
            (
                EntryPointVersion::V0_7,
                vec![info(EP_7, None), info(EP_7, Some("pbh-aggregator"))],
            ),
        ]
    }

    fn per_entry_point(counts: &str) -> WorkerLayout {
        WorkerLayout::PerEntryPoint {
            counts: counts.parse().unwrap(),
        }
    }

    #[test]
    fn shared_layout_is_one_group_for_all_entry_points() {
        let groups =
            plan_workers(&entry_points(), &WorkerLayout::Shared { num_signers: 32 }).unwrap();
        assert_eq!(
            groups,
            vec![WorkerGroup {
                entry_point: None,
                infos: vec![
                    info(EP_6, None),
                    info(EP_7, None),
                    info(EP_7, Some("pbh-aggregator")),
                ],
                num_workers: 32,
            }]
        );
        assert_eq!(WorkerLayout::Shared { num_signers: 32 }.total(), 32);
    }

    #[test]
    fn per_entry_point_layout_splits_groups_and_keeps_filters() {
        let layout = per_entry_point("v0.7=20,v0.6=6");
        let groups = plan_workers(&entry_points(), &layout).unwrap();
        assert_eq!(
            groups,
            vec![
                WorkerGroup {
                    entry_point: Some(EntryPointVersion::V0_6),
                    infos: vec![info(EP_6, None)],
                    num_workers: 6,
                },
                WorkerGroup {
                    entry_point: Some(EntryPointVersion::V0_7),
                    infos: vec![info(EP_7, None), info(EP_7, Some("pbh-aggregator"))],
                    num_workers: 20,
                },
            ]
        );
        assert_eq!(layout.total(), 26);
    }

    #[test]
    fn per_entry_point_layout_needs_a_count_for_every_entry_point() {
        let err = plan_workers(&entry_points(), &per_entry_point("v0.7=20")).unwrap_err();
        assert!(
            err.to_string()
                .contains("v0.6 is enabled but has no signer count")
        );
    }

    #[test]
    fn per_entry_point_layout_rejects_counts_for_disabled_entry_points() {
        let err =
            plan_workers(&entry_points(), &per_entry_point("v0.6=1,v0.7=1,v0.8=1")).unwrap_err();
        assert!(err.to_string().contains("v0.8, which is not enabled"));
    }
}
