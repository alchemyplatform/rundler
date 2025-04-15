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

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use alloy_primitives::{Address, B256};
use rundler_provider::Providers as ProvidersT;
use rundler_signer::{SignerManager, SigningScheme};
use rundler_sim::{
    gas::{self, FeeEstimatorImpl},
    MempoolConfig, PriorityFeeMode, SimulationSettings,
};
use rundler_task::TaskSpawnerExt;
use rundler_types::{chain::ChainSpec, pool::Pool as PoolT, EntryPointVersion};
use rundler_utils::emit::WithEntryPoint;
use tokio::sync::broadcast;
use tracing::info;

use crate::{
    bundle_proposer::Settings as BundleProposerSettings,
    bundle_sender::Settings as BundleSenderSettings,
    emit::BuilderEvent,
    factory::BundleSenderTaskFactory,
    sender::TransactionSenderArgs,
    server::{self, LocalBuilderBuilder},
    transaction_tracker,
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
    /// Whether to automatically fund signers
    pub auto_fund: bool,
    /// Maximum bundle size in number of operations
    pub max_bundle_size: u64,
    /// Target bundle size in gas
    pub target_bundle_gas: u128,
    /// Maximum bundle size in gas
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
    /// Types of builders to run
    pub builders: Vec<BuilderSettings>,
    /// Enable DA tracking
    pub da_gas_tracking_enabled: bool,
    /// Provider client timeout
    pub provider_client_timeout_seconds: u64,
    /// Maximum number of expected storage slots in a bundle
    pub max_expected_storage_slots: usize,
}
/// Builder settings
#[derive(Debug, Clone)]
pub struct BuilderSettings {
    /// Entry point address
    pub address: Address,
    /// Entry point version
    pub version: EntryPointVersion,
    /// Mempool configs
    pub mempool_configs: HashMap<B256, MempoolConfig>,
    /// Optional submission proxy to use for this builder
    pub submission_proxy: Option<Address>,
    /// Optional filter id to apply to this builder
    pub filter_id: Option<String>,
}

impl BuilderSettings {
    /// Unique string tag for this builder
    pub fn tag(&self, entry_point_address: &Address, signer_address: &Address) -> String {
        format!(
            "{}:{}:{}",
            entry_point_address,
            signer_address,
            self.filter_id.as_ref().map_or("any", |v| v),
        )
    }

    pub fn tag_from_ep_version(
        &self,
        chain_spec: &ChainSpec,
        ep_version: EntryPointVersion,
        signer_address: &Address,
    ) -> String {
        match ep_version {
            EntryPointVersion::V0_6 => {
                self.tag(&chain_spec.entry_point_address_v0_6, signer_address)
            }
            EntryPointVersion::V0_7 => {
                self.tag(&chain_spec.entry_point_address_v0_7, signer_address)
            }
            EntryPointVersion::Unspecified => panic!("entry point version is unspecified"),
        }
    }
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
    pub async fn spawn<T: TaskSpawnerExt>(self, task_spawner: T) -> anyhow::Result<()> {
        let (block_broadcaster, _) = broadcast::channel(100_000);

        let sender_settings = BundleSenderSettings {
            max_replacement_underpriced_blocks: self.args.max_replacement_underpriced_blocks,
            max_cancellation_fee_increases: self.args.max_cancellation_fee_increases,
            max_blocks_to_wait_for_mine: self.args.max_blocks_to_wait_for_mine,
        };

        let proposer_settings = BundleProposerSettings {
            max_bundle_size: self.args.max_bundle_size,
            target_bundle_gas: self.args.target_bundle_gas,
            max_bundle_gas: self.args.max_bundle_gas,
            chain_spec: self.args.chain_spec.clone(),
            priority_fee_mode: self.args.priority_fee_mode,
            da_gas_tracking_enabled: self.args.da_gas_tracking_enabled,
            max_expected_storage_slots: self.args.max_expected_storage_slots,
        };

        let fee_oracle = gas::get_fee_oracle(&self.args.chain_spec, self.providers.evm().clone());
        let fee_estimator = FeeEstimatorImpl::new(
            self.providers.evm().clone(),
            fee_oracle,
            proposer_settings.priority_fee_mode,
            self.args.bundle_base_fee_overhead_percent,
            self.args.bundle_priority_fee_overhead_percent,
        );

        // TODO
        let factory = BundleSenderTaskFactory {
            chain_spec: self.args.chain_spec.clone(),
            sender_settings,
            proposer_settings,
            sim_settings: self.args.sim_settings.clone(),
            tracker_settings: transaction_tracker::Settings {
                replacement_fee_percent_increase: self.args.replacement_fee_percent_increase,
            },
            unsafe_mode: self.args.unsafe_mode,
            providers: self.providers.clone(),
            fee_estimator: Arc::new(fee_estimator),
            pool: self.pool.clone(),
            sender_args: self.args.sender_args.clone(),
            event_sender: self.event_sender.clone(),
            provider_client_timeout_seconds: self.args.provider_client_timeout_seconds,
            rpc_url: self.args.rpc_url.clone(),
        };

        let builder_handle = self.builder_builder.get_handle();

        task_spawner.spawn_critical_with_graceful_shutdown_signal(
            "local builder server",
            |shutdown| {
                self.builder_builder.run(
                    Box::new(task_spawner.clone()),
                    self.args.chain_spec.clone(),
                    vec![self.args.chain_spec.entry_point_address_v0_6],
                    Box::new(factory),
                    self.args.builders.clone(),
                    block_broadcaster,
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
}
