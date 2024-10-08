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
use futures::FutureExt;
use rundler_provider::{EntryPointProvider, EvmProvider};
use rundler_sim::{
    gas::{self, FeeEstimatorImpl},
    simulation::{self, UnsafeSimulator},
    PrecheckerImpl, Simulator,
};
use rundler_task::TaskSpawnerExt;
use rundler_types::{
    chain::ChainSpec, v0_6::UserOperation as UserOperationV0_6,
    v0_7::UserOperation as UserOperationV0_7, EntryPointVersion, UserOperation,
    UserOperationVariant,
};
use rundler_utils::emit::WithEntryPoint;
use tokio::sync::broadcast;

use super::mempool::PoolConfig;
use crate::{
    chain::{self, Chain},
    emit::OpPoolEvent,
    mempool::{
        AddressReputation, Mempool, PaymasterConfig, PaymasterTracker, ReputationParams, UoPool,
    },
    server::{self, LocalPoolBuilder},
};

/// Arguments for the pool task.
#[derive(Debug)]
pub struct Args {
    /// Chain specification.
    pub chain_spec: ChainSpec,
    /// True if using unsafe mode.
    pub unsafe_mode: bool,
    /// HTTP URL for the full node.
    pub http_url: String,
    /// Interval to poll the chain for updates.
    pub chain_poll_interval: Duration,
    /// Number of times to retry a block sync at the `chain_poll_interval` before abandoning
    pub chain_max_sync_retries: u64,
    /// Pool configurations.
    pub pool_configs: Vec<PoolConfig>,
    /// Address to bind the remote mempool server to, if any.
    /// If not provided, a server will not be started.
    pub remote_address: Option<SocketAddr>,
    /// Channel capacity for the chain update channel.
    pub chain_update_channel_capacity: usize,
}

/// Mempool task.
#[derive(Debug)]
pub struct PoolTask<P, E06, E07> {
    args: Args,
    event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
    pool_builder: LocalPoolBuilder,
    provider: P,
    ep_06: Option<E06>,
    ep_07: Option<E07>,
}

impl<P, E06, E07> PoolTask<P, E06, E07> {
    /// Create a new pool task.
    pub fn new(
        args: Args,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        pool_builder: LocalPoolBuilder,
        provider: P,
        ep_06: Option<E06>,
        ep_07: Option<E07>,
    ) -> Self {
        Self {
            args,
            event_sender,
            pool_builder,
            provider,
            ep_06,
            ep_07,
        }
    }
}

impl<P, E06, E07> PoolTask<P, E06, E07>
where
    P: EvmProvider + Clone + 'static,
    E06: EntryPointProvider<UserOperationV0_6> + Clone + 'static,
    E07: EntryPointProvider<UserOperationV0_7> + Clone + 'static,
{
    /// Spawns the mempool task on the given task spawner.
    pub async fn spawn<T: TaskSpawnerExt>(self, task_spawner: T) -> anyhow::Result<()> {
        let chain_id = self.args.chain_spec.id;
        tracing::info!("Chain id: {chain_id}");
        tracing::info!("Http url: {:?}", self.args.http_url);

        // create chain
        let chain_settings = chain::Settings {
            history_size: self.args.chain_spec.chain_history_size,
            poll_interval: self.args.chain_poll_interval,
            max_sync_retries: self.args.chain_max_sync_retries,
            entry_point_addresses: self
                .args
                .pool_configs
                .iter()
                .map(|config| (config.entry_point, config.entry_point_version))
                .collect(),
        };

        let chain = Chain::new(self.provider.clone(), chain_settings);
        let (update_sender, _) = broadcast::channel(self.args.chain_update_channel_capacity);

        task_spawner.spawn_critical_with_graceful_shutdown_signal("chain watcher", |shutdown| {
            chain.watch(update_sender.clone(), shutdown)
        });

        // create mempools
        let mut mempools = HashMap::new();
        for pool_config in &self.args.pool_configs {
            match pool_config.entry_point_version {
                EntryPointVersion::V0_6 => {
                    let pool = self
                        .create_mempool_v0_6(
                            &task_spawner,
                            self.args.chain_spec.clone(),
                            pool_config,
                            self.args.unsafe_mode,
                            self.event_sender.clone(),
                        )
                        .context("should have created mempool")?;

                    mempools.insert(pool_config.entry_point, pool);
                }
                EntryPointVersion::V0_7 => {
                    let pool = self
                        .create_mempool_v0_7(
                            &task_spawner,
                            self.args.chain_spec.clone(),
                            pool_config,
                            self.args.unsafe_mode,
                            self.event_sender.clone(),
                        )
                        .context("should have created mempool")?;

                    mempools.insert(pool_config.entry_point, pool);
                }
                EntryPointVersion::Unspecified => {
                    bail!("Unsupported entry point version");
                }
            }
        }

        let pool_handle = self.pool_builder.get_handle();

        let ts_box = Box::new(task_spawner.clone());
        task_spawner.spawn_critical_with_graceful_shutdown_signal(
            "local pool server",
            |shutdown| {
                self.pool_builder
                    .run(ts_box, mempools, update_sender.subscribe(), shutdown)
            },
        );

        if let Some(addr) = self.args.remote_address {
            let ts_box = Box::new(task_spawner.clone());
            task_spawner.spawn_critical_with_graceful_shutdown_signal(
                "remote mempool server",
                |shutdown| {
                    server::remote_mempool_server_task(
                        ts_box,
                        self.args.chain_spec.clone(),
                        pool_handle,
                        addr,
                        shutdown,
                    )
                },
            );
        };

        tracing::info!("Started op_pool");

        Ok(())
    }

    fn create_mempool_v0_6<T: TaskSpawnerExt>(
        &self,
        task_spawner: &T,
        chain_spec: ChainSpec,
        pool_config: &PoolConfig,
        unsafe_mode: bool,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
    ) -> anyhow::Result<Arc<dyn Mempool + 'static>> {
        let ep = self
            .ep_06
            .clone()
            .context("entry point v0.6 not supplied")?;

        if unsafe_mode {
            let simulator = UnsafeSimulator::new(ep.clone());
            Self::create_mempool(
                task_spawner,
                chain_spec,
                pool_config,
                event_sender,
                self.provider.clone(),
                ep.clone(),
                simulator,
            )
        } else {
            let simulator = simulation::new_v0_6_simulator(
                self.provider.clone(),
                ep.clone(),
                pool_config.sim_settings.clone(),
                pool_config.mempool_channel_configs.clone(),
            );
            Self::create_mempool(
                task_spawner,
                chain_spec,
                pool_config,
                event_sender,
                self.provider.clone(),
                ep.clone(),
                simulator,
            )
        }
    }

    fn create_mempool_v0_7<T: TaskSpawnerExt>(
        &self,
        task_spawner: &T,
        chain_spec: ChainSpec,
        pool_config: &PoolConfig,
        unsafe_mode: bool,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
    ) -> anyhow::Result<Arc<dyn Mempool + 'static>> {
        let ep = self
            .ep_07
            .clone()
            .context("entry point v0.7 not supplied")?;

        if unsafe_mode {
            let simulator = UnsafeSimulator::new(ep.clone());
            Self::create_mempool(
                task_spawner,
                chain_spec,
                pool_config,
                event_sender,
                self.provider.clone(),
                ep.clone(),
                simulator,
            )
        } else {
            let simulator = simulation::new_v0_7_simulator(
                self.provider.clone(),
                ep.clone(),
                pool_config.sim_settings.clone(),
                pool_config.mempool_channel_configs.clone(),
            );
            Self::create_mempool(
                task_spawner,
                chain_spec,
                pool_config,
                event_sender,
                self.provider.clone(),
                ep.clone(),
                simulator,
            )
        }
    }

    fn create_mempool<T, UO, E, S>(
        task_spawner: &T,
        chain_spec: ChainSpec,
        pool_config: &PoolConfig,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        provider: P,
        ep: E,
        simulator: S,
    ) -> anyhow::Result<Arc<dyn Mempool + 'static>>
    where
        T: TaskSpawnerExt,
        UO: UserOperation + From<UserOperationVariant> + Into<UserOperationVariant>,
        UserOperationVariant: From<UO>,
        E: EntryPointProvider<UO> + Clone + 'static,
        S: Simulator<UO = UO> + 'static,
    {
        let fee_oracle = gas::get_fee_oracle(&chain_spec, provider.clone());
        let fee_estimator = FeeEstimatorImpl::new(
            provider.clone(),
            fee_oracle,
            pool_config.precheck_settings.priority_fee_mode,
            pool_config
                .precheck_settings
                .bundle_priority_fee_overhead_percent,
        );

        let prechecker = PrecheckerImpl::new(
            chain_spec,
            provider.clone(),
            ep.clone(),
            fee_estimator,
            pool_config.precheck_settings,
        );

        let reputation = Arc::new(AddressReputation::new(
            ReputationParams::new(pool_config.reputation_tracking_enabled),
            pool_config.blocklist.clone().unwrap_or_default(),
            pool_config.allowlist.clone().unwrap_or_default(),
        ));

        // Start reputation manager
        let reputation_runner = Arc::clone(&reputation);
        task_spawner.spawn_critical(
            "reputation manager",
            async move { reputation_runner.run().await }.boxed(),
        );

        let paymaster = PaymasterTracker::new(
            ep.clone(),
            PaymasterConfig::new(
                pool_config.sim_settings.min_stake_value,
                pool_config.sim_settings.min_unstake_delay,
                pool_config.paymaster_tracking_enabled,
                pool_config.paymaster_cache_length,
            ),
        );

        let uo_pool = UoPool::new(
            pool_config.clone(),
            event_sender,
            provider,
            prechecker,
            simulator,
            paymaster,
            reputation,
        );

        Ok(Arc::new(uo_pool))
    }
}
