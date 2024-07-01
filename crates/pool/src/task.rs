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
use ethers::providers::Middleware;
use rundler_provider::{EntryPointProvider, EthersEntryPointV0_6, EthersEntryPointV0_7, Provider};
use rundler_sim::{
    simulation::{self, UnsafeSimulator},
    PrecheckerImpl, Simulator,
};
use rundler_task::Task;
use rundler_types::{chain::ChainSpec, EntryPointVersion, UserOperation, UserOperationVariant};
use rundler_utils::{emit::WithEntryPoint, handle};
use tokio::{sync::broadcast, try_join};
use tokio_util::sync::CancellationToken;

use super::mempool::PoolConfig;
use crate::{
    chain::{self, Chain},
    emit::OpPoolEvent,
    mempool::{
        AddressReputation, Mempool, PaymasterConfig, PaymasterTracker, ReputationParams, UoPool,
    },
    server::{spawn_remote_mempool_server, LocalPoolBuilder},
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
pub struct PoolTask {
    args: Args,
    event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
    pool_builder: LocalPoolBuilder,
}

#[async_trait]
impl Task for PoolTask {
    async fn run(mut self: Box<Self>, shutdown_token: CancellationToken) -> anyhow::Result<()> {
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
        let provider = rundler_provider::new_provider(
            &self.args.http_url,
            Some(self.args.chain_poll_interval),
        )?;
        let chain = Chain::new(provider.clone(), chain_settings);
        let (update_sender, _) = broadcast::channel(self.args.chain_update_channel_capacity);
        let chain_handle = chain.spawn_watcher(update_sender.clone(), shutdown_token.clone());

        // create mempools
        let mut mempools = HashMap::new();
        for pool_config in &self.args.pool_configs {
            match pool_config.entry_point_version {
                EntryPointVersion::V0_6 => {
                    let pool = PoolTask::create_mempool_v0_6(
                        self.args.chain_spec.clone(),
                        pool_config,
                        self.args.unsafe_mode,
                        self.event_sender.clone(),
                        provider.clone(),
                    )
                    .context("should have created mempool")?;

                    mempools.insert(pool_config.entry_point, pool);
                }
                EntryPointVersion::V0_7 => {
                    let pool = PoolTask::create_mempool_v0_7(
                        self.args.chain_spec.clone(),
                        pool_config,
                        self.args.unsafe_mode,
                        self.event_sender.clone(),
                        provider.clone(),
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
        let pool_runner_handle =
            self.pool_builder
                .run(mempools, update_sender.subscribe(), shutdown_token.clone());

        let remote_handle = match self.args.remote_address {
            Some(addr) => {
                spawn_remote_mempool_server(
                    self.args.chain_spec.clone(),
                    pool_handle,
                    addr,
                    shutdown_token,
                )
                .await?
            }
            None => tokio::spawn(async { Ok(()) }),
        };

        tracing::info!("Started op_pool");

        match try_join!(
            handle::flatten_handle(pool_runner_handle),
            handle::flatten_handle(remote_handle),
            handle::as_anyhow_handle(chain_handle),
        ) {
            Ok(_) => {
                tracing::info!("Pool server shutdown");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Pool server error: {e:?}");
                bail!("Pool server error: {e:?}")
            }
        }
    }
}

impl PoolTask {
    /// Create a new pool task.
    pub fn new(
        args: Args,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        pool_builder: LocalPoolBuilder,
    ) -> PoolTask {
        Self {
            args,
            event_sender,
            pool_builder,
        }
    }

    /// Convert this task into a boxed task.
    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }

    fn create_mempool_v0_6<P: Provider + Middleware>(
        chain_spec: ChainSpec,
        pool_config: &PoolConfig,
        unsafe_mode: bool,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        provider: Arc<P>,
    ) -> anyhow::Result<Arc<dyn Mempool>> {
        let ep = EthersEntryPointV0_6::new(
            pool_config.entry_point,
            &chain_spec,
            pool_config.sim_settings.max_simulate_handle_ops_gas,
            Arc::clone(&provider),
        );

        if unsafe_mode {
            let simulator = UnsafeSimulator::new(
                Arc::clone(&provider),
                ep.clone(),
                pool_config.sim_settings.clone(),
            );
            Self::create_mempool(
                chain_spec,
                pool_config,
                event_sender,
                provider,
                ep,
                simulator,
            )
        } else {
            let simulator = simulation::new_v0_6_simulator(
                Arc::clone(&provider),
                ep.clone(),
                pool_config.sim_settings.clone(),
                pool_config.mempool_channel_configs.clone(),
            );
            Self::create_mempool(
                chain_spec,
                pool_config,
                event_sender,
                provider,
                ep,
                simulator,
            )
        }
    }

    fn create_mempool_v0_7<P: Provider + Middleware>(
        chain_spec: ChainSpec,
        pool_config: &PoolConfig,
        unsafe_mode: bool,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        provider: Arc<P>,
    ) -> anyhow::Result<Arc<dyn Mempool>> {
        let ep = EthersEntryPointV0_7::new(
            pool_config.entry_point,
            &chain_spec,
            pool_config.sim_settings.max_simulate_handle_ops_gas,
            Arc::clone(&provider),
        );

        if unsafe_mode {
            let simulator = UnsafeSimulator::new(
                Arc::clone(&provider),
                ep.clone(),
                pool_config.sim_settings.clone(),
            );
            Self::create_mempool(
                chain_spec,
                pool_config,
                event_sender,
                provider,
                ep,
                simulator,
            )
        } else {
            let simulator = simulation::new_v0_7_simulator(
                Arc::clone(&provider),
                ep.clone(),
                pool_config.sim_settings.clone(),
                pool_config.mempool_channel_configs.clone(),
            );
            Self::create_mempool(
                chain_spec,
                pool_config,
                event_sender,
                provider,
                ep,
                simulator,
            )
        }
    }

    fn create_mempool<UO, P, E, S>(
        chain_spec: ChainSpec,
        pool_config: &PoolConfig,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        provider: Arc<P>,
        ep: E,
        simulator: S,
    ) -> anyhow::Result<Arc<dyn Mempool>>
    where
        UO: UserOperation + From<UserOperationVariant> + Into<UserOperationVariant>,
        UserOperationVariant: From<UO>,
        P: Provider,
        E: EntryPointProvider<UO> + Clone,
        S: Simulator<UO = UO>,
    {
        let prechecker = PrecheckerImpl::new(
            chain_spec,
            Arc::clone(&provider),
            ep.clone(),
            pool_config.precheck_settings,
        );

        let reputation = Arc::new(AddressReputation::new(
            ReputationParams::new(pool_config.reputation_tracking_enabled),
            pool_config.blocklist.clone().unwrap_or_default(),
            pool_config.allowlist.clone().unwrap_or_default(),
        ));

        // Start reputation manager
        let reputation_runner = Arc::clone(&reputation);
        tokio::spawn(async move { reputation_runner.run().await });

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
            prechecker,
            simulator,
            paymaster,
            reputation,
        );

        Ok(Arc::new(uo_pool))
    }
}
