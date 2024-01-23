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
use rundler_provider::{EntryPoint, PaymasterHelper, Provider};
use rundler_sim::{
    Prechecker, PrecheckerImpl, SimulateValidationTracerImpl, Simulator, SimulatorImpl,
};
use rundler_task::Task;
use rundler_types::contracts::{
    i_entry_point::IEntryPoint, paymaster_helper::PaymasterHelper as PaymasterHelperContract,
};
use rundler_utils::{emit::WithEntryPoint, eth, handle};
use tokio::{sync::broadcast, try_join};
use tokio_util::sync::CancellationToken;

use super::mempool::{HourlyMovingAverageReputation, PoolConfig, ReputationParams};
use crate::{
    chain::{self, Chain},
    emit::OpPoolEvent,
    mempool::UoPool,
    server::{spawn_remote_mempool_server, LocalPoolBuilder},
};

/// Arguments for the pool task.
#[derive(Debug)]
pub struct Args {
    /// HTTP URL for the full node.
    pub http_url: String,
    /// Poll interval for full node requests.
    pub http_poll_interval: Duration,
    /// ID of the chain this pool is tracking
    pub chain_id: u64,
    /// Number of blocks to keep in the chain history.
    pub chain_history_size: u64,
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
        let chain_id = self.args.chain_id;
        tracing::info!("Chain id: {chain_id}");
        tracing::info!("Http url: {:?}", self.args.http_url);

        // create chain
        let chain_settings = chain::Settings {
            history_size: self.args.chain_history_size,
            poll_interval: self.args.http_poll_interval,
            entry_point_addresses: self
                .args
                .pool_configs
                .iter()
                .map(|config| config.entry_point)
                .collect(),
        };
        let provider = eth::new_provider(&self.args.http_url, Some(self.args.http_poll_interval))?;
        let chain = Chain::new(provider.clone(), chain_settings);
        let (update_sender, _) = broadcast::channel(self.args.chain_update_channel_capacity);
        let chain_handle = chain.spawn_watcher(update_sender.clone(), shutdown_token.clone());

        // create mempools
        let mut mempools = HashMap::new();
        for pool_config in &self.args.pool_configs {
            let pool =
                PoolTask::create_mempool(pool_config, self.event_sender.clone(), provider.clone())
                    .await
                    .context("should have created mempool")?;

            mempools.insert(pool_config.entry_point, Arc::new(pool));
        }

        let pool_handle = self.pool_builder.get_handle();
        let pool_runner_handle =
            self.pool_builder
                .run(mempools, update_sender.subscribe(), shutdown_token.clone());

        let remote_handle = match self.args.remote_address {
            Some(addr) => {
                spawn_remote_mempool_server(self.args.chain_id, pool_handle, addr, shutdown_token)
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

    async fn create_mempool<P: Provider + Middleware>(
        pool_config: &PoolConfig,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        provider: Arc<P>,
    ) -> anyhow::Result<
        UoPool<
            HourlyMovingAverageReputation,
            impl Prechecker,
            impl Simulator,
            impl EntryPoint,
            impl PaymasterHelper,
        >,
    > {
        // Reputation manager
        let reputation = Arc::new(HourlyMovingAverageReputation::new(
            ReputationParams::bundler_default(),
            pool_config.blocklist.clone(),
            pool_config.allowlist.clone(),
        ));
        // Start reputation manager
        let reputation_runner = Arc::clone(&reputation);
        tokio::spawn(async move { reputation_runner.run().await });

        let i_entry_point = IEntryPoint::new(pool_config.entry_point, Arc::clone(&provider));
        let paymaster_helper =
            PaymasterHelperContract::new(pool_config.entry_point, Arc::clone(&provider));

        let simulate_validation_tracer =
            SimulateValidationTracerImpl::new(Arc::clone(&provider), i_entry_point.clone());
        let prechecker = PrecheckerImpl::new(
            Arc::clone(&provider),
            i_entry_point.clone(),
            pool_config.precheck_settings,
        );
        let simulator = SimulatorImpl::new(
            Arc::clone(&provider),
            i_entry_point.address(),
            simulate_validation_tracer,
            pool_config.sim_settings,
            pool_config.mempool_channel_configs.clone(),
        );

        Ok(UoPool::new(
            pool_config.clone(),
            Arc::clone(&reputation),
            event_sender,
            prechecker,
            simulator,
            i_entry_point,
            paymaster_helper,
        ))
    }
}
