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

use alloy_primitives::{Address, B256};
use anyhow::Context;
use async_trait::async_trait;
use futures::FutureExt;
use rundler_provider::{
    EntryPoint, FeeEstimator, Providers, ProvidersWithEntryPointT, SimulationProvider,
    StateOverride,
};
use rundler_sim::{
    EstimationSettings, GasEstimator, GasEstimatorV0_6, GasEstimatorV0_7, PrecheckerImpl,
    Simulator,
    simulation::{self, UnsafeSimulator},
};
use rundler_task::TaskSpawnerExt;
use rundler_types::{
    EntryPointAbiVersion, GasEstimate, GasFees, UserOperation, UserOperationOptionalGas,
    UserOperationVariant,
    chain::ChainSpec,
    pool::{FeeEstimate, MinedUserOperation, PoolError, UserOperationReceiptData},
};
use rundler_utils::emit::WithEntryPoint;
use tokio::sync::broadcast;

use super::mempool::PoolConfig;
use crate::{
    chain::{self, Chain},
    emit::OpPoolEvent,
    events::{
        UserOperationEventProvider, UserOperationEventProviderV0_6, UserOperationEventProviderV0_7,
    },
    mempool::{
        AddressReputation, Mempool, PaymasterConfig, PaymasterTracker, ReputationParams, UoPool,
        UoPoolProviders,
    },
    server::{self, LocalPoolBuilder, PoolEntryPointServices, PoolFeeEstimator},
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
    /// Gas estimation settings.
    pub estimation_settings: EstimationSettings,
    /// Maximum block distance to search for user operation events.
    pub event_block_distance: Option<u64>,
    /// Fallback block distance to search for user operation events.
    pub event_block_distance_fallback: Option<u64>,
}

/// Mempool task.
pub struct PoolTask<P> {
    args: Args,
    event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
    pool_builder: LocalPoolBuilder,
    providers: P,
}

impl<P> PoolTask<P> {
    /// Create a new pool task.
    pub fn new(
        args: Args,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        pool_builder: LocalPoolBuilder,
        providers: P,
    ) -> Self {
        Self {
            args,
            event_sender,
            pool_builder,
            providers,
        }
    }
}

impl<P> PoolTask<P>
where
    P: Providers + 'static,
{
    /// Spawns the mempool task on the given task spawner.
    pub async fn spawn<T>(self, task_spawner: T) -> anyhow::Result<()>
    where
        T: TaskSpawnerExt,
    {
        let chain_id = self.args.chain_spec.id;
        tracing::info!("Chain id: {chain_id}");
        tracing::info!("Http url: {:?}", self.args.http_url);

        // create chain
        let chain_settings = chain::Settings {
            history_size: self.args.chain_spec.chain_history_size,
            poll_interval: self.args.chain_poll_interval,
            max_sync_retries: self.args.chain_max_sync_retries,
            channel_capacity: self.args.chain_update_channel_capacity,
            entry_point_addresses: self
                .args
                .pool_configs
                .iter()
                .map(|config| (config.entry_point, config.entry_point_version))
                .collect(),
            flashblocks: self.args.chain_spec.flashblocks_enabled,
        };

        let chain = Chain::new(self.providers.evm().clone(), chain_settings);
        let chain_subscriber = chain.subscriber();

        task_spawner.spawn_critical_with_graceful_shutdown_signal("chain watcher", |shutdown| {
            chain.watch(shutdown)
        });

        // create mempools and entry point services
        let mut mempools = HashMap::new();
        let mut ep_services: HashMap<Address, Arc<dyn PoolEntryPointServices>> = HashMap::new();
        for pool_config in &self.args.pool_configs {
            match pool_config.entry_point_version.abi_version() {
                EntryPointAbiVersion::V0_6 => {
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

                    let services = self
                        .create_ep_services_v0_6(pool_config)
                        .context("should have created v0.6 entry point services")?;
                    ep_services.insert(pool_config.entry_point, services);
                }
                EntryPointAbiVersion::V0_7 => {
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

                    let services = self
                        .create_ep_services_v0_7(pool_config)
                        .context("should have created v0.7 entry point services")?;
                    ep_services.insert(pool_config.entry_point, services);
                }
            }
        }

        // create fee estimator
        let fee_estimator: Arc<dyn PoolFeeEstimator> = Arc::new(PoolFeeEstimatorImpl {
            fee_estimator: self.providers.fee_estimator().clone(),
        });

        let pool_handle = self.pool_builder.get_handle();

        let ts_box = Box::new(task_spawner.clone());
        task_spawner.spawn_critical_with_graceful_shutdown_signal(
            "local pool server",
            |shutdown| {
                self.pool_builder.run(
                    ts_box,
                    mempools,
                    ep_services,
                    fee_estimator,
                    chain_subscriber,
                    shutdown,
                )
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

    fn create_mempool_v0_6<T>(
        &self,
        task_spawner: &T,
        chain_spec: ChainSpec,
        pool_config: &PoolConfig,
        unsafe_mode: bool,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
    ) -> anyhow::Result<Arc<dyn Mempool + 'static>>
    where
        T: TaskSpawnerExt,
    {
        let ep_providers = self
            .providers
            .ep_v0_6_providers()
            .clone()
            .context("entry point v0.6 not supplied")?;

        if unsafe_mode {
            let simulator = UnsafeSimulator::new(
                ep_providers.entry_point().clone(),
                pool_config.sim_settings.clone(),
                &pool_config.mempool_channel_configs,
            );
            self.create_mempool(
                task_spawner,
                chain_spec,
                pool_config,
                event_sender,
                ep_providers,
                simulator,
            )
        } else {
            let simulator = simulation::new_v0_6_simulator(
                ep_providers.evm().clone(),
                ep_providers.entry_point().clone(),
                pool_config.sim_settings.clone(),
                pool_config.mempool_channel_configs.clone(),
            );
            self.create_mempool(
                task_spawner,
                chain_spec,
                pool_config,
                event_sender,
                ep_providers,
                simulator,
            )
        }
    }

    fn create_mempool_v0_7<T>(
        &self,
        task_spawner: &T,
        chain_spec: ChainSpec,
        pool_config: &PoolConfig,
        unsafe_mode: bool,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
    ) -> anyhow::Result<Arc<dyn Mempool + 'static>>
    where
        T: TaskSpawnerExt,
    {
        let ep_providers = self
            .providers
            .ep_v0_7_providers(pool_config.entry_point_version)
            .clone()
            .context(format!(
                "entry point v0.7 not supplied for entry point version: {:?}",
                pool_config.entry_point_version
            ))?;

        if unsafe_mode {
            let simulator = UnsafeSimulator::new(
                ep_providers.entry_point().clone(),
                pool_config.sim_settings.clone(),
                &pool_config.mempool_channel_configs,
            );
            self.create_mempool(
                task_spawner,
                chain_spec,
                pool_config,
                event_sender,
                ep_providers,
                simulator,
            )
        } else {
            let simulator = simulation::new_v0_7_simulator(
                self.providers.evm().clone(),
                ep_providers.entry_point().clone(),
                pool_config.sim_settings.clone(),
                pool_config.mempool_channel_configs.clone(),
            );
            self.create_mempool(
                task_spawner,
                chain_spec,
                pool_config,
                event_sender,
                ep_providers,
                simulator,
            )
        }
    }

    fn create_ep_services_v0_6(
        &self,
        _pool_config: &PoolConfig,
    ) -> anyhow::Result<Arc<dyn PoolEntryPointServices>> {
        let ep_providers = self
            .providers
            .ep_v0_6_providers()
            .clone()
            .context("entry point v0.6 not supplied")?;

        let gas_estimator = GasEstimatorV0_6::new(
            self.args.chain_spec.clone(),
            ep_providers.evm().clone(),
            ep_providers.entry_point().clone(),
            self.args.estimation_settings,
            ep_providers.fee_estimator().clone(),
        );

        let event_provider = UserOperationEventProviderV0_6::new(
            self.args.chain_spec.clone(),
            *ep_providers.entry_point().address(),
            ep_providers.evm().clone(),
            self.args.event_block_distance,
            self.args.event_block_distance_fallback,
        );

        Ok(Arc::new(PoolEntryPointServicesImpl {
            gas_estimator,
            entry_point: ep_providers.entry_point().clone(),
            event_provider: Box::new(event_provider),
        }))
    }

    fn create_ep_services_v0_7(
        &self,
        pool_config: &PoolConfig,
    ) -> anyhow::Result<Arc<dyn PoolEntryPointServices>> {
        let ep_providers = self
            .providers
            .ep_v0_7_providers(pool_config.entry_point_version)
            .clone()
            .context(format!(
                "entry point v0.7 not supplied for entry point version: {:?}",
                pool_config.entry_point_version
            ))?;

        let gas_estimator = GasEstimatorV0_7::new(
            self.args.chain_spec.clone(),
            ep_providers.evm().clone(),
            ep_providers.entry_point().clone(),
            self.args.estimation_settings,
            ep_providers.fee_estimator().clone(),
        );

        let event_provider = UserOperationEventProviderV0_7::new(
            self.args.chain_spec.clone(),
            *ep_providers.entry_point().address(),
            ep_providers.evm().clone(),
            self.args.event_block_distance,
            self.args.event_block_distance_fallback,
        );

        Ok(Arc::new(PoolEntryPointServicesImpl {
            gas_estimator,
            entry_point: ep_providers.entry_point().clone(),
            event_provider: Box::new(event_provider),
        }))
    }

    fn create_mempool<T, UO, EP, S>(
        &self,
        task_spawner: &T,
        chain_spec: ChainSpec,
        pool_config: &PoolConfig,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        ep_providers: EP,
        simulator: S,
    ) -> anyhow::Result<Arc<dyn Mempool + 'static>>
    where
        T: TaskSpawnerExt,
        UO: UserOperation + From<UserOperationVariant> + Into<UserOperationVariant>,
        UserOperationVariant: From<UO>,
        EP: ProvidersWithEntryPointT<UO = UO> + 'static,
        S: Simulator<UO = UO> + 'static,
    {
        let prechecker = PrecheckerImpl::new(
            chain_spec,
            ep_providers.evm().clone(),
            ep_providers.entry_point().clone(),
            ep_providers.fee_estimator().clone(),
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
            ep_providers.entry_point().clone(),
            PaymasterConfig::new(
                pool_config.sim_settings.min_stake_value,
                pool_config.sim_settings.min_unstake_delay,
                pool_config.paymaster_tracking_enabled,
                pool_config.paymaster_cache_length,
            ),
        );

        // There should only be one mempool config per entry point
        let mempool_config = pool_config
            .mempool_channel_configs
            .values()
            .find(|c| c.entry_point() == *ep_providers.entry_point().address())
            .cloned()
            .unwrap_or_default();

        let uo_pool = UoPool::new(
            pool_config.clone(),
            ep_providers,
            UoPoolProviders::new(simulator, prechecker),
            event_sender,
            paymaster,
            reputation,
            mempool_config,
        );

        Ok(Arc::new(uo_pool))
    }
}

/// Concrete implementation of `PoolEntryPointServices` that wraps a `GasEstimator`,
/// an `EntryPoint` (as `SimulationProvider` for signature checking), and an event
/// provider for looking up mined user operations and receipts.
struct PoolEntryPointServicesImpl<G, E> {
    gas_estimator: G,
    entry_point: E,
    event_provider: Box<dyn UserOperationEventProvider>,
}

#[async_trait]
impl<UO, G, E> PoolEntryPointServices for PoolEntryPointServicesImpl<G, E>
where
    UO: UserOperation + From<UserOperationVariant>,
    G: GasEstimator + 'static,
    G::UserOperationOptionalGas: From<UserOperationOptionalGas>,
    E: SimulationProvider<UO = UO> + 'static,
{
    async fn estimate_gas(
        &self,
        op: UserOperationOptionalGas,
        state_override_json: Option<Vec<u8>>,
    ) -> Result<GasEstimate, PoolError> {
        let state_override: StateOverride = match state_override_json {
            Some(json) => serde_json::from_slice(&json)
                .map_err(|e| PoolError::Other(anyhow::anyhow!("Invalid state override: {e}")))?,
            None => StateOverride::default(),
        };

        self.gas_estimator
            .estimate_op_gas(op.into(), state_override)
            .await
            .map_err(|e| PoolError::GasEstimation(e.to_string()))
    }

    async fn check_signature(&self, op: UserOperationVariant) -> Result<bool, PoolError> {
        let output = self
            .entry_point
            .simulate_validation(op.into(), None)
            .await
            .map_err(|e| PoolError::Other(anyhow::anyhow!("Simulation error: {e}")))?
            .map_err(|e| PoolError::Other(anyhow::anyhow!("Validation revert: {e}")))?;

        Ok(!output.return_info.account_sig_failed)
    }

    async fn get_mined_by_hash(&self, hash: B256) -> Result<Option<MinedUserOperation>, PoolError> {
        self.event_provider
            .get_mined_by_hash(hash)
            .await
            .map_err(PoolError::Other)
    }

    async fn get_receipt(
        &self,
        hash: B256,
        bundle_transaction: Option<B256>,
    ) -> Result<Option<UserOperationReceiptData>, PoolError> {
        match bundle_transaction {
            Some(tx_hash) => self
                .event_provider
                .get_receipt_from_tx_hash(hash, tx_hash)
                .await
                .map_err(PoolError::Other),
            None => self
                .event_provider
                .get_receipt(hash)
                .await
                .map_err(PoolError::Other),
        }
    }

    async fn get_mined_from_tx(
        &self,
        uo_hash: B256,
        tx_hash: B256,
    ) -> Result<Option<(MinedUserOperation, UserOperationReceiptData)>, PoolError> {
        // First get the tx receipt
        let mined = self
            .event_provider
            .get_mined_by_hash(uo_hash)
            .await
            .map_err(PoolError::Other)?;

        let Some(mined) = mined else {
            return Ok(None);
        };

        // Only return if the mined operation matches the expected tx hash
        if mined.transaction_hash != tx_hash {
            return Ok(None);
        }

        let receipt = self
            .event_provider
            .get_receipt_from_tx_hash(uo_hash, tx_hash)
            .await
            .map_err(PoolError::Other)?;

        match receipt {
            Some(receipt) => Ok(Some((mined, receipt))),
            None => Ok(None),
        }
    }
}

/// Concrete implementation of `PoolFeeEstimator` that wraps a `FeeEstimator`.
struct PoolFeeEstimatorImpl<F> {
    fee_estimator: F,
}

#[async_trait]
impl<F: FeeEstimator> PoolFeeEstimator for PoolFeeEstimatorImpl<F> {
    async fn get_max_priority_fee_per_gas(&self) -> Result<u128, PoolError> {
        let (bundle_fees, _) = self
            .fee_estimator
            .latest_bundle_fees()
            .await
            .map_err(PoolError::Other)?;
        Ok(self
            .fee_estimator
            .required_op_fees(bundle_fees)
            .max_priority_fee_per_gas)
    }

    async fn get_fee_estimate(&self) -> Result<FeeEstimate, PoolError> {
        let estimate = self
            .fee_estimator
            .latest_fee_estimate()
            .await
            .map_err(PoolError::Other)?;
        Ok(FeeEstimate {
            block_number: estimate.block_number,
            base_fee: estimate.base_fee,
            required_base_fee: estimate.required_base_fee,
            required_priority_fee: estimate.required_priority_fee,
        })
    }

    fn get_required_op_fees(&self, bundle_fees: GasFees) -> GasFees {
        self.fee_estimator.required_op_fees(bundle_fees)
    }
}
