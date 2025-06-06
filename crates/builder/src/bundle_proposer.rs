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
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    mem,
    pin::Pin,
    sync::Arc,
    time::Instant,
};

use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::Context;
use async_trait::async_trait;
use futures::future;
use linked_hash_map::LinkedHashMap;
use metrics::{Counter, Histogram};
use metrics_derive::Metrics;
#[cfg(test)]
use mockall::automock;
use rundler_provider::{
    BundleHandler, DAGasOracleSync, DAGasProvider, EntryPoint, EvmProvider, FeeEstimator,
    HandleOpsOut, ProvidersWithEntryPointT,
};
use rundler_sim::{SimulationError, SimulationResult, Simulator, ViolationError};
use rundler_types::{
    aggregator::SignatureAggregatorResult,
    chain::ChainSpec,
    da::DAGasBlockData,
    pool::{PoolOperation, SimulationViolation},
    proxy::SubmissionProxy,
    BundleExpectedStorage, Entity, EntityInfo, EntityInfos, EntityType, EntityUpdate,
    EntityUpdateType, EntryPointVersion, ExpectedStorage, GasFees, Timestamp, UserOperation,
    UserOperationVariant, UserOpsPerAggregator, ValidTimeRange, ValidationRevert,
    BUNDLE_BYTE_OVERHEAD, TIME_RANGE_BUFFER,
};
use rundler_utils::{emit::WithEntryPoint, guard_timer::CustomTimerGuard, math};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::emit::{BuilderEvent, ConditionNotMetReason, OpRejectionReason, SkipReason};

/// Extra buffer percent to add on the bundle transaction gas estimate to be sure it will be enough
const BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT: u32 = 5;

#[derive(Debug)]
pub(crate) struct Bundle<UO: UserOperation> {
    pub(crate) ops_per_aggregator: Vec<UserOpsPerAggregator<UO>>,
    pub(crate) gas_estimate: u64,
    pub(crate) gas_fees: GasFees,
    pub(crate) expected_storage: ExpectedStorage,
    pub(crate) rejected_ops: Vec<UO>,
    pub(crate) entity_updates: Vec<EntityUpdate>,
}

impl<UO: UserOperation> Default for Bundle<UO> {
    fn default() -> Self {
        Self {
            ops_per_aggregator: Vec::new(),
            gas_estimate: 0,
            gas_fees: GasFees::default(),
            expected_storage: ExpectedStorage::default(),
            rejected_ops: Vec::new(),
            entity_updates: Vec::new(),
        }
    }
}

impl<UO: UserOperation> Bundle<UO> {
    pub(crate) fn len(&self) -> usize {
        self.ops_per_aggregator
            .iter()
            .map(|ops| ops.user_ops.len())
            .sum()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ops_per_aggregator.is_empty()
    }

    pub(crate) fn iter_ops(&self) -> impl Iterator<Item = &UO> + '_ {
        self.ops_per_aggregator.iter().flat_map(|ops| &ops.user_ops)
    }
}

#[async_trait]
#[cfg_attr(test, automock(type UO = rundler_types::v0_6::UserOperation;))]
pub(crate) trait BundleProposer: Send + Sync {
    type UO: UserOperation;

    /// Constructs the next bundle
    ///
    /// If `min_fees` is `Some`, the proposer will ensure the bundle has
    /// at least `min_fees`.
    async fn make_bundle(
        &mut self,
        ops: Vec<PoolOperation>,
        block_hash: B256,
        max_bundle_fee: U256,
        min_gas_fees: Option<GasFees>,
        is_replacement: bool,
    ) -> BundleProposerResult<Bundle<<Self as BundleProposer>::UO>>;

    /// Gets the current gas fees
    ///
    /// If `min_fees` is `Some`, the proposer will ensure the gas fees returned are at least `min_fees`.
    async fn estimate_gas_fees(
        &self,
        block_hash: B256,
        min_fees: Option<GasFees>,
    ) -> BundleProposerResult<(GasFees, u128)>;

    /// Notifies the proposer that a condition was not met during the last bundle proposal
    fn notify_condition_not_met(&mut self);
}

pub(crate) type BundleProposerResult<T> = std::result::Result<T, BundleProposerError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum BundleProposerError {
    #[error("No operations after fee filtering")]
    NoOperationsAfterFeeFilter,
    #[error(transparent)]
    ProviderError(#[from] rundler_provider::ProviderError),
    /// All other errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub(crate) struct BundleProposerImpl<EP, BP> {
    builder_tag: String,
    settings: Settings,
    ep_providers: EP,
    bundle_providers: BP,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    condition_not_met_notified: bool,
    metrics: BuilderProposerMetrics,
}

#[derive(Debug)]
pub(crate) struct Settings {
    pub(crate) chain_spec: ChainSpec,
    pub(crate) target_bundle_gas: u128,
    pub(crate) max_bundle_gas: u128,
    pub(crate) sender_eoa: Address,
    pub(crate) da_gas_tracking_enabled: bool,
    pub(crate) max_expected_storage_slots: usize,
    pub(crate) verification_gas_limit_efficiency_reject_threshold: f64,
    pub(crate) submission_proxy: Option<Arc<dyn SubmissionProxy>>,
}

#[async_trait]
impl<EP, BP> BundleProposer for BundleProposerImpl<EP, BP>
where
    EP: ProvidersWithEntryPointT,
    BP: BundleProposerProvidersT,
{
    type UO = EP::UO;

    async fn estimate_gas_fees(
        &self,
        block_hash: B256,
        required_fees: Option<GasFees>,
    ) -> BundleProposerResult<(GasFees, u128)> {
        Ok(self
            .ep_providers
            .fee_estimator()
            .required_bundle_fees(block_hash, required_fees)
            .await?)
    }

    fn notify_condition_not_met(&mut self) {
        self.condition_not_met_notified = true;
    }

    async fn make_bundle(
        &mut self,
        ops: Vec<PoolOperation>,
        block_hash: B256,
        max_bundle_fee: U256,
        min_gas_fees: Option<GasFees>,
        is_replacement: bool,
    ) -> BundleProposerResult<Bundle<Self::UO>> {
        let timer = Instant::now();
        let (bundle_fees, base_fee) = self.estimate_gas_fees(block_hash, min_gas_fees).await?;

        // (0) Determine fees required for ops to be included in a bundle
        // if replacing, just require bundle fees increase chances of unsticking
        let required_op_fees = if is_replacement {
            bundle_fees
        } else {
            self.ep_providers
                .fee_estimator()
                .required_op_fees(bundle_fees)
        };
        let all_paymaster_addresses = ops
            .iter()
            .filter_map(|op| op.uo.paymaster())
            .collect::<Vec<Address>>();

        let da_block_data = if self.settings.da_gas_tracking_enabled
            && self.ep_providers.da_gas_oracle_sync().is_some()
        {
            let da_gas_oracle = self.ep_providers.da_gas_oracle_sync().as_ref().unwrap();

            // should typically be a cache hit and fast
            match da_gas_oracle.da_block_data(block_hash.into()).await {
                Ok(block_data) => Some(block_data),
                Err(e) => {
                    error!("Failed to get block data for block hash {block_hash:?}, falling back to async da gas calculations: {e:?}");
                    None
                }
            }
        } else {
            None
        };
        // (1) Filter out ops that don't pay enough to be included
        let fee_futs = ops
            .into_iter()
            .map(|op| {
                self.check_fees(
                    op,
                    block_hash,
                    da_block_data.as_ref(),
                    base_fee,
                    required_op_fees,
                )
            })
            .collect::<Vec<_>>();
        // if using a sync da oracle, this doesn't make any remote calls
        let ops = future::join_all(fee_futs)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        tracing::debug!("Bundle proposal after fee limit had {} ops", ops.len());
        if ops.is_empty() {
            return Err(BundleProposerError::NoOperationsAfterFeeFilter);
        }

        // (2) Limit the amount of operations for simulation
        let (ops, gas_limit) = self.limit_user_operations_for_simulation(ops);

        debug!(
            "Bundle proposal after gas limit had {} ops and {:?} gas limit",
            ops.len(),
            gas_limit
        );

        // (3) simulate ops
        let simulation_futures = ops
            .into_iter()
            .map(|op| self.simulate_op(op, block_hash))
            .collect::<Vec<_>>();

        let ops_with_simulations_future = future::join_all(simulation_futures);
        let balances_by_paymaster_future =
            self.get_balances_by_paymaster(all_paymaster_addresses, block_hash);

        let (ops_with_simulations, balances_by_paymaster) =
            tokio::join!(ops_with_simulations_future, balances_by_paymaster_future);

        let balances_by_paymaster = balances_by_paymaster?;
        let ops_with_simulations = ops_with_simulations
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let mut context = self
            .assemble_context(
                max_bundle_fee,
                bundle_fees.max_fee_per_gas,
                ops_with_simulations,
                balances_by_paymaster,
            )
            .await;
        while !context.is_empty() {
            let gas_estimate = self
                .estimate_gas_rejecting_failed_ops(&mut context, bundle_fees)
                .await?;
            if let Some(gas_estimate) = gas_estimate {
                tracing::debug!(
                    "Bundle proposal succeeded with {} ops and {:?} gas limit",
                    context.iter_ops().count(),
                    gas_estimate
                );

                // If recently notified that a bundle condition was not met, check each of
                // the conditions again to ensure if they are met, rejecting OPs if they are not.
                if self.condition_not_met_notified {
                    self.condition_not_met_notified = false;
                    self.check_conditions_met(&mut context).await?;
                    if context.is_empty() {
                        break;
                    }
                }

                // bundle built, record time
                self.metrics
                    .bundle_build_ms
                    .record(timer.elapsed().as_millis() as f64);
                return Ok(Bundle {
                    ops_per_aggregator: context.to_ops_per_aggregator(),
                    gas_estimate,
                    gas_fees: bundle_fees,
                    expected_storage: context.bundle_expected_storage.inner,
                    rejected_ops: context.rejected_ops.iter().map(|po| po.0.clone()).collect(),
                    entity_updates: context.entity_updates.into_values().collect(),
                });
            }

            self.metrics.bundle_simulation_failures.increment(1);
            info!("Bundle gas estimation failed. Retrying after removing rejected op(s).");
        }

        Ok(Bundle {
            rejected_ops: context.rejected_ops.iter().map(|po| po.0.clone()).collect(),
            entity_updates: context.entity_updates.into_values().collect(),
            gas_fees: bundle_fees,
            ..Default::default()
        })
    }
}

#[derive(Metrics)]
#[metrics(scope = "builder_proposer")]
struct BuilderProposerMetrics {
    #[metric(describe = "the distribution of end to end bundle build time.")]
    bundle_build_ms: Histogram,
    #[metric(describe = "the distribution of op simulation time during bundle build.")]
    op_simulation_ms: Histogram,
    #[metric(describe = "the number of bundle simulation failures.")]
    bundle_simulation_failures: Counter,
    #[metric(describe = "the distribution of bundle simulation time.")]
    bundle_simulation_ms: Histogram,
}

impl<EP, BP> BundleProposerImpl<EP, BP>
where
    EP: ProvidersWithEntryPointT,
    BP: BundleProposerProvidersT,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        builder_tag: String,
        ep_providers: EP,
        bundle_providers: BP,
        settings: Settings,
        event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    ) -> Self {
        Self {
            builder_tag,
            ep_providers,
            bundle_providers,
            settings,
            event_sender,
            condition_not_met_notified: false,
            metrics: BuilderProposerMetrics::default(),
        }
    }

    // Check fees for a single user op. Returns None if the op should be skipped.
    //
    // Filters on:
    // - Insufficient gas fees
    // - Insufficient pre-verification gas. The initial PVG check is done when the block is updated in the mempool. However,
    //   that check uses the initial gas fee estimate, whereas this check uses the gas fees specifically from this bundle.
    async fn check_fees(
        &self,
        op: PoolOperation,
        block_hash: B256,
        da_block_data: Option<&DAGasBlockData>,
        base_fee: u128,
        required_op_fees: GasFees,
    ) -> Option<PoolOperationWithSponsoredDAGas> {
        let op_hash = op.uo.hash();

        let mut required_max_fee_per_gas = required_op_fees.max_fee_per_gas;
        let mut required_max_priority_fee_per_gas = required_op_fees.max_priority_fee_per_gas;

        if let Some(pct) = op.perms.underpriced_bundle_pct {
            required_max_fee_per_gas = math::percent_ceil(required_max_fee_per_gas, pct);
            required_max_priority_fee_per_gas =
                math::percent_ceil(required_max_priority_fee_per_gas, pct);
        }

        // filter by fees
        if (op.uo.max_fee_per_gas() < required_max_fee_per_gas
            || op.uo.max_priority_fee_per_gas() < required_max_priority_fee_per_gas)
            && op.perms.bundler_sponsorship.is_none()
        // skip if bundler sponsored
        {
            self.emit(BuilderEvent::skipped_op(
                self.builder_tag.clone(),
                op_hash,
                SkipReason::InsufficientFees {
                    required_fees: required_op_fees,
                    actual_fees: GasFees {
                        max_fee_per_gas: op.uo.max_fee_per_gas(),
                        max_priority_fee_per_gas: op.uo.max_priority_fee_per_gas(),
                    },
                },
            ));
            return None;
        }

        if !self.settings.chain_spec.da_pre_verification_gas {
            // Skip PVG check if no da pre-verification gas as this is checked on entry to the mempool.
            return Some(PoolOperationWithSponsoredDAGas {
                op,
                sponsored_da_gas: 0,
            });
        }

        // TODO(bundle): assuming a bundle size of 1
        let bundle_size = 1;

        let gas_price = if op.perms.bundler_sponsorship.is_some() {
            required_op_fees.gas_price(base_fee)
        } else {
            op.uo.gas_price(base_fee)
        };

        let required_da_gas = if self.settings.da_gas_tracking_enabled
            && da_block_data.is_some()
            && self.ep_providers.da_gas_oracle_sync().is_some()
        {
            let da_gas_oracle = self.ep_providers.da_gas_oracle_sync().as_ref().unwrap();
            let da_block_data = da_block_data.unwrap();
            let extra_data_len = op.uo.extra_data_len(bundle_size);

            da_gas_oracle.calc_da_gas_sync(
                &op.da_gas_data,
                da_block_data,
                gas_price,
                extra_data_len,
            )
        } else {
            match self
                .ep_providers
                .entry_point()
                .calc_da_gas(
                    op.uo.clone().into(),
                    block_hash.into(),
                    gas_price,
                    bundle_size,
                )
                .await
            {
                Ok((required_da_gas, _, _)) => required_da_gas,
                Err(e) => {
                    error!(
                        "Failed to calculate required pre-verification gas for op: {e:?}, skipping"
                    );
                    self.emit(BuilderEvent::skipped_op(
                        self.builder_tag.clone(),
                        op_hash,
                        SkipReason::Other {
                            reason: Arc::new(format!(
                                "Failed to calculate required pre-verification gas for op: {e:?}, skipping"
                            )),
                        },
                    ));
                    return None;
                }
            }
        };

        let mut required_pvg = op.uo.required_pre_verification_gas(
            &self.settings.chain_spec,
            bundle_size,
            required_da_gas,
            Some(
                self.settings
                    .verification_gas_limit_efficiency_reject_threshold,
            ),
        );

        if let Some(pct) = op.perms.underpriced_bundle_pct {
            required_pvg = math::percent_ceil(required_pvg, pct);
        }

        if op.uo.pre_verification_gas() < required_pvg && op.perms.bundler_sponsorship.is_none() {
            self.emit(BuilderEvent::skipped_op(
                self.builder_tag.clone(),
                op_hash,
                SkipReason::InsufficientPreVerificationGas {
                    base_fee,
                    op_fees: GasFees {
                        max_fee_per_gas: op.uo.max_fee_per_gas(),
                        max_priority_fee_per_gas: op.uo.max_priority_fee_per_gas(),
                    },
                    required_pvg,
                    actual_pvg: op.uo.pre_verification_gas(),
                },
            ));
            return None;
        }

        // Check total gas cost and time for bundler sponsorship
        let mut sponsored_da_gas = 0;
        if let Some(bundler_sponsorship) = &op.perms.bundler_sponsorship {
            let gas_limit = op
                .uo
                .bundle_gas_limit(&self.settings.chain_spec, Some(bundle_size))
                + required_pvg; // PVG is added as part of the gas limit as this is part of the cost of sponsorship

            let total_gas_cost = U256::from(gas_limit) * U256::from(gas_price);
            if total_gas_cost > bundler_sponsorship.max_cost {
                self.emit(BuilderEvent::skipped_op(
                    self.builder_tag.clone(),
                    op_hash,
                    SkipReason::OverSponsorshipMaxCost {
                        max_cost: bundler_sponsorship.max_cost,
                        actual_cost: total_gas_cost,
                    },
                ));
                return None;
            }

            sponsored_da_gas = required_da_gas;
        }

        Some(PoolOperationWithSponsoredDAGas {
            op,
            sponsored_da_gas,
        })
    }

    // Simulate a single op. Returns None if the op should be skipped.
    //
    // Filters on any errors
    async fn simulate_op(
        &self,
        op: PoolOperationWithSponsoredDAGas,
        block_hash: B256,
    ) -> Option<(
        PoolOperationWithSponsoredDAGas,
        Result<SimulationResult, SimulationError>,
    )> {
        let _timer_guard = CustomTimerGuard::new(self.metrics.op_simulation_ms.clone());
        let op_hash = op.op.uo.hash();

        // Simulate
        let result = self
            .bundle_providers
            .simulator()
            .simulate_validation(
                op.op.uo.clone().into(),
                op.op.perms.trusted,
                block_hash,
                Some(op.op.expected_code_hash),
            )
            .await;
        let result = match result {
            Ok(success) => (op, Ok(success)),
            Err(error) => match error {
                SimulationError {
                    violation_error: ViolationError::Violations(_),
                    entity_infos: _,
                } => (op, Err(error)),
                SimulationError {
                    violation_error: ViolationError::Other(error),
                    entity_infos: _,
                } => {
                    self.emit(BuilderEvent::skipped_op(
                        self.builder_tag.clone(),
                        op_hash,
                        SkipReason::Other {
                            reason: Arc::new(format!("Failed to simulate op: {error:?}, skipping")),
                        },
                    ));
                    return None;
                }
            },
        };

        Some(result)
    }

    async fn assemble_context(
        &self,
        max_bundle_fee: U256,
        gas_price: u128,
        ops_with_simulations: Vec<(
            PoolOperationWithSponsoredDAGas,
            Result<SimulationResult, SimulationError>,
        )>,
        mut balances_by_paymaster: HashMap<Address, U256>,
    ) -> ProposalContext<<Self as BundleProposer>::UO> {
        if max_bundle_fee == U256::ZERO {
            warn!("Max bundle fee is zero, skipping bundle");
            return ProposalContext::<<Self as BundleProposer>::UO>::new();
        }
        let buffered_max_bundle_fee = max_bundle_fee
            * U256::from(100 - BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT * 2) // slight over-buffer to account for miscalculations
            / U256::from(100);

        let all_sender_addresses: HashSet<Address> = ops_with_simulations
            .iter()
            .map(|(op, _)| op.op.uo.sender())
            .collect();
        let mut context = ProposalContext::<<Self as BundleProposer>::UO>::new();
        let mut paymasters_to_reject = Vec::<EntityInfo>::new();
        let mut passed_target = false;

        for (po, simulation) in ops_with_simulations {
            // first process any possible rejections
            let op = po.op.clone().uo;
            let simulation = match simulation {
                Ok(simulation) => simulation,
                Err(error) => {
                    self.emit(BuilderEvent::rejected_op(
                        self.builder_tag.clone(),
                        op.hash(),
                        OpRejectionReason::FailedRevalidation {
                            error: error.clone(),
                        },
                    ));
                    if let SimulationError {
                        violation_error: ViolationError::Violations(violations),
                        entity_infos,
                    } = error
                    {
                        // try to use EntityInfos from the latest simulation, but if it doesn't exist use the EntityInfos from the previous simulation
                        let infos = entity_infos.map_or(po.op.entity_infos, |e| e);
                        context.process_simulation_violations(op.into(), violations, infos);
                    }
                    continue;
                }
            };

            // filter time range
            if !simulation
                .valid_time_range
                .contains(Timestamp::now(), TIME_RANGE_BUFFER)
            {
                self.emit(BuilderEvent::rejected_op(
                    self.builder_tag.clone(),
                    op.hash(),
                    OpRejectionReason::InvalidTimeRange {
                        valid_range: simulation.valid_time_range,
                    },
                ));
                context.rejected_ops.push((op.into(), po.op.entity_infos));
                continue;
            } else if let Some(bundler_sponsorship) = &po.op.perms.bundler_sponsorship {
                let valid_time_range =
                    ValidTimeRange::from_genesis(bundler_sponsorship.valid_until.into());
                if !simulation
                    .valid_time_range
                    .contains(Timestamp::now(), TIME_RANGE_BUFFER)
                {
                    self.emit(BuilderEvent::rejected_op(
                        self.builder_tag.clone(),
                        op.hash(),
                        OpRejectionReason::InvalidTimeRange {
                            valid_range: valid_time_range,
                        },
                    ));
                    context.rejected_ops.push((op.into(), po.op.entity_infos));
                    continue;
                }
            }

            // if the bundle is at or past target, skip op and continue to finish processing any rejections
            if passed_target {
                self.emit(BuilderEvent::skipped_op(
                    self.builder_tag.clone(),
                    op.hash(),
                    SkipReason::TargetGasLimit,
                ));
                continue;
            }

            // Add op to candidate context
            let mut context_with_op = context.clone();
            context_with_op
                .groups_by_aggregator
                .entry(op.aggregator().unwrap_or(Address::ZERO))
                .or_default()
                .ops_with_simulations
                .push(OpWithSimulation {
                    op: op.clone().into(),
                    simulation: simulation.clone(),
                    sponsored_da_gas: po.sponsored_da_gas,
                });

            // Limit by max bundle computation gas (excluding DA gas)
            let bundle_computation_gas_limit =
                context_with_op.get_bundle_computation_gas_limit(&self.settings.chain_spec);
            if bundle_computation_gas_limit > self.settings.max_bundle_gas {
                self.emit(BuilderEvent::skipped_op(
                    self.builder_tag.clone(),
                    op.hash(),
                    SkipReason::MaxGasLimit,
                ));
                continue;
            }

            // Limit by max bundle fee
            let total_gas_cost =
                context_with_op.get_bundle_cost(&self.settings.chain_spec, gas_price);
            if total_gas_cost > buffered_max_bundle_fee {
                self.emit(BuilderEvent::skipped_op(
                    self.builder_tag.clone(),
                    op.hash(),
                    SkipReason::OverMaxBundleFee,
                ));
                continue;
            }

            // Limit by transaction size
            let bundle_transaction_size =
                context_with_op.get_bundle_transaction_size(&self.settings.chain_spec);
            if bundle_transaction_size
                >= self.settings.chain_spec.max_transaction_size_bytes as u128
            {
                self.emit(BuilderEvent::skipped_op(
                    self.builder_tag.clone(),
                    op.hash(),
                    SkipReason::TransactionSizeLimit,
                ));
                continue;
            }

            // Merge the expected storage and skip if there is a conflict or if the storage is over max
            if let Err(e) = context
                .bundle_expected_storage
                .add(&simulation.expected_storage)
            {
                self.emit(BuilderEvent::skipped_op(
                    self.builder_tag.clone(),
                    op.hash(),
                    SkipReason::ExpectedStorageConflict(e.to_string()),
                ));
                continue;
            } else if context.bundle_expected_storage.inner.num_slots()
                > self.settings.max_expected_storage_slots
            {
                self.emit(BuilderEvent::skipped_op(
                    self.builder_tag.clone(),
                    op.hash(),
                    SkipReason::ExpectedStorageLimit,
                ));
                continue;
            }

            if let Some(&other_sender) = simulation
                .accessed_addresses
                .iter()
                .find(|&address| *address != op.sender() && all_sender_addresses.contains(address))
            {
                // Exclude ops that access the sender of another op in the
                // batch, but don't reject them (remove them from pool).
                info!("Excluding op from {:?} because it accessed the address of another sender in the bundle.", op.sender());
                self.emit(BuilderEvent::skipped_op(
                    self.builder_tag.clone(),
                    op.hash(),
                    SkipReason::AccessedOtherSender { other_sender },
                ));
                continue;
            }

            if let Some(paymaster) = op.paymaster() {
                let Some(balance) = balances_by_paymaster.get_mut(&paymaster) else {
                    error!("Op had paymaster with unknown balance, but balances should have been loaded for all paymasters in bundle.");
                    continue;
                };
                let max_cost = op.max_gas_cost();
                if *balance < max_cost {
                    info!("Rejected paymaster {paymaster:?} because its balance {balance:?} was too low.");
                    paymasters_to_reject.push(po.op.entity_infos.paymaster.unwrap());
                    continue;
                } else {
                    *balance -= max_cost;
                }
            }

            // check if we've passed the computation target
            if bundle_computation_gas_limit >= self.settings.target_bundle_gas {
                passed_target = true;
            }

            // add the op to the context
            context
                .groups_by_aggregator
                .entry(op.aggregator().unwrap_or(Address::ZERO))
                .or_default()
                .ops_with_simulations
                .push(OpWithSimulation {
                    op: op.into(),
                    simulation,
                    sponsored_da_gas: po.sponsored_da_gas,
                });
        }

        for paymaster in paymasters_to_reject {
            // No need to update aggregator signatures because we haven't computed them yet.
            let _ = context.reject_entity(paymaster.entity, paymaster.is_staked);
        }

        self.compute_all_aggregator_signatures(&mut context).await;

        context
    }

    async fn check_conditions_met(
        &self,
        context: &mut ProposalContext<<Self as BundleProposer>::UO>,
    ) -> anyhow::Result<()> {
        let futs = context
            .iter_ops_with_simulations()
            .enumerate()
            .map(|(i, op)| async move {
                self.check_op_conditions_met(&op.simulation.expected_storage)
                    .await
                    .map(|reason| (i, reason))
            })
            .collect::<Vec<_>>();

        let to_reject = future::join_all(futs).await.into_iter().flatten();

        for (index, reason) in to_reject {
            self.emit(BuilderEvent::rejected_op(
                self.builder_tag.clone(),
                context.get_op_at(index)?.op.hash(),
                OpRejectionReason::ConditionNotMet(reason),
            ));
            self.reject_index(context, index, false).await;
        }

        Ok(())
    }

    async fn check_op_conditions_met(
        &self,
        expected_storage: &ExpectedStorage,
    ) -> Option<ConditionNotMetReason> {
        let futs = expected_storage
            .0
            .iter()
            .map(|(address, slots)| async move {
                let storage = match self
                    .ep_providers
                    .evm()
                    .batch_get_storage_at(*address, slots.keys().copied().collect())
                    .await
                {
                    Ok(storage) => storage,
                    Err(e) => {
                        error!("Error getting storage for address {address:?} failing open: {e:?}");
                        return None;
                    }
                };

                for ((slot, expected), actual) in slots.iter().zip(storage) {
                    if *expected != actual {
                        return Some(ConditionNotMetReason {
                            address: *address,
                            slot: *slot,
                            expected: *expected,
                            actual,
                        });
                    }
                }
                None
            });

        let results = future::join_all(futs).await;
        for result in results {
            if result.is_some() {
                return result;
            }
        }
        None
    }

    async fn reject_bundle(&self, context: &mut ProposalContext<<Self as BundleProposer>::UO>) {
        context.reject_all();
    }

    async fn reject_hash(
        &self,
        context: &mut ProposalContext<<Self as BundleProposer>::UO>,
        hash: B256,
    ) -> bool {
        let Some(index) = context.get_op_index(hash) else {
            return false;
        };

        self.reject_index(context, index, false).await;
        true
    }

    async fn reject_index(
        &self,
        context: &mut ProposalContext<<Self as BundleProposer>::UO>,
        i: usize,
        paymaster_amendment: bool,
    ) {
        let changed_aggregator = context.reject_index(i, paymaster_amendment);
        self.compute_aggregator_signatures(context, &changed_aggregator)
            .await;
    }

    async fn reject_entity(
        &self,
        context: &mut ProposalContext<<Self as BundleProposer>::UO>,
        entity: Entity,
        is_staked: bool,
    ) {
        let changed_aggregators = context.reject_entity(entity, is_staked);
        self.compute_aggregator_signatures(context, &changed_aggregators)
            .await;
    }

    async fn compute_all_aggregator_signatures(
        &self,
        context: &mut ProposalContext<<Self as BundleProposer>::UO>,
    ) {
        let aggregators: Vec<_> = context.groups_by_aggregator.keys().copied().collect();
        self.compute_aggregator_signatures(context, &aggregators)
            .await;
    }

    async fn compute_aggregator_signatures<'a>(
        &self,
        context: &mut ProposalContext<<Self as BundleProposer>::UO>,
        aggregators: impl IntoIterator<Item = &'a Address>,
    ) {
        let signature_futures = aggregators.into_iter().filter_map(|&aggregator| {
            if aggregator.is_zero() {
                return None;
            }

            context
                .groups_by_aggregator
                .get(&aggregator)
                .map(|group| self.aggregate_signatures(aggregator, group))
        });
        let signatures = future::join_all(signature_futures).await;
        for (aggregator, result) in signatures {
            context.apply_aggregation_signature_result(aggregator, result);
        }
    }

    /// Estimates the gas needed to send this bundle. If successful, returns the
    /// amount of gas, but if not then mutates the context to remove whichever
    /// op(s) caused the failure.
    async fn estimate_gas_rejecting_failed_ops(
        &self,
        context: &mut ProposalContext<<Self as BundleProposer>::UO>,
        bundle_fees: GasFees,
    ) -> BundleProposerResult<Option<u64>> {
        // sum up the gas needed for all the ops in the bundle
        // and apply an overhead multiplier
        let gas = math::increase_by_percent(
            context.get_bundle_gas_limit(&self.settings.chain_spec),
            BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT,
        );

        let gas_limit: u64 = gas
            .try_into()
            .context("estimated bundle gas limit is larger than u64::MAX")?;

        // if EP v0.7+ and only 1 op, skip this call as simulation has already run a similar check
        // v0.6 cannot do this as we need to check for postOp reverts
        if self.ep_providers.entry_point().version() != EntryPointVersion::V0_6
            && context.iter_ops().count() == 1
        {
            return Ok(Some(gas_limit));
        }

        // validate the bundle to filter any rejected ops before sending
        let start = Instant::now();
        // if not using a proxy, and using v0.7+, we can only run validation and skip execution
        let validation_only = self.settings.submission_proxy.is_none()
            && self.ep_providers.entry_point().version() != EntryPointVersion::V0_6;

        let handle_ops_out = self
            .ep_providers
            .entry_point()
            .call_handle_ops(
                context.to_ops_per_aggregator(),
                self.settings.sender_eoa,
                gas_limit,
                bundle_fees,
                self.settings.submission_proxy.as_ref().map(|p| p.address()),
                validation_only,
            )
            .await
            .context("should call handle ops with candidate bundle")?;
        self.metrics
            .bundle_simulation_ms
            .record(start.elapsed().as_millis() as f64);

        match handle_ops_out {
            HandleOpsOut::Success => Ok(Some(gas_limit)),
            HandleOpsOut::FailedOp(index, message) => {
                self.emit(BuilderEvent::rejected_op(
                    self.builder_tag.clone(),
                    context.get_op_at(index)?.op.hash(),
                    OpRejectionReason::FailedInBundle {
                        message: Arc::new(message.clone()),
                    },
                ));
                self.process_failed_op(context, index, message).await?;
                Ok(None)
            }
            HandleOpsOut::SignatureValidationFailed(aggregator) => {
                info!("Rejected aggregator {aggregator:?} because its signature validation failed during gas estimation.");
                self.reject_entity(context, Entity::aggregator(aggregator), true)
                    .await;
                Ok(None)
            }
            HandleOpsOut::PostOpRevert => {
                warn!("PostOpShortRevert error during gas estimation due to bug in the 0.6 entry point contract. Removing the offending op from the bundle.");
                self.process_post_op_revert(context, gas_limit, bundle_fees)
                    .await?;
                Ok(None)
            }
            HandleOpsOut::Revert(revert_data) => {
                // Process the revert.
                // If we can't identify the offending op, reject the full bundle to avoid infinite failure loops.

                if let Some(proxy) = self.settings.submission_proxy.as_ref() {
                    let ops = context
                        .to_ops_per_aggregator()
                        .into_iter()
                        .map(|uo| uo.into_uo_variants())
                        .collect::<Vec<_>>();
                    let to_remove = proxy.process_revert(&revert_data, &ops).await;
                    let mut removed = false;
                    for hash in to_remove {
                        removed |= self.reject_hash(context, hash).await;
                    }

                    if !removed {
                        warn!("HandleOps reverted during gas estimation, proxy {proxy:?} returned no hashes to remove. Rejecting full bundle. revert data: {revert_data:?}");
                        self.reject_bundle(context).await;
                    }
                } else {
                    warn!(
                        "HandleOps reverted during gas estimation. Rejecting full bundle. revert data: {revert_data:?}"
                    );
                    self.reject_bundle(context).await;
                }

                Ok(None)
            }
        }
    }

    async fn get_balances_by_paymaster(
        &self,
        addresses: impl IntoIterator<Item = Address>,
        block_hash: B256,
    ) -> BundleProposerResult<HashMap<Address, U256>> {
        let futures = addresses.into_iter().map(|address| async move {
            let deposit = self
                .ep_providers
                .entry_point()
                .balance_of(address, Some(block_hash.into()))
                .await?;
            Ok::<_, anyhow::Error>((address, deposit))
        });
        let addresses_and_deposits = future::try_join_all(futures)
            .await
            .context("entry point should return deposits for paymasters")?;
        Ok(HashMap::from_iter(addresses_and_deposits))
    }

    async fn aggregate_signatures(
        &self,
        aggregator: Address,
        group: &AggregatorGroup<<Self as BundleProposer>::UO>,
    ) -> (Address, SignatureAggregatorResult<Bytes>) {
        let Some(agg) = self
            .settings
            .chain_spec
            .get_signature_aggregator(&aggregator)
        else {
            // this should be checked prior to calling this function
            panic!("BUG: aggregator {aggregator:?} not found in chain spec");
        };

        let uos = group
            .ops_with_simulations
            .iter()
            // Mempool ops are transformed during insertion - use the original signature to aggregate
            .map(|op| op.op.clone().with_original_signature().into())
            .collect::<Vec<_>>();

        let aggregated = match agg.aggregate_signatures(uos).await {
            Ok(aggregated) => aggregated,
            Err(e) => {
                return (aggregator, Err(e));
            }
        };

        (aggregator, Ok(aggregated))
    }

    async fn process_failed_op(
        &self,
        context: &mut ProposalContext<<Self as BundleProposer>::UO>,
        index: usize,
        message: String,
    ) -> anyhow::Result<()> {
        match &message[..4] {
            // Entrypoint error codes that we want to reject the factory for.
            // AA10 is an internal error and is ignored
            "AA13" | "AA14" | "AA15" => {
                let op_with_sim = context.get_op_at(index)?;
                let factory = op_with_sim.op.factory().context("op failed during gas estimation with factory error, but did not include a factory")?;
                info!("Rejected op because it failed during gas estimation with factory {factory:?} error {message}.");
                self.reject_entity(
                    context,
                    Entity::factory(factory),
                    op_with_sim
                        .simulation
                        .entity_infos
                        .factory
                        .is_some_and(|f| f.is_staked),
                )
                .await;
            }
            // Entrypoint error codes that we want to reject the paymaster for.
            // Note: AA32 is not included as this is a time expiry error.
            "AA30" | "AA31" | "AA33" | "AA34" => {
                let op_with_sim = context.get_op_at(index)?;
                let paymaster = op_with_sim.op.paymaster().context(
                    "op failed during gas estimation with {message}, but had no paymaster",
                )?;
                info!("Rejected op because it failed during gas estimation with a paymaster {paymaster:?} error {message}.");
                self.reject_entity(
                    context,
                    Entity::paymaster(paymaster),
                    op_with_sim
                        .simulation
                        .entity_infos
                        .paymaster
                        .is_some_and(|p| p.is_staked),
                )
                .await;
            }
            _ => {
                info!(
                    "Rejected op because it failed during gas estimation with message {message}."
                );
                self.reject_index(context, index, true).await;
                return Ok(());
            }
        };

        Ok(())
    }

    // This function is called when a postOpRevert error is encountered during gas estimation.
    // This is due to a bug in the 0.6 entry point and needs to be handled else the bundle transaction will revert on chain.
    //
    // This function attempts to remove any offending user ops. If it can't identify the offending user ops, it will remove all user ops
    // from the bundle and from the pool.
    async fn process_post_op_revert(
        &self,
        context: &mut ProposalContext<<Self as BundleProposer>::UO>,
        gas_limit: u64,
        bundle_fees: GasFees,
    ) -> anyhow::Result<()> {
        let agg_groups = context.to_ops_per_aggregator();
        let mut op_index = 0;
        let mut futures: Vec<Pin<Box<dyn Future<Output = Vec<usize>> + Send>>> = vec![];

        for agg_group in agg_groups {
            // For non-aggregated ops, re-simulate each op individually
            if agg_group.aggregator.is_zero() {
                for op in agg_group.user_ops {
                    futures.push(Box::pin(self.check_for_post_op_revert_single_op(
                        op,
                        op_index,
                        gas_limit,
                        bundle_fees,
                    )));
                    op_index += 1;
                }
            } else {
                // For aggregated ops, re-simulate the group
                let len = agg_group.user_ops.len();
                futures.push(Box::pin(self.check_for_post_op_revert_agg_ops(
                    agg_group,
                    op_index,
                    gas_limit,
                    bundle_fees,
                )));
                op_index += len;
            }
        }

        let results = future::join_all(futures).await;
        let mut to_remove = results.into_iter().flatten().collect::<Vec<_>>();
        if to_remove.is_empty() {
            // if we can't identify the offending user ops, remove all user ops from the bundle and from the pool
            error!(
                "Failed to identify offending user ops, removing all user ops from bundle and pool"
            );
            to_remove.extend(0..op_index);
        }

        // iterate in reverse so that we can remove ops without affecting the index of the next op to remove
        for index in to_remove.into_iter().rev() {
            self.emit(BuilderEvent::rejected_op(
                self.builder_tag.clone(),
                context.get_op_at(index)?.op.hash(),
                OpRejectionReason::FailedInBundle {
                    message: Arc::new("post op reverted leading to entry point revert".to_owned()),
                },
            ));
            self.reject_index(context, index, true).await;
        }

        Ok(())
    }

    async fn check_for_post_op_revert_single_op(
        &self,
        op: <Self as BundleProposer>::UO,
        op_index: usize,
        gas_limit: u64,
        bundle_fees: GasFees,
    ) -> Vec<usize> {
        let op_hash = op.hash();
        let bundle = vec![UserOpsPerAggregator {
            aggregator: Address::ZERO,
            signature: Bytes::new(),
            user_ops: vec![op],
        }];
        let ret = self
            .ep_providers
            .entry_point()
            .call_handle_ops(
                bundle,
                self.settings.sender_eoa,
                gas_limit,
                bundle_fees,
                self.settings.submission_proxy.as_ref().map(|p| p.address()),
                false,
            )
            .await;
        match ret {
            Ok(out) => {
                if let HandleOpsOut::PostOpRevert = out {
                    warn!(
                        "PostOpRevert error found, removing {:?} from bundle",
                        op_hash
                    );
                    vec![op_index]
                } else {
                    vec![]
                }
            }
            Err(e) => {
                // If we get an error here, we can't be sure if the op is the offending op or not, so we remove it to be safe
                error!("Failed to call handle ops: {e} during postOpRevert handling, removing op");
                vec![op_index]
            }
        }
    }

    async fn check_for_post_op_revert_agg_ops(
        &self,
        group: UserOpsPerAggregator<<Self as BundleProposer>::UO>,
        start_index: usize,
        gas_limit: u64,
        bundle_fees: GasFees,
    ) -> Vec<usize> {
        let len = group.user_ops.len();
        let agg = group.aggregator;
        let bundle = vec![group];
        let ret = self
            .ep_providers
            .entry_point()
            .call_handle_ops(
                bundle,
                self.settings.sender_eoa,
                gas_limit,
                bundle_fees,
                self.settings.submission_proxy.as_ref().map(|p| p.address()),
                false,
            )
            .await;
        match ret {
            Ok(out) => {
                if let HandleOpsOut::PostOpRevert = out {
                    warn!(
                        "PostOpRevert error found, removing all ops with aggregator {:?}",
                        agg
                    );
                    (start_index..start_index + len).collect()
                } else {
                    vec![]
                }
            }
            Err(e) => {
                // If we get an error here, we can't be sure if the op is the offending op or not, so we remove it to be safe
                error!("Failed to call handle ops: {e} during postOpRevert handling, removing all ops from aggregator {:?}", agg);
                (start_index..start_index + len).collect()
            }
        }
    }

    fn limit_user_operations_for_simulation(
        &self,
        ops: Vec<PoolOperationWithSponsoredDAGas>,
    ) -> (Vec<PoolOperationWithSponsoredDAGas>, u128) {
        let mut gas_left = self.settings.max_bundle_gas;
        let mut ops_in_bundle = Vec::new();
        for op in ops {
            // if the op has an aggregator, check if the aggregator is supported, if not skip
            if let Some(agg) = op.op.uo.aggregator() {
                if self
                    .settings
                    .chain_spec
                    .get_signature_aggregator(&agg)
                    .is_none()
                {
                    self.emit(BuilderEvent::skipped_op(
                        self.builder_tag.clone(),
                        op.op.uo.hash(),
                        SkipReason::UnsupportedAggregator(agg),
                    ));
                    continue;
                }
            }

            // Here we use optimistic gas limits for the UOs by assuming none of the paymaster UOs use postOp calls.
            // This way after simulation once we have determined if each UO actually uses a postOp call or not we can still pack a full bundle
            let gas = op
                .op
                .uo
                .bundle_computation_gas_limit(&self.settings.chain_spec, None);
            if gas_left < gas {
                self.emit(BuilderEvent::skipped_op(
                    self.builder_tag.clone(),
                    op.op.uo.hash(),
                    SkipReason::SimulationGasLimit,
                ));
                continue;
            }
            gas_left -= gas;
            ops_in_bundle.push(op);
        }
        (
            ops_in_bundle,
            self.settings.max_bundle_gas.saturating_sub(gas_left),
        )
    }

    fn emit(&self, event: BuilderEvent) {
        let _ = self.event_sender.send(WithEntryPoint {
            entry_point: *self.ep_providers.entry_point().address(),
            event,
        });
    }
}

// Type erasure for the bundle proposer providers
pub(crate) trait BundleProposerProvidersT: Send + Sync {
    type UO: UserOperation + From<UserOperationVariant>;
    type Simulator: Simulator<UO = Self::UO>;

    fn simulator(&self) -> &Self::Simulator;
}

pub(crate) struct BundleProposerProviders<S> {
    simulator: S,
}

impl<S> BundleProposerProviders<S> {
    pub(crate) fn new(simulator: S) -> Self {
        Self { simulator }
    }
}

impl<S> BundleProposerProvidersT for BundleProposerProviders<S>
where
    S: Simulator,
    S::UO: UserOperation + From<UserOperationVariant>,
{
    type UO = S::UO;
    type Simulator = S;

    fn simulator(&self) -> &Self::Simulator {
        &self.simulator
    }
}

#[derive(Debug)]
struct PoolOperationWithSponsoredDAGas {
    op: PoolOperation,
    sponsored_da_gas: u128,
}

#[derive(Debug, Clone)]
struct OpWithSimulation<UO> {
    op: UO,
    simulation: SimulationResult,
    sponsored_da_gas: u128,
}

/// A struct used internally to represent the current state of a proposed bundle
/// as it goes through iterations. Contains similar data to the
/// `Vec<UserOpsPerAggregator>` that will eventually be passed to the entry
/// point, but contains extra context needed for the computation.
#[derive(Debug, Clone)]
struct ProposalContext<UO> {
    groups_by_aggregator: LinkedHashMap<Address, AggregatorGroup<UO>>,
    rejected_ops: Vec<(UO, EntityInfos)>,
    // This is a BTreeMap so that the conversion to a Vec<EntityUpdate> is deterministic, mainly for tests
    entity_updates: BTreeMap<Address, EntityUpdate>,
    bundle_expected_storage: BundleExpectedStorage,
}

#[derive(Debug, Clone)]
struct AggregatorGroup<UO> {
    ops_with_simulations: Vec<OpWithSimulation<UO>>,
    signature: Bytes,
}

impl<UO> Default for AggregatorGroup<UO> {
    fn default() -> Self {
        Self {
            ops_with_simulations: Vec::new(),
            signature: Bytes::new(),
        }
    }
}

impl<UO: UserOperation> ProposalContext<UO> {
    fn new() -> Self {
        Self {
            groups_by_aggregator: LinkedHashMap::<Address, AggregatorGroup<UO>>::new(),
            rejected_ops: Vec::<(UO, EntityInfos)>::new(),
            entity_updates: BTreeMap::new(),
            bundle_expected_storage: BundleExpectedStorage::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.groups_by_aggregator.is_empty()
    }

    fn apply_aggregation_signature_result(
        &mut self,
        aggregator: Address,
        result: SignatureAggregatorResult<Bytes>,
    ) {
        match result {
            Ok(sig) => self.groups_by_aggregator[&aggregator].signature = sig,
            Err(error) => {
                error!("Failed to compute aggregator signature, rejecting aggregator {aggregator:?}: {error}");
                self.reject_aggregator(aggregator);
            }
        }
    }

    fn get_op_at(&self, index: usize) -> anyhow::Result<&OpWithSimulation<UO>> {
        let mut remaining_i = index;
        for group in self.groups_by_aggregator.values() {
            if remaining_i < group.ops_with_simulations.len() {
                return Ok(&group.ops_with_simulations[remaining_i]);
            }
            remaining_i -= group.ops_with_simulations.len();
        }
        anyhow::bail!("op at {index} out of bounds")
    }

    fn get_op_index(&self, hash: B256) -> Option<usize> {
        self.iter_ops_with_simulations()
            .position(|op| op.op.hash() == *hash)
    }

    fn reject_all(&mut self) {
        for _ in 0..self.iter_ops_with_simulations().count() {
            let _ = self.reject_index(0, true);
        }
    }

    /// Returns the address of the op's aggregator if the aggregator's signature
    /// may need to be recomputed.
    #[must_use = "rejected op but did not update aggregator signatures"]
    fn reject_index(&mut self, i: usize, paymaster_amendment: bool) -> Option<Address> {
        let mut remaining_i = i;
        let mut found_aggregator: Option<Address> = None;
        for (&aggregator, group) in &mut self.groups_by_aggregator {
            if remaining_i < group.ops_with_simulations.len() {
                let rejected = group.ops_with_simulations.remove(remaining_i);
                self.reject_op(rejected, paymaster_amendment);
                found_aggregator = Some(aggregator);
                break;
            }
            remaining_i -= group.ops_with_simulations.len();
        }
        let Some(found_aggregator) = found_aggregator else {
            error!("The entry point indicated a failed op at index {i}, but the bundle size is only {}", i - remaining_i);
            return None;
        };
        // If we just removed the last op from a group, delete that group.
        // Otherwise, the signature is invalidated and we need to recompute it.
        if self.groups_by_aggregator[&found_aggregator]
            .ops_with_simulations
            .is_empty()
        {
            self.groups_by_aggregator.remove(&found_aggregator);
            None
        } else {
            Some(found_aggregator)
        }
    }

    /// Returns the addresses of any aggregators whose signature may need to be recomputed.
    #[must_use = "rejected entity but did not update aggregator signatures"]
    fn reject_entity(&mut self, entity: Entity, is_staked: bool) -> Vec<Address> {
        let ret = match entity.kind {
            EntityType::Paymaster => self.reject_paymaster(entity.address),
            EntityType::Factory => self.reject_factory(entity.address),
            EntityType::Account => self.reject_sender(entity.address),
            EntityType::Aggregator => self.reject_aggregator(entity.address),
        };
        self.entity_updates.insert(
            entity.address,
            EntityUpdate {
                entity,
                update_type: if is_staked {
                    EntityUpdateType::StakedInvalidation
                } else {
                    EntityUpdateType::UnstakedInvalidation
                },
                ..Default::default()
            },
        );
        ret
    }

    fn reject_paymaster(&mut self, address: Address) -> Vec<Address> {
        self.filter_reject(false, |op| op.paymaster() == Some(address))
    }

    // In accordance with [EREP-015]/[EREP-020]/[EREP-030], responsibility for failures lies with the factory or account.
    // Paymasters should not be held accountable, so the paymaster's `opsSeen` count should be decremented accordingly.
    // Paymaster amendment is required for all other entities rejections.
    fn reject_factory(&mut self, address: Address) -> Vec<Address> {
        self.filter_reject(true, |op| op.factory() == Some(address))
    }

    fn reject_sender(&mut self, address: Address) -> Vec<Address> {
        self.filter_reject(true, |op| op.sender() == address)
    }

    fn reject_aggregator(&mut self, address: Address) -> Vec<Address> {
        self.filter_reject(true, |op| op.aggregator() == Some(address))
    }

    /// Reject all ops that match the filter, and return the addresses of any aggregators
    /// whose signature may need to be recomputed.
    fn filter_reject(
        &mut self,
        paymaster_amendment: bool,
        filter: impl Fn(&UO) -> bool,
    ) -> Vec<Address> {
        let mut changed_aggregators: Vec<Address> = vec![];
        let mut aggregators_to_remove: Vec<Address> = vec![];
        let mut new_groups = LinkedHashMap::new();
        let old_groups = mem::take(&mut self.groups_by_aggregator);

        for (aggregator, group) in old_groups {
            let group_uses_rejected_entity =
                group.ops_with_simulations.iter().any(|op| filter(&op.op));

            if group_uses_rejected_entity {
                let mut new_group = AggregatorGroup::default();
                for op in group.ops_with_simulations {
                    if !filter(&op.op) {
                        new_group.ops_with_simulations.push(op);
                    } else {
                        self.reject_op(op, paymaster_amendment);
                    }
                }
                if new_group.ops_with_simulations.is_empty() {
                    aggregators_to_remove.push(aggregator);
                } else {
                    new_groups.insert(aggregator, new_group);

                    if aggregator.is_zero() {
                        changed_aggregators.push(aggregator);
                    }
                }
            } else {
                new_groups.insert(aggregator, group);
            }
        }
        for aggregator in aggregators_to_remove {
            self.groups_by_aggregator.remove(&aggregator);
        }
        self.groups_by_aggregator = new_groups;
        changed_aggregators
    }

    fn reject_op(&mut self, rejected: OpWithSimulation<UO>, paymaster_amendment: bool) {
        if paymaster_amendment {
            if let Some(paymaster) = rejected.op.paymaster() {
                self.add_erep_015_paymaster_amendment(paymaster, 1);
            }
        }
        self.rejected_ops
            .push((rejected.op, rejected.simulation.entity_infos));

        // remove associated storage slots
        self.bundle_expected_storage
            .remove(&rejected.simulation.expected_storage);
    }

    fn to_ops_per_aggregator(&self) -> Vec<UserOpsPerAggregator<UO>> {
        self.groups_by_aggregator
            .iter()
            .map(|(&aggregator, group)| UserOpsPerAggregator {
                user_ops: group
                    .ops_with_simulations
                    .iter()
                    .map(|op| op.op.clone())
                    .collect(),
                aggregator,
                signature: group.signature.clone(),
            })
            .collect()
    }

    fn get_bundle_transaction_size(&self, chain_spec: &ChainSpec) -> u128 {
        self.bundle_overhead_bytes(chain_spec)
            + self
                .iter_ops_with_simulations()
                .map(|sim_op| sim_op.op.abi_encoded_size() as u128)
                .sum::<u128>()
    }

    // Get the computation gas limit in the bundle
    fn get_bundle_computation_gas_limit(&self, chain_spec: &ChainSpec) -> u128 {
        self.get_bundle_gas_limit_inner(chain_spec, false)
    }

    // Get the total gas in the bundle
    fn get_bundle_cost(&self, chain_spec: &ChainSpec, gas_price: u128) -> U256 {
        U256::from(self.get_bundle_gas_limit_inner(chain_spec, true)) * U256::from(gas_price)
    }

    // Get the bundle gas limit
    fn get_bundle_gas_limit(&self, chain_spec: &ChainSpec) -> u128 {
        self.get_bundle_gas_limit_inner(chain_spec, chain_spec.include_da_gas_in_gas_limit)
    }

    fn bundle_overhead_bytes(&self, chain_spec: &ChainSpec) -> u128 {
        let mut bundle_overhead_bytes = BUNDLE_BYTE_OVERHEAD as u128;

        if self.groups_by_aggregator.len() == 1
            && self.groups_by_aggregator.keys().next().unwrap().is_zero()
        {
            // handleOps case
            bundle_overhead_bytes += 32
                * self
                    .groups_by_aggregator
                    .values()
                    .next()
                    .unwrap()
                    .ops_with_simulations
                    .len() as u128;
        } else {
            // handleAggregatedOps case
            for (agg, group) in &self.groups_by_aggregator {
                // Size of `UserOpsPerAggregator` (without op data and signature) is 96 bytes + 32 bytes per op
                bundle_overhead_bytes += 96 + 32 * group.ops_with_simulations.len() as u128;

                if agg.is_zero() {
                    continue;
                }
                let Some(agg) = chain_spec.get_signature_aggregator(agg) else {
                    // this should be checked prior to calling this function
                    panic!("BUG: aggregator {agg:?} not found in chain spec");
                };
                bundle_overhead_bytes += agg.costs().sig_fixed_length
                    + agg.costs().sig_variable_length * group.ops_with_simulations.len() as u128;
            }
        }

        bundle_overhead_bytes
    }

    fn get_bundle_gas_limit_inner(&self, chain_spec: &ChainSpec, include_da_gas: bool) -> u128 {
        let mut gas_limit = rundler_types::bundle_shared_gas(chain_spec);

        // Per aggregator fixed gas
        for agg in self.groups_by_aggregator.keys() {
            if agg.is_zero() {
                continue;
            }
            let Some(agg) = chain_spec.get_signature_aggregator(agg) else {
                // this should be checked prior to calling this function
                panic!("BUG: aggregator {agg:?} not found in chain spec");
            };
            gas_limit += agg.costs().execution_fixed_gas;

            // NOTE: this assumes that the DA cost for the aggregated signature is covered by the gas limits
            // from the UOs (on chains that have DA gas in gas limit). This is enforced during fee check phase.
        }

        // per UO gas, bundle_size == None to signal to exclude shared gas
        gas_limit += self
            .iter_ops_with_simulations()
            .map(|sim_op| {
                if include_da_gas {
                    sim_op.op.bundle_gas_limit(chain_spec, None) + sim_op.sponsored_da_gas
                } else {
                    sim_op.op.bundle_computation_gas_limit(chain_spec, None)
                }
            })
            .sum::<u128>();

        let calldata_floor_gas_limit = self.bundle_overhead_bytes(chain_spec)
            * chain_spec.calldata_floor_non_zero_byte_gas()
            + self
                .iter_ops_with_simulations()
                .map(|sim_op| sim_op.op.calldata_floor_gas_limit())
                .sum::<u128>();

        if calldata_floor_gas_limit > gas_limit {
            return calldata_floor_gas_limit;
        }

        gas_limit
    }

    fn iter_ops_with_simulations(&self) -> impl Iterator<Item = &OpWithSimulation<UO>> + '_ {
        self.groups_by_aggregator
            .values()
            .flat_map(|group| &group.ops_with_simulations)
    }

    fn iter_ops(&self) -> impl Iterator<Item = &UO> + '_ {
        self.iter_ops_with_simulations().map(|op| &op.op)
    }

    // Go through the simulation violations for a given op and add all entity updates to pass to the mempool in entity_updates
    fn process_simulation_violations(
        &mut self,
        op: UO,
        violations: Vec<SimulationViolation>,
        entity_infos: EntityInfos,
    ) {
        self.rejected_ops.push((op, entity_infos));

        // If a staked factory or sender is present, we attribute errors to them directly.

        // In accordance with [EREP-015]/[EREP-020]/[EREP-030], responsibility for failures lies with the staked factory or account.
        // Paymasters should not be held accountable, so the paymaster's `opsSeen` count should be decremented accordingly.
        let is_staked_factory = entity_infos.factory.is_some_and(|f| f.is_staked);
        let is_staked_sender = entity_infos.sender.is_staked;
        if is_staked_factory || is_staked_sender {
            if let Some(paymaster) = entity_infos.paymaster {
                self.add_erep_015_paymaster_amendment(paymaster.address(), 1)
            }
        }

        // [EREP-020] When there is a staked factory any error in validation is attributed to it.
        if is_staked_factory {
            let factory = entity_infos.factory.unwrap();
            self.entity_updates.insert(
                factory.address(),
                EntityUpdate {
                    entity: factory.entity,
                    update_type: EntityUpdateType::StakedInvalidation,
                    value: None,
                },
            );
            return;
        }

        // [EREP-030] When there is a staked sender (without a staked factory) any error in validation is attributed to it.
        if is_staked_sender {
            self.entity_updates.insert(
                entity_infos.sender.address(),
                EntityUpdate {
                    entity: entity_infos.sender.entity,
                    update_type: EntityUpdateType::StakedInvalidation,
                    value: None,
                },
            );
            return;
        }

        // If not a staked factory or sender, attribute errors to each entity directly.
        // For a given op, there can only be a single update per entity so we don't double count the [UREP-030] throttle penalty.
        let mut paymaster_amendment_required = false;
        for violation in violations {
            match violation {
                SimulationViolation::UsedForbiddenOpcode(entity, _, _) => {
                    self.add_entity_update(entity, entity_infos)
                }
                SimulationViolation::UsedForbiddenPrecompile(entity, _, _) => {
                    self.add_entity_update(entity, entity_infos)
                }
                SimulationViolation::AccessedUndeployedContract(entity, _) => {
                    self.add_entity_update(entity, entity_infos)
                }
                SimulationViolation::InvalidStorageAccess(entity, _) => {
                    self.add_entity_update(entity, entity_infos)
                }
                SimulationViolation::CalledBannedEntryPointMethod(entity) => {
                    self.add_entity_update(entity, entity_infos)
                }
                SimulationViolation::CallHadValue(entity) => {
                    self.add_entity_update(entity, entity_infos)
                }
                SimulationViolation::NotStaked(stake_data) => {
                    self.add_entity_update(stake_data.needs_stake, entity_infos)
                }
                SimulationViolation::UnintendedRevertWithMessage(entity_type, message, address) => {
                    match &message[..4] {
                        // do not penalize an entity for invalid account nonces or already deployed senders,
                        // which can occur without malicious intent from the sender or factory
                        "AA10" | "AA25" => {}
                        _ => {
                            if let Some(entity_address) = address {
                                self.add_entity_update(
                                    Entity {
                                        kind: entity_type,
                                        address: entity_address,
                                    },
                                    entity_infos,
                                );
                            }
                        }
                    }
                }
                SimulationViolation::UnintendedRevert(entity_type, address) => {
                    if let Some(entity_address) = address {
                        self.add_entity_update(
                            Entity {
                                kind: entity_type,
                                address: entity_address,
                            },
                            entity_infos,
                        );
                    }
                }
                SimulationViolation::ValidationRevert(ValidationRevert::Operation {
                    entry_point_reason,
                    ..
                }) => {
                    // [EREP-015] If user operations error derived from factory or account, paymaster opsSeen amendment is required.
                    paymaster_amendment_required |=
                        matches!(&entry_point_reason[..3], "AA1" | "AA2");
                }
                SimulationViolation::OutOfGas(entity) => {
                    self.add_entity_update(entity, entity_infos)
                }
                _ => continue,
            }
        }

        if paymaster_amendment_required {
            if let Some(paymaster) = entity_infos.paymaster {
                self.add_erep_015_paymaster_amendment(paymaster.address(), 1)
            };
        }
    }

    // Add an entity update for the entity
    fn add_entity_update(&mut self, entity: Entity, entity_infos: EntityInfos) {
        let entity_update = EntityUpdate {
            entity,
            update_type: ProposalContext::<UO>::get_entity_update_type(entity.kind, entity_infos),
            value: None,
        };
        self.entity_updates.insert(entity.address, entity_update);
    }

    // For a given entity that has caused a revert during simulation, determine if the entity was staked or not.
    // If it is staked, we push a StakedInvalidation entity update to enforce [SREP-050]
    // If it is not staked, we push an UnstakedInvalidation entity update to enforce [UREP-030]
    fn get_entity_update_type(
        entity_type: EntityType,
        entity_infos: EntityInfos,
    ) -> EntityUpdateType {
        match entity_type {
            EntityType::Account => {
                if entity_infos.sender.is_staked {
                    EntityUpdateType::StakedInvalidation
                } else {
                    EntityUpdateType::UnstakedInvalidation
                }
            }
            EntityType::Paymaster => {
                if let Some(paymaster) = entity_infos.paymaster {
                    if paymaster.is_staked {
                        EntityUpdateType::StakedInvalidation
                    } else {
                        EntityUpdateType::UnstakedInvalidation
                    }
                } else {
                    EntityUpdateType::StakedInvalidation
                }
            }
            EntityType::Factory => {
                if let Some(factory) = entity_infos.factory {
                    if factory.is_staked {
                        EntityUpdateType::StakedInvalidation
                    } else {
                        EntityUpdateType::UnstakedInvalidation
                    }
                } else {
                    EntityUpdateType::StakedInvalidation
                }
            }
            EntityType::Aggregator => {
                if let Some(aggregator) = entity_infos.aggregator {
                    if aggregator.is_staked {
                        EntityUpdateType::StakedInvalidation
                    } else {
                        EntityUpdateType::UnstakedInvalidation
                    }
                } else {
                    EntityUpdateType::StakedInvalidation
                }
            }
        }
    }

    fn add_erep_015_paymaster_amendment(&mut self, address: Address, to_add: u64) {
        // Insert to entity_updates if entry is vacant, otherwise increment the value (precisely EntityUpdate.value)
        self.entity_updates
            .entry(address)
            .and_modify(|e| {
                if let Some(value) = &mut e.value {
                    *value += to_add;
                }
            })
            .or_insert_with(|| EntityUpdate {
                entity: Entity {
                    kind: EntityType::Paymaster,
                    address,
                },
                update_type: EntityUpdateType::PaymasterOpsSeenDecrement,
                value: Some(1),
            });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy_primitives::{utils::parse_units, Address, B256};
    use anyhow::anyhow;
    use rundler_provider::{
        MockDAGasOracleSync, MockEntryPointV0_6, MockEvmProvider, MockFeeEstimator,
        ProvidersWithEntryPoint,
    };
    use rundler_sim::MockSimulator;
    use rundler_types::{
        aggregator::{
            AggregatorCosts, MockSignatureAggregator, SignatureAggregator, SignatureAggregatorError,
        },
        chain::ContractRegistry,
        da::BedrockDAGasBlockData,
        pool::SimulationViolation,
        proxy::MockSubmissionProxy,
        v0_6::{UserOperation, UserOperationBuilder, UserOperationRequiredFields},
        BundlerSponsorship, UserOperation as _, UserOperationPermissions, ValidTimeRange,
    };

    use super::*;

    #[tokio::test]
    async fn test_singleton_valid_bundle() {
        let op = op_from_required(UserOperationRequiredFields {
            pre_verification_gas: DEFAULT_PVG,
            verification_gas_limit: 10000,
            call_gas_limit: 100000,
            ..Default::default()
        });

        let bundle = simple_make_bundle(vec![MockOp {
            op: op.clone(),
            simulation_result: Box::new(|| Ok(SimulationResult::default())),
            perms: UserOperationPermissions::default(),
        }])
        .await;

        let cs = ChainSpec::default();

        let expected_gas: u64 = math::increase_by_percent(
            op.bundle_gas_limit(&cs, Some(1)),
            BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT,
        )
        .try_into()
        .unwrap();

        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op],
                ..Default::default()
            }]
        );

        assert_eq!(bundle.gas_estimate, expected_gas);
    }

    #[tokio::test]
    async fn test_rejects_on_violation() {
        let op = default_op();
        let bundle = simple_make_bundle(vec![MockOp {
            op: op.clone(),
            simulation_result: Box::new(|| {
                Err(SimulationError {
                    violation_error: ViolationError::Violations(vec![]),
                    entity_infos: None,
                })
            }),
            perms: UserOperationPermissions::default(),
        }])
        .await;
        assert!(bundle.ops_per_aggregator.is_empty());
        assert_eq!(bundle.rejected_ops, vec![op]);
    }

    #[tokio::test]
    async fn test_drops_but_not_rejects_on_simulation_failure() {
        let op = default_op();
        let bundle = simple_make_bundle(vec![MockOp {
            op: op.clone(),
            simulation_result: Box::new(|| {
                Err(SimulationError {
                    violation_error: ViolationError::Other(anyhow!("simulation failed")),
                    entity_infos: None,
                })
            }),
            perms: UserOperationPermissions::default(),
        }])
        .await;
        assert!(bundle.ops_per_aggregator.is_empty());
        assert!(bundle.rejected_ops.is_empty());
    }

    #[tokio::test]
    async fn test_rejects_on_signature_failure() {
        let op = default_op();
        let bundle = simple_make_bundle(vec![MockOp {
            op: op.clone(),
            simulation_result: Box::new(|| {
                Err(SimulationError {
                    violation_error: ViolationError::Violations(vec![
                        SimulationViolation::InvalidSignature,
                    ]),
                    entity_infos: None,
                })
            }),
            perms: UserOperationPermissions::default(),
        }])
        .await;
        assert!(bundle.ops_per_aggregator.is_empty());
        assert_eq!(bundle.rejected_ops, vec![op]);
    }

    #[tokio::test]
    async fn test_rejects_on_invalid_time_range() {
        let invalid_time_ranges = [
            ValidTimeRange::new(Timestamp::now() + Duration::from_secs(3600), Timestamp::MAX),
            ValidTimeRange::new(Timestamp::MIN, Timestamp::now() + Duration::from_secs(5)),
        ];
        for time_range in invalid_time_ranges {
            let op = default_op();
            let bundle = simple_make_bundle(vec![MockOp {
                op: op.clone(),
                simulation_result: Box::new(move || {
                    Ok(SimulationResult {
                        valid_time_range: time_range,
                        ..Default::default()
                    })
                }),
                perms: UserOperationPermissions::default(),
            }])
            .await;
            assert!(bundle.ops_per_aggregator.is_empty());
            assert_eq!(bundle.rejected_ops, vec![op]);
        }
    }

    #[tokio::test]
    async fn test_skips_but_not_rejects_op_accessing_another_sender() {
        let op1 = op_with_sender(address(1));
        let op2 = op_with_sender(address(2));
        let bundle = simple_make_bundle(vec![
            MockOp {
                op: op1,
                simulation_result: Box::new(|| {
                    Ok(SimulationResult {
                        accessed_addresses: [address(1), address(2)].into(),
                        ..Default::default()
                    })
                }),
                perms: UserOperationPermissions::default(),
            },
            MockOp {
                op: op2.clone(),
                simulation_result: Box::new(|| {
                    Ok(SimulationResult {
                        accessed_addresses: [address(2)].into(),
                        ..Default::default()
                    })
                }),
                perms: UserOperationPermissions::default(),
            },
        ])
        .await;
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op2],
                ..Default::default()
            }]
        );
        assert!(bundle.rejected_ops.is_empty())
    }

    #[tokio::test]
    async fn test_skips_but_not_rejects_op_with_too_low_max_priority_fee() {
        // With 10% required overhead on priority fee, op1 should be excluded
        // but op2 accepted.
        let base_fee = 1000;
        let max_priority_fee_per_gas = 50;
        let op1 = op_with_sender_and_fees(address(1), 2049, 49, DEFAULT_PVG);
        let op2 = op_with_sender_and_fees(address(2), 2050, 50, DEFAULT_PVG);
        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            base_fee,
            max_priority_fee_per_gas,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op2],
                ..Default::default()
            }],
        );
        assert!(bundle.rejected_ops.is_empty());
    }

    #[tokio::test]
    async fn test_skips_but_not_rejects_op_with_too_low_max_fee_per_gas() {
        let base_fee = 1000;
        let max_priority_fee_per_gas = 50;
        let op1 = op_with_sender_and_fees(address(1), 1049, 49, DEFAULT_PVG);
        let op2 = op_with_sender_and_fees(address(2), 1050, 50, DEFAULT_PVG);
        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            base_fee,
            max_priority_fee_per_gas,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;
        assert_eq!(
            bundle.gas_fees,
            GasFees {
                max_fee_per_gas: 1050,
                max_priority_fee_per_gas: 50,
            }
        );
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op2],
                ..Default::default()
            }],
        );
        assert!(bundle.rejected_ops.is_empty());
    }

    #[tokio::test]
    async fn test_skips_but_not_rejects_op_with_too_low_pvg() {
        let base_fee = 1000;
        let max_priority_fee_per_gas = 50;
        // Should be skipped but not rejected
        let op1 = op_with_sender_and_fees(address(1), 1054, 55, 0);
        // Should be included
        let op2 = op_with_sender_and_fees(address(2), 1055, 55, DEFAULT_PVG);

        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            base_fee,
            max_priority_fee_per_gas,
            false,
            ExpectedStorage::default(),
            true,
            vec![],
            None,
            U256::MAX,
        )
        .await;
        assert_eq!(
            bundle.gas_fees,
            GasFees {
                max_fee_per_gas: 1050,
                max_priority_fee_per_gas: 50,
            }
        );
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op2],
                ..Default::default()
            }],
        );
        assert!(bundle.rejected_ops.is_empty());
    }

    #[tokio::test]
    async fn test_aggregators() {
        // One op with no aggregator, two from aggregator A, and one from
        // aggregator B.
        let aggregator_a_address = address(10);
        let aggregator_b_address = address(11);
        let unaggregated_op = op_with_sender(address(1));
        let aggregated_op_a1 =
            op_with_sender_aggregator(address(2), aggregator_a_address, Bytes::new());
        let aggregated_op_a2 =
            op_with_sender_aggregator(address(3), aggregator_a_address, Bytes::new());
        let aggregated_op_b =
            op_with_sender_aggregator(address(4), aggregator_b_address, Bytes::new());
        let aggregator_a_signature = 101;
        let aggregator_b_signature = 102;

        let agg_a = mock_signature_aggregator(aggregator_a_address, bytes(aggregator_a_signature));
        let agg_b = mock_signature_aggregator(aggregator_b_address, bytes(aggregator_b_signature));

        let mut bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: unaggregated_op.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: aggregated_op_a1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: aggregated_op_a2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: aggregated_op_b.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![
                MockAggregator {
                    address: aggregator_a_address,
                    signature: Box::new(move || Ok(Some(bytes(aggregator_a_signature)))),
                },
                MockAggregator {
                    address: aggregator_b_address,
                    signature: Box::new(move || Ok(Some(bytes(aggregator_b_signature)))),
                },
            ],
            vec![HandleOpsOut::Success],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![agg_a, agg_b],
            None,
            U256::MAX,
        )
        .await;
        // Ops should be grouped by aggregator. Further, the `signature` field
        // of each op with an aggregator should be empty.

        bundle
            .ops_per_aggregator
            .sort_by(|a, b| a.aggregator.cmp(&b.aggregator));

        assert_eq!(
            bundle.ops_per_aggregator,
            vec![
                UserOpsPerAggregator {
                    user_ops: vec![unaggregated_op],
                    ..Default::default()
                },
                UserOpsPerAggregator {
                    user_ops: vec![aggregated_op_a1, aggregated_op_a2,],
                    aggregator: aggregator_a_address,
                    signature: bytes(aggregator_a_signature)
                },
                UserOpsPerAggregator {
                    user_ops: vec![aggregated_op_b],
                    aggregator: aggregator_b_address,
                    signature: bytes(aggregator_b_signature)
                },
            ],
        );
    }

    #[tokio::test]
    async fn test_reject_aggregator() {
        // One op with no aggregator, two from aggregator A, and one from
        // aggregator B.
        let aggregator_a_address = address(10);
        let aggregator_b_address = address(11);
        let unaggregated_op = op_with_sender(address(1));
        let aggregated_op_a1 =
            op_with_sender_aggregator(address(2), aggregator_a_address, Bytes::new());
        let aggregated_op_a2 =
            op_with_sender_aggregator(address(3), aggregator_a_address, Bytes::new());
        let aggregated_op_b =
            op_with_sender_aggregator(address(4), aggregator_b_address, Bytes::new());

        let aggregator_a_signature = 101;
        let aggregator_b_signature = 102;

        let agg_a = mock_signature_aggregator(aggregator_a_address, bytes(aggregator_a_signature));

        // Aggregator B fails validation and should be rejected with its ops
        let mut agg_b = MockSignatureAggregator::default();
        agg_b.expect_address().return_const(aggregator_b_address);
        agg_b
            .expect_costs()
            .return_const(AggregatorCosts::default());
        agg_b
            .expect_aggregate_signatures()
            .returning(move |_| Err(SignatureAggregatorError::ValidationReverted(Bytes::new())));

        let mut bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: unaggregated_op.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: aggregated_op_a1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: aggregated_op_a2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: aggregated_op_b.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![
                MockAggregator {
                    address: aggregator_a_address,
                    signature: Box::new(move || Ok(Some(bytes(aggregator_a_signature)))),
                },
                MockAggregator {
                    address: aggregator_b_address,
                    signature: Box::new(move || Ok(Some(bytes(aggregator_b_signature)))),
                },
            ],
            vec![HandleOpsOut::Success],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![agg_a, agg_b],
            None,
            U256::MAX,
        )
        .await;

        bundle
            .ops_per_aggregator
            .sort_by(|a, b| a.aggregator.cmp(&b.aggregator));

        assert_eq!(
            bundle.ops_per_aggregator,
            vec![
                UserOpsPerAggregator {
                    user_ops: vec![unaggregated_op],
                    ..Default::default()
                },
                UserOpsPerAggregator {
                    user_ops: vec![aggregated_op_a1, aggregated_op_a2,],
                    aggregator: aggregator_a_address,
                    signature: bytes(aggregator_a_signature)
                },
            ],
        );

        assert_eq!(bundle.rejected_ops, vec![aggregated_op_b]);
    }

    #[tokio::test]
    async fn test_reject_entities() {
        let op1 = op_with_sender_paymaster(address(1), address(1));
        let op2 = op_with_sender_paymaster(address(2), address(1));
        let op3 = op_with_sender_paymaster(address(3), address(2));
        let op4 = op_with_sender_factory(address(4), address(3));
        let op5 = op_with_sender_factory(address(5), address(3));
        let op6 = op_with_sender_factory(address(6), address(4));
        let deposit = parse_units("1", "ether").unwrap().into();

        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op3.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op4.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op5.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op6.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![
                HandleOpsOut::FailedOp(0, "AA30: reject paymaster".to_string()),
                HandleOpsOut::FailedOp(1, "AA13: reject factory".to_string()),
                HandleOpsOut::Success,
            ],
            vec![deposit, deposit, deposit],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert_eq!(
            bundle.entity_updates,
            vec![
                EntityUpdate {
                    entity: Entity::paymaster(address(1)),
                    update_type: EntityUpdateType::UnstakedInvalidation,
                    ..Default::default()
                },
                EntityUpdate {
                    entity: Entity::factory(address(3)),
                    update_type: EntityUpdateType::UnstakedInvalidation,
                    ..Default::default()
                },
            ]
        );
        assert_eq!(bundle.rejected_ops, vec![op1, op2, op4, op5]);
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op3, op6],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_paymaster_amended_by_staked_factory_revert() {
        let sender = address(1);
        let staked_factory = address(2);
        let paymaster = address(3);

        let deposit = parse_units("1", "ether").unwrap().into();

        let entity_infos = EntityInfos {
            sender: EntityInfo::new(Entity::account(sender), false),
            factory: Some(EntityInfo::new(Entity::factory(staked_factory), true)),
            paymaster: Some(EntityInfo::new(Entity::paymaster(paymaster), false)),
            aggregator: None,
        };

        // EREP-015: If a staked factory or sender is present, we attribute errors to them directly.
        // Expect EntityUpdateType::PaymasterOpsSeenDecrement to be recorded.
        let op = op_with_sender_factory_paymaster(sender, staked_factory, paymaster);
        let bundle = mock_make_bundle(
            vec![MockOp {
                op: op.clone(),
                simulation_result: Box::new(move || {
                    Err(SimulationError {
                        violation_error: ViolationError::Violations(vec![]),
                        entity_infos: Some(entity_infos),
                    })
                }),
                perms: UserOperationPermissions::default(),
            }],
            vec![],
            vec![],
            vec![deposit],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        let mut actual_entity_updates = bundle.entity_updates;
        let mut expected_entity_updates = vec![
            EntityUpdate {
                entity: Entity::factory(staked_factory),
                update_type: EntityUpdateType::StakedInvalidation,
                ..Default::default()
            },
            EntityUpdate {
                entity: Entity::paymaster(paymaster),
                update_type: EntityUpdateType::PaymasterOpsSeenDecrement,
                value: Some(1),
            },
        ];

        // we want to check that the entity updates are the same regardless of order
        actual_entity_updates.sort_by(|a, b| a.entity.address.cmp(&b.entity.address));
        expected_entity_updates.sort_by(|a, b| a.entity.address.cmp(&b.entity.address));

        assert_eq!(actual_entity_updates, expected_entity_updates);
    }

    #[tokio::test]
    async fn test_paymaster_amended_by_staked_sender_revert() {
        let sender = address(1);
        let paymaster = address(2);

        let deposit = parse_units("1", "ether").unwrap().into();

        let entity_infos = EntityInfos {
            sender: EntityInfo::new(Entity::account(sender), true),
            factory: None,
            paymaster: Some(EntityInfo::new(Entity::paymaster(paymaster), false)),
            aggregator: None,
        };

        // EREP-015: If not a staked factory or sender, attribute errors to each entity directly.
        // Expect EntityUpdateType::PaymasterOpsSeenDecrement to be recorded.
        let op = op_with_sender_paymaster(sender, paymaster);
        let bundle = mock_make_bundle(
            vec![MockOp {
                op: op.clone(),
                simulation_result: Box::new(move || {
                    Err(SimulationError {
                        violation_error: ViolationError::Violations(vec![]),
                        entity_infos: Some(entity_infos),
                    })
                }),
                perms: UserOperationPermissions::default(),
            }],
            vec![],
            vec![],
            vec![deposit],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        let mut actual_entity_updates = bundle.entity_updates;
        let mut expected_entity_updates = vec![
            EntityUpdate {
                entity: Entity::account(sender),
                update_type: EntityUpdateType::StakedInvalidation,
                ..Default::default()
            },
            EntityUpdate {
                entity: Entity::paymaster(paymaster),
                update_type: EntityUpdateType::PaymasterOpsSeenDecrement,
                value: Some(1),
            },
        ];

        // we want to check that the entity updates are the same regardless of order
        actual_entity_updates.sort_by(|a, b| a.entity.address.cmp(&b.entity.address));
        expected_entity_updates.sort_by(|a, b| a.entity.address.cmp(&b.entity.address));

        assert_eq!(actual_entity_updates, expected_entity_updates);
    }

    #[tokio::test]
    async fn test_paymaster_amended_by_factory_or_sender_revert() {
        let sender_1 = address(1);
        let sender_2 = address(2);
        let factory = address(3);
        let paymaster = address(4);

        let deposit = parse_units("1", "ether").unwrap().into();

        let entity_infos_1 = EntityInfos {
            sender: EntityInfo::new(Entity::account(sender_1), false),
            factory: Some(EntityInfo::new(Entity::factory(factory), false)),
            paymaster: Some(EntityInfo::new(Entity::paymaster(paymaster), false)),
            aggregator: None,
        };

        let entity_infos_2 = EntityInfos {
            sender: EntityInfo::new(Entity::account(sender_2), false),
            factory: Some(EntityInfo::new(Entity::factory(factory), false)),
            paymaster: Some(EntityInfo::new(Entity::paymaster(paymaster), false)),
            aggregator: None,
        };

        // EREP-015: If a staked factory or sender is present, we attribute errors to them directly.
        // Expect EntityUpdateType::PaymasterOpsSeenDecrement to be recorded.
        let op_1 = op_with_sender_factory_paymaster(sender_1, factory, paymaster);
        let op_2 = op_with_sender_factory_paymaster(sender_2, factory, paymaster);
        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op_1.clone(),
                    simulation_result: Box::new(move || {
                        Err(SimulationError {
                            violation_error: ViolationError::Violations(vec![
                                SimulationViolation::ValidationRevert(
                                    ValidationRevert::Operation {
                                        entry_point_reason: "AA1x: factory related errors"
                                            .to_string(),
                                        inner_revert_reason: None,
                                        inner_revert_data: Bytes::new(),
                                    },
                                ),
                            ]),
                            entity_infos: Some(entity_infos_1),
                        })
                    }),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op_2.clone(),
                    simulation_result: Box::new(move || {
                        Err(SimulationError {
                            violation_error: ViolationError::Violations(vec![
                                SimulationViolation::ValidationRevert(
                                    ValidationRevert::Operation {
                                        entry_point_reason: "AA2x: sender related errors"
                                            .to_string(),
                                        inner_revert_reason: None,
                                        inner_revert_data: Bytes::new(),
                                    },
                                ),
                            ]),
                            entity_infos: Some(entity_infos_2),
                        })
                    }),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![],
            vec![deposit, deposit],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        let actual_entity_updates = bundle.entity_updates;
        let expected_entity_updates = vec![EntityUpdate {
            entity: Entity::paymaster(paymaster),
            update_type: EntityUpdateType::PaymasterOpsSeenDecrement,
            value: Some(2),
        }];

        assert_eq!(actual_entity_updates, expected_entity_updates);
    }

    #[tokio::test]
    async fn test_bundle_gas_limit_max() {
        // Target is 10M, max is 25M
        // Each OP has 1M pre_verification_gas, 0 verification_gas_limit, call_gas_limit is passed in
        let op1 = op_with_sender_call_gas_limit(address(1), 4_000_000);
        let op2 = op_with_sender_call_gas_limit(address(2), 3_000_000);
        // these two shouldn't be included in the bundle as they put us over the max
        let op3 = op_with_sender_call_gas_limit(address(3), 20_000_000);
        let op4 = op_with_sender_call_gas_limit(address(4), 20_000_000);
        let deposit = parse_units("1", "ether").unwrap().into();

        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op3.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op4.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![deposit, deposit, deposit],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        let cs = ChainSpec::default();
        let expected_gas_limit: u64 = (op1.bundle_gas_limit(&cs, None)
            + op2.bundle_gas_limit(&cs, None)
            + rundler_types::bundle_shared_gas(&cs))
        .try_into()
        .unwrap();

        assert_eq!(bundle.entity_updates, vec![]);
        assert_eq!(bundle.rejected_ops, vec![]);
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op1, op2],
                ..Default::default()
            }]
        );
        assert_eq!(
            bundle.gas_estimate,
            math::increase_by_percent(expected_gas_limit, BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT)
        );
    }

    #[tokio::test]
    async fn test_bundle_gas_limit_target() {
        // Target is 10M, max is 25M
        // Each OP has 1M pre_verification_gas, 0 verification_gas_limit, call_gas_limit is passed in
        let op1 = op_with_sender_call_gas_limit(address(1), 4_000_000);
        let op2 = op_with_sender_call_gas_limit(address(2), 6_000_000);
        // this op should be included in the bundle as we're already at the target
        let op3 = op_with_sender_call_gas_limit(address(3), 1_000_000);
        let deposit = parse_units("1", "ether").unwrap().into();

        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op3.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![deposit, deposit, deposit],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        let cs = ChainSpec::default();
        let expected_gas_limit: u64 = (op1.bundle_gas_limit(&cs, None)
            + op2.bundle_gas_limit(&cs, None)
            + rundler_types::bundle_shared_gas(&cs))
        .try_into()
        .unwrap();

        assert_eq!(bundle.entity_updates, vec![]);
        assert_eq!(bundle.rejected_ops, vec![]);
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op1, op2],
                ..Default::default()
            }]
        );
        assert_eq!(
            bundle.gas_estimate,
            math::increase_by_percent(expected_gas_limit, BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT)
        );
    }

    #[tokio::test]
    async fn test_bundle_gas_limit_da_gas() {
        let cs = ChainSpec {
            include_da_gas_in_gas_limit: false,
            ..Default::default()
        };
        let op1 = op_with_gas(100_000, 100_000, 1_000_000, false);
        let op2 = op_with_gas(100_000, 100_000, 200_000, false);
        let mut groups_by_aggregator = LinkedHashMap::new();
        groups_by_aggregator.insert(
            Address::ZERO,
            AggregatorGroup {
                ops_with_simulations: vec![
                    OpWithSimulation {
                        op: op1.clone(),
                        simulation: SimulationResult {
                            requires_post_op: false,
                            ..Default::default()
                        },
                        sponsored_da_gas: 100_000,
                    },
                    OpWithSimulation {
                        op: op2.clone(),
                        simulation: SimulationResult {
                            requires_post_op: false,
                            ..Default::default()
                        },
                        sponsored_da_gas: 0,
                    },
                ],
                signature: Default::default(),
            },
        );
        let context = ProposalContext {
            groups_by_aggregator,
            rejected_ops: vec![],
            entity_updates: BTreeMap::new(),
            bundle_expected_storage: BundleExpectedStorage::default(),
        };

        // DA gas is not included in the gas limit
        let expected_gas_limit = op1.bundle_gas_limit(&cs, None)
            + op2.bundle_gas_limit(&cs, None)
            + rundler_types::bundle_shared_gas(&cs);
        assert_eq!(context.get_bundle_gas_limit(&cs), expected_gas_limit);

        // DA gas is included in the gas cost (gas price is 1)
        let expected_gas_cost = U256::from(expected_gas_limit) + U256::from(100_000);
        assert_eq!(context.get_bundle_cost(&cs, 1), expected_gas_cost);
    }

    #[tokio::test]
    async fn test_bundle_gas_limit_with_paymaster_op() {
        let cs = ChainSpec::default();
        let op1 = op_with_gas(100_000, 100_000, 1_000_000, true); // has paymaster
        let op2 = op_with_gas(100_000, 100_000, 200_000, false);
        let mut groups_by_aggregator = LinkedHashMap::new();
        groups_by_aggregator.insert(
            Address::ZERO,
            AggregatorGroup {
                ops_with_simulations: vec![
                    OpWithSimulation {
                        op: op1.clone(),
                        simulation: SimulationResult {
                            requires_post_op: true, // uses postOp
                            ..Default::default()
                        },
                        sponsored_da_gas: 0,
                    },
                    OpWithSimulation {
                        op: op2.clone(),
                        simulation: SimulationResult {
                            requires_post_op: false,
                            ..Default::default()
                        },
                        sponsored_da_gas: 0,
                    },
                ],
                signature: Default::default(),
            },
        );
        let context = ProposalContext {
            groups_by_aggregator,
            rejected_ops: vec![],
            entity_updates: BTreeMap::new(),
            bundle_expected_storage: BundleExpectedStorage::default(),
        };
        let gas_limit = context.get_bundle_gas_limit(&cs);

        let expected_gas_limit = op1.bundle_gas_limit(&cs, None)
            + op2.bundle_gas_limit(&cs, None)
            + rundler_types::bundle_shared_gas(&cs);

        assert_eq!(gas_limit, expected_gas_limit);
    }

    #[tokio::test]
    async fn test_post_op_revert() {
        let op1 = op_with_sender(address(1));
        let bundle = mock_make_bundle(
            vec![MockOp {
                op: op1.clone(),
                simulation_result: Box::new(|| Ok(SimulationResult::default())),
                perms: UserOperationPermissions::default(),
            }],
            vec![],
            vec![HandleOpsOut::PostOpRevert, HandleOpsOut::PostOpRevert],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert_eq!(bundle.rejected_ops, vec![op1]);
        assert!(bundle.ops_per_aggregator.is_empty());
    }

    #[tokio::test]
    async fn test_post_op_revert_two() {
        let op1 = op_with_sender(address(1));
        let op2 = op_with_sender(address(2));
        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![
                HandleOpsOut::PostOpRevert,
                HandleOpsOut::PostOpRevert,
                HandleOpsOut::Success,
                HandleOpsOut::Success,
            ],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert_eq!(bundle.rejected_ops, vec![op1]);
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op2],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_post_op_revert_agg() {
        let aggregator_a_address = address(10);
        let unaggregated_op = op_with_sender(address(1));
        let aggregated_op_a1 =
            op_with_sender_aggregator(address(2), aggregator_a_address, Bytes::new());
        let aggregated_op_a2 =
            op_with_sender_aggregator(address(3), aggregator_a_address, Bytes::new());

        let aggregator_a_signature = 101;

        let agg_a = mock_signature_aggregator(aggregator_a_address, bytes(aggregator_a_signature));

        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: unaggregated_op.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: aggregated_op_a1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: aggregated_op_a2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![MockAggregator {
                address: aggregator_a_address,
                signature: Box::new(move || Ok(Some(bytes(aggregator_a_signature)))),
            }],
            vec![
                HandleOpsOut::PostOpRevert, // bundle
                HandleOpsOut::Success,      // unaggregated check
                HandleOpsOut::PostOpRevert, // aggregated check
                HandleOpsOut::Success,      // after remove
            ],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![agg_a],
            None,
            U256::MAX,
        )
        .await;

        assert_eq!(
            bundle.rejected_ops,
            vec![aggregated_op_a2, aggregated_op_a1]
        );
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![unaggregated_op],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_condition_not_met_match() {
        let op = default_op();

        let mut expected_storage = ExpectedStorage::default();
        expected_storage.insert(address(1), U256::ZERO, U256::ZERO);
        let actual_storage = expected_storage.clone();

        let bundle = mock_make_bundle(
            vec![MockOp {
                op: op.clone(),
                simulation_result: Box::new(move || {
                    Ok(SimulationResult {
                        expected_storage: expected_storage.clone(),
                        ..Default::default()
                    })
                }),
                perms: UserOperationPermissions::default(),
            }],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            0,
            0,
            true,
            actual_storage,
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_condition_not_met_mismatch() {
        let op = default_op();

        let mut expected_storage = ExpectedStorage::default();
        expected_storage.insert(address(1), U256::ZERO, U256::ZERO);
        let mut actual_storage = ExpectedStorage::default();
        actual_storage.insert(address(1), U256::ZERO, U256::from(1));

        let bundle = mock_make_bundle(
            vec![MockOp {
                op: op.clone(),
                simulation_result: Box::new(move || {
                    Ok(SimulationResult {
                        expected_storage: expected_storage.clone(),
                        ..Default::default()
                    })
                }),
                perms: UserOperationPermissions::default(),
            }],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            0,
            0,
            true,
            actual_storage,
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert!(bundle.ops_per_aggregator.is_empty());
        assert_eq!(bundle.rejected_ops, vec![op]);
    }

    #[tokio::test]
    async fn test_single_uo_max_expected_storage_slots() {
        let op = default_op();
        let mut expected_storage = ExpectedStorage::default();
        for _ in 0..=MAX_EXPECTED_STORAGE_SLOTS {
            expected_storage.insert(Address::random(), U256::ZERO, U256::ZERO);
        }

        let bundle = mock_make_bundle(
            vec![MockOp {
                op,
                simulation_result: Box::new(move || {
                    Ok(SimulationResult {
                        expected_storage: expected_storage.clone(),
                        ..Default::default()
                    })
                }),
                perms: UserOperationPermissions::default(),
            }],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert!(bundle.is_empty())
    }

    #[tokio::test]
    async fn test_skip_max_expected_storage_slots() {
        let op0 = op_with_sender(address(1));
        let op1 = op_with_sender(address(2));
        let mut expected_storage0 = ExpectedStorage::default();
        for _ in 0..MAX_EXPECTED_STORAGE_SLOTS {
            expected_storage0.insert(Address::random(), U256::ZERO, U256::ZERO);
        }
        let mut expected_storage1 = ExpectedStorage::default();
        expected_storage1.insert(Address::random(), U256::ZERO, U256::ZERO);

        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op0.clone(),
                    simulation_result: Box::new(move || {
                        Ok(SimulationResult {
                            expected_storage: expected_storage0.clone(),
                            ..Default::default()
                        })
                    }),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(move || {
                        Ok(SimulationResult {
                            expected_storage: expected_storage1.clone(),
                            ..Default::default()
                        })
                    }),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op0],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_submitter_proxy() {
        let op = default_op();
        let proxy_address = address(1);

        let mut proxy = MockSubmissionProxy::new();
        proxy.expect_address().returning(move || proxy_address);

        // will throw if proxy doesn't match
        let bundle = mock_make_bundle(
            vec![MockOp {
                op: op.clone(),
                simulation_result: Box::new(|| Ok(SimulationResult::default())),
                perms: UserOperationPermissions::default(),
            }],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            Some(proxy),
            U256::MAX,
        )
        .await;

        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_submitter_proxy_revert() {
        let op = default_op();
        let op_hash = op.hash();
        let proxy_address = address(1);
        let bytes = bytes(1);
        let cloned_bytes = bytes.clone();

        let mut proxy = MockSubmissionProxy::new();
        proxy.expect_address().returning(move || proxy_address);
        proxy
            .expect_process_revert()
            .withf(move |b, _| *b == cloned_bytes)
            .returning(move |_, _| vec![op_hash]);

        let bundle = mock_make_bundle(
            vec![MockOp {
                op: op.clone(),
                simulation_result: Box::new(|| Ok(SimulationResult::default())),
                perms: UserOperationPermissions::default(),
            }],
            vec![],
            vec![HandleOpsOut::Revert(bytes)],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            Some(proxy),
            U256::MAX,
        )
        .await;

        assert_eq!(bundle.ops_per_aggregator, vec![]);
    }

    #[tokio::test]
    async fn test_bundle_expected_storage_remove() {
        let op0 = op_with_sender(address(1));
        let op1 = op_with_sender(address(2));

        let address0 = Address::random();
        let mut expected_storage0 = ExpectedStorage::default();
        expected_storage0.insert(address0, U256::ZERO, U256::ZERO);
        expected_storage0.insert(address0, U256::from(1), U256::ZERO);
        let mut expected_storage1 = ExpectedStorage::default();
        expected_storage1.insert(address0, U256::ZERO, U256::ZERO);
        expected_storage1.insert(address0, U256::from(2), U256::ZERO);
        let expected_storage1_clone = expected_storage1.clone();

        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op0.clone(),
                    simulation_result: Box::new(move || {
                        Ok(SimulationResult {
                            expected_storage: expected_storage0.clone(),
                            ..Default::default()
                        })
                    }),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(move || {
                        Ok(SimulationResult {
                            expected_storage: expected_storage1.clone(),
                            ..Default::default()
                        })
                    }),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![
                HandleOpsOut::FailedOp(0, "AA25: invalid nonce".to_string()),
                HandleOpsOut::Success,
            ],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert_eq!(bundle.rejected_ops, vec![op0]);
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op1],
                ..Default::default()
            }]
        );
        assert_eq!(bundle.expected_storage.0, expected_storage1_clone.0);
    }

    #[tokio::test]
    async fn test_trusted_op() {
        let op = default_op();
        let bundle = mock_make_bundle(
            vec![MockOp {
                op: op.clone(),
                simulation_result: Box::new(|| Ok(SimulationResult::default())),
                perms: UserOperationPermissions {
                    trusted: true,
                    ..Default::default()
                },
            }],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_trusted_untrusted_ops() {
        let op0 = op_with_sender(address(1));
        let op1 = op_with_sender(address(2));
        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op0.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions {
                        trusted: true,
                        ..Default::default()
                    },
                },
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op0, op1],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_underpriced_op_perms() {
        let op0 = op_with_sender_and_fees(address(1), 7500, 0, DEFAULT_PVG); // accept
        let op1 = op_with_sender_and_fees(address(2), 7499, 0, DEFAULT_PVG); // reject w/o remove
        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op0.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions {
                        underpriced_bundle_pct: Some(75),
                        ..Default::default()
                    },
                },
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions {
                        underpriced_bundle_pct: Some(75),
                        ..Default::default()
                    },
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            10000,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op0],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_underpriced_op_perms_pvg() {
        let cs = ChainSpec {
            da_pre_verification_gas: true,
            ..Default::default()
        };
        let mock_op0 = op_with_sender_and_fees(address(1), 10000, 0, DEFAULT_PVG);
        let required_pvg =
            mock_op0.required_pre_verification_gas(&cs, 1, DEFAULT_DA_PVG, Some(0.5));

        let op0 = op_with_sender_and_fees(address(1), 10000, 0, math::percent(required_pvg, 75)); // accept
        let op1 =
            op_with_sender_and_fees(address(2), 10000, 0, math::percent(required_pvg, 75 - 1)); // reject w/o remove
        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op0.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions {
                        underpriced_bundle_pct: Some(75),
                        ..Default::default()
                    },
                },
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions {
                        underpriced_bundle_pct: Some(75),
                        ..Default::default()
                    },
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            10000,
            0,
            false,
            ExpectedStorage::default(),
            true, // da_gas_tracking_enabled == dynamic PVG
            vec![],
            None,
            U256::MAX,
        )
        .await;

        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op0],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_bundler_sponsorship_skip_fee_check() {
        let mock_op = op_with_sender_and_fees(address(1), 0, 0, 0); // Zero fees
        let perms = UserOperationPermissions {
            bundler_sponsorship: Some(BundlerSponsorship {
                max_cost: U256::from(1000000000000_u64), // High enough max cost
                valid_until: u64::MAX,                   // Never expires
            }),
            ..Default::default()
        };

        let bundle = mock_make_bundle(
            vec![MockOp {
                op: mock_op.clone(),
                simulation_result: Box::new(|| Ok(SimulationResult::default())),
                perms,
            }],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            100,
            10,
            false,
            ExpectedStorage::default(),
            true,
            vec![],
            None,
            U256::MAX,
        )
        .await;

        // Operation should be included despite having zero fees
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![mock_op],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_bundler_sponsorship_expired() {
        let mock_op = op_with_sender_and_fees(address(1), 0, 0, 0); // Zero fees
        let perms = UserOperationPermissions {
            bundler_sponsorship: Some(BundlerSponsorship {
                max_cost: U256::from(1000), // High enough max cost
                valid_until: u64::MAX,      // Never expires
            }),
            ..Default::default()
        };
        let error = mock_make_bundle_allow_error(
            vec![MockOp {
                op: mock_op.clone(),
                simulation_result: Box::new(|| {
                    Ok(SimulationResult {
                        valid_time_range: ValidTimeRange::from_genesis(200.into()), // Current time > valid_until
                        ..Default::default()
                    })
                }),
                perms,
            }],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            10000,
            1000,
            false,
            ExpectedStorage::default(),
            true,
            vec![],
            None,
            U256::MAX,
        )
        .await
        .expect_err("should fail to bundle");

        assert!(matches!(
            error,
            BundleProposerError::NoOperationsAfterFeeFilter
        ));
    }

    #[tokio::test]
    async fn test_bundler_sponsorship_over_max_cost() {
        let mock_op = op_with_gas(0, 100_000, 100_000, false); // High gas limits
        let perms = UserOperationPermissions {
            bundler_sponsorship: Some(BundlerSponsorship {
                max_cost: U256::from(1_000_000), // Max cost too low for gas price * gas limit
                valid_until: u64::MAX,
            }),
            ..Default::default()
        };

        let error = mock_make_bundle_allow_error(
            vec![MockOp {
                op: mock_op.clone(),
                simulation_result: Box::new(|| Ok(SimulationResult::default())),
                perms,
            }],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            10_000, // High base fee
            1_000,  // High priority fee
            false,
            ExpectedStorage::default(),
            true,
            vec![],
            None,
            U256::MAX,
        )
        .await
        .expect_err("should fail to bundle");

        assert!(matches!(
            error,
            BundleProposerError::NoOperationsAfterFeeFilter
        ));
    }

    #[tokio::test]
    async fn test_max_bundle_fee() {
        let gas_price = 1_000_000_000;
        // Create operations with different gas limits
        let op1 =
            op_with_sender_call_gas_limit_and_fees(address(1), 1_000_000, gas_price, gas_price);
        let op2 =
            op_with_sender_call_gas_limit_and_fees(address(2), 2_000_000, gas_price, gas_price);
        let op3 =
            op_with_sender_call_gas_limit_and_fees(address(3), 3_000_000, gas_price, gas_price);

        let cs = ChainSpec::default();
        let total_gas_cost = U256::from(
            op1.bundle_gas_limit(&cs, None)
                + op2.bundle_gas_limit(&cs, None)
                + op3.bundle_gas_limit(&cs, None),
        ) * U256::from(gas_price);

        // set max bundle fee to 1 gwei less than the total gas cost, op3 will be skipped
        let max_bundle_fee = total_gas_cost - U256::from(1_000_000_000);

        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
                MockOp {
                    op: op3.clone(),
                    simulation_result: Box::new(|| Ok(SimulationResult::default())),
                    perms: UserOperationPermissions::default(),
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            gas_price,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            max_bundle_fee,
        )
        .await;

        assert_eq!(bundle.entity_updates, vec![]);
        assert_eq!(bundle.rejected_ops, vec![]);
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op1, op2],
                ..Default::default()
            }]
        );
    }

    struct MockOp {
        op: UserOperation,
        simulation_result: Box<dyn Fn() -> Result<SimulationResult, SimulationError> + Send + Sync>,
        perms: UserOperationPermissions,
    }

    struct MockAggregator {
        address: Address,
        signature: Box<dyn Fn() -> anyhow::Result<Option<Bytes>> + Send + Sync>,
    }

    async fn simple_make_bundle(mock_ops: Vec<MockOp>) -> Bundle<UserOperation> {
        mock_make_bundle(
            mock_ops,
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            0,
            0,
            false,
            ExpectedStorage::default(),
            false,
            vec![],
            None,
            U256::MAX,
        )
        .await
    }

    const MAX_EXPECTED_STORAGE_SLOTS: usize = 100;

    #[allow(clippy::too_many_arguments)]
    async fn mock_make_bundle(
        mock_ops: Vec<MockOp>,
        mock_aggregators: Vec<MockAggregator>,
        mock_handle_ops_call_results: Vec<HandleOpsOut>,
        mock_paymaster_deposits: Vec<U256>,
        base_fee: u128,
        max_priority_fee_per_gas: u128,
        notify_condition_not_met: bool,
        actual_storage: ExpectedStorage,
        da_gas_tracking_enabled: bool,
        aggregators: Vec<MockSignatureAggregator>,
        proxy: Option<MockSubmissionProxy>,
        max_bundle_fee: U256,
    ) -> Bundle<UserOperation> {
        mock_make_bundle_allow_error(
            mock_ops,
            mock_aggregators,
            mock_handle_ops_call_results,
            mock_paymaster_deposits,
            base_fee,
            max_priority_fee_per_gas,
            notify_condition_not_met,
            actual_storage,
            da_gas_tracking_enabled,
            aggregators,
            proxy,
            max_bundle_fee,
        )
        .await
        .expect("should make a bundle")
    }

    #[allow(clippy::too_many_arguments)]
    async fn mock_make_bundle_allow_error(
        mock_ops: Vec<MockOp>,
        mock_aggregators: Vec<MockAggregator>,
        mock_handle_ops_call_results: Vec<HandleOpsOut>,
        mock_paymaster_deposits: Vec<U256>,
        base_fee: u128,
        max_priority_fee_per_gas: u128,
        notify_condition_not_met: bool,
        actual_storage: ExpectedStorage,
        da_gas_tracking_enabled: bool,
        aggregators: Vec<MockSignatureAggregator>,
        proxy: Option<MockSubmissionProxy>,
        max_bundle_fee: U256,
    ) -> BundleProposerResult<Bundle<UserOperation>> {
        let mut chain_spec = ChainSpec {
            da_pre_verification_gas: da_gas_tracking_enabled,
            ..Default::default()
        };
        let sender_eoa = address(124);
        let current_block_hash = hash(125);
        let expected_code_hash = hash(126);
        let proxy_address = proxy.as_ref().map(|p| p.address());
        let ops: Vec<_> = mock_ops
            .iter()
            .map(|MockOp { op, perms, .. }| PoolOperation {
                uo: op.clone().into(),
                expected_code_hash,
                entry_point: chain_spec.entry_point_address_v0_6,
                sim_block_hash: current_block_hash,
                sim_block_number: 0,
                account_is_staked: false,
                valid_time_range: ValidTimeRange::default(),
                entity_infos: EntityInfos::default(),
                aggregator: None,
                da_gas_data: Default::default(),
                filter_id: None,
                perms: perms.clone(),
            })
            .collect();

        let simulations_by_op: Arc<HashMap<B256, MockOp>> = Arc::from(
            mock_ops
                .into_iter()
                .map(|op| (op.op.hash(), op))
                .collect::<HashMap<_, _>>(),
        );
        let simulations_by_op_cloned: Arc<HashMap<_, _>> = Arc::clone(&simulations_by_op);

        let mut simulator = MockSimulator::new();
        simulator
            .expect_simulate_validation()
            .withf(move |op, &trusted, &block_hash, &code_hash| {
                block_hash == current_block_hash
                    && code_hash == Some(expected_code_hash)
                    && simulations_by_op_cloned[&op.hash()].perms.trusted == trusted
            })
            .returning(move |op, _, _, _| {
                simulations_by_op[&op.hash()].simulation_result.as_ref()()
            });
        let mut entry_point = MockEntryPointV0_6::new();
        entry_point
            .expect_version()
            .returning(move || EntryPointVersion::V0_6);
        entry_point
            .expect_address()
            .return_const(chain_spec.entry_point_address_v0_6);
        for call_res in mock_handle_ops_call_results {
            entry_point
                .expect_call_handle_ops()
                .times(..=1)
                .withf(move |_, &b, _, _, &p, _| b == sender_eoa && p == proxy_address)
                .return_once(|_, _, _, _, _, _| Ok(call_res));
        }
        for deposit in mock_paymaster_deposits {
            entry_point
                .expect_balance_of()
                .times(..=1)
                .return_once(move |_, _| Ok(deposit));
        }

        let signatures_by_aggregator: HashMap<_, _> = mock_aggregators
            .into_iter()
            .map(|agg| (agg.address, agg.signature))
            .collect();

        let mut provider = MockEvmProvider::new();
        provider
            .expect_get_latest_block_hash_and_number()
            .returning(move || Ok((current_block_hash, 0)));

        let mut fee_estimator = MockFeeEstimator::new();
        fee_estimator
            .expect_required_bundle_fees()
            .returning(move |_, _| {
                Ok((
                    GasFees {
                        max_fee_per_gas: base_fee + max_priority_fee_per_gas,
                        max_priority_fee_per_gas,
                    },
                    base_fee,
                ))
            });
        fee_estimator
            .expect_required_op_fees()
            .returning(move |_| GasFees {
                max_fee_per_gas: base_fee + max_priority_fee_per_gas,
                max_priority_fee_per_gas,
            });

        if notify_condition_not_met {
            for (addr, slots) in actual_storage.0.into_iter() {
                let values = slots.values().cloned().collect::<Vec<_>>();
                provider
                    .expect_batch_get_storage_at()
                    .withf(move |a, s| *a == addr && s.iter().all(|slot| slots.contains_key(slot)))
                    .returning(move |_, _| Ok(values.clone()));
            }
        }

        entry_point
            .expect_aggregate_signatures()
            .returning(move |address, _| Ok(signatures_by_aggregator[&address]().unwrap()));

        let (event_sender, _) = broadcast::channel(16);

        let mut da_oracle = MockDAGasOracleSync::new();
        let block_data = DAGasBlockData::Bedrock(BedrockDAGasBlockData {
            base_fee_scalar: 1,
            l1_base_fee: 1,
            blob_base_fee: 1,
            blob_base_fee_scalar: 1,
        });
        let bd_cloned = block_data.clone();
        da_oracle
            .expect_da_block_data()
            .returning(move |_| Ok(bd_cloned.clone()));
        da_oracle
            .expect_calc_da_gas_sync()
            .returning(move |_, bd, _, _| {
                assert_eq!(*bd, block_data);
                DEFAULT_DA_PVG
            });

        let mut registry = ContractRegistry::<Arc<dyn SignatureAggregator>>::default();
        for agg in aggregators {
            registry.register(agg.address(), Arc::new(agg));
        }
        chain_spec.set_signature_aggregators(Arc::new(registry));

        let submission_proxy: Option<Arc<dyn SubmissionProxy>> =
            proxy.map(|p| Arc::new(p) as Arc<dyn SubmissionProxy>);

        let mut proposer = BundleProposerImpl::new(
            "test".to_string(),
            ProvidersWithEntryPoint::new(
                Arc::new(provider),
                Arc::new(entry_point),
                Some(Arc::new(da_oracle)),
                Arc::new(fee_estimator),
            ),
            BundleProposerProviders::new(simulator),
            Settings {
                chain_spec,
                target_bundle_gas: 10_000_000,
                max_bundle_gas: 25_000_000,
                sender_eoa,
                da_gas_tracking_enabled,
                max_expected_storage_slots: MAX_EXPECTED_STORAGE_SLOTS,
                verification_gas_limit_efficiency_reject_threshold: 0.5,
                submission_proxy,
            },
            event_sender,
        );

        if notify_condition_not_met {
            proposer.notify_condition_not_met();
        }

        proposer
            .make_bundle(ops, current_block_hash, max_bundle_fee, None, false)
            .await
    }

    fn address(n: u8) -> Address {
        let mut bytes = [0_u8; 20];
        bytes[0] = n;
        Address::from_slice(&bytes)
    }

    fn hash(n: u8) -> B256 {
        let mut bytes = [0_u8; 32];
        bytes[0] = n;
        B256::from_slice(&bytes)
    }

    fn bytes(n: u8) -> Bytes {
        Bytes::from([n])
    }

    // UOs require PVG to pass the PVG check even when fees are 0
    const DEFAULT_PVG: u128 = 1_000_000;
    const DEFAULT_DA_PVG: u128 = 100_000;

    fn op_with_sender(sender: Address) -> UserOperation {
        op_from_required(UserOperationRequiredFields {
            sender,
            pre_verification_gas: DEFAULT_PVG,
            ..Default::default()
        })
    }

    fn op_with_sender_paymaster(sender: Address, paymaster: Address) -> UserOperation {
        op_from_required(UserOperationRequiredFields {
            sender,
            paymaster_and_data: paymaster.to_vec().into(),
            pre_verification_gas: DEFAULT_PVG,
            ..Default::default()
        })
    }

    fn op_with_sender_factory(sender: Address, factory: Address) -> UserOperation {
        op_from_required(UserOperationRequiredFields {
            sender,
            init_code: factory.to_vec().into(),
            pre_verification_gas: DEFAULT_PVG,
            ..Default::default()
        })
    }

    fn op_with_sender_aggregator(
        sender: Address,
        aggregator: Address,
        new_signature: Bytes,
    ) -> UserOperation {
        let mut op = op_from_required(UserOperationRequiredFields {
            sender,
            pre_verification_gas: DEFAULT_PVG,
            ..Default::default()
        });
        op = op.transform_for_aggregator(
            &ChainSpec::default(),
            aggregator,
            AggregatorCosts::default(),
            new_signature,
        );
        op
    }

    fn op_with_sender_factory_paymaster(
        sender: Address,
        factory: Address,
        paymaster: Address,
    ) -> UserOperation {
        op_from_required(UserOperationRequiredFields {
            sender,
            init_code: factory.to_vec().into(),
            paymaster_and_data: paymaster.to_vec().into(),
            pre_verification_gas: DEFAULT_PVG,
            ..Default::default()
        })
    }

    fn op_with_sender_and_fees(
        sender: Address,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        pre_verification_gas: u128,
    ) -> UserOperation {
        op_from_required(UserOperationRequiredFields {
            sender,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            pre_verification_gas,
            ..Default::default()
        })
    }

    fn default_op() -> UserOperation {
        op_from_required(UserOperationRequiredFields {
            pre_verification_gas: DEFAULT_PVG,
            ..Default::default()
        })
    }

    fn op_with_sender_call_gas_limit(sender: Address, call_gas_limit: u128) -> UserOperation {
        op_from_required(UserOperationRequiredFields {
            sender,
            call_gas_limit,
            pre_verification_gas: DEFAULT_PVG,
            ..Default::default()
        })
    }

    fn op_with_sender_call_gas_limit_and_fees(
        sender: Address,
        call_gas_limit: u128,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> UserOperation {
        op_from_required(UserOperationRequiredFields {
            sender,
            call_gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            pre_verification_gas: DEFAULT_PVG,
            ..Default::default()
        })
    }

    fn op_with_gas(
        pre_verification_gas: u128,
        call_gas_limit: u128,
        verification_gas_limit: u128,
        with_paymaster: bool,
    ) -> UserOperation {
        op_from_required(UserOperationRequiredFields {
            pre_verification_gas,
            call_gas_limit,
            verification_gas_limit,
            paymaster_and_data: if with_paymaster {
                Bytes::from(vec![0; 20])
            } else {
                Default::default()
            },
            ..Default::default()
        })
    }

    fn op_from_required(required: UserOperationRequiredFields) -> UserOperation {
        UserOperationBuilder::new(&ChainSpec::default(), required).build()
    }

    fn mock_signature_aggregator(address: Address, signature: Bytes) -> MockSignatureAggregator {
        let mut agg = MockSignatureAggregator::default();
        agg.expect_address().return_const(address);
        agg.expect_costs().return_const(AggregatorCosts::default());
        agg.expect_aggregate_signatures()
            .returning(move |_| Ok(signature.clone()));
        agg
    }
}
