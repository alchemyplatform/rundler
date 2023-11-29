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
    cmp,
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    mem,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use async_trait::async_trait;
use ethers::types::{Address, BlockId, Bytes, H256, U256};
use futures::future;
use futures_util::TryFutureExt;
use linked_hash_map::LinkedHashMap;
#[cfg(test)]
use mockall::automock;
use rundler_pool::{PoolOperation, PoolServer};
use rundler_provider::{EntryPoint, HandleOpsOut, Provider};
use rundler_sim::{
    gas::{self, GasOverheads},
    EntityInfo, EntityInfos, ExpectedStorage, FeeEstimator, PriorityFeeMode, SimulationError,
    SimulationSuccess, SimulationViolation, Simulator, ViolationError,
};
use rundler_types::{
    Entity, EntityType, EntityUpdate, EntityUpdateType, GasFees, Timestamp, UserOperation,
    UserOpsPerAggregator,
};
use rundler_utils::{emit::WithEntryPoint, math};
use tokio::{sync::broadcast, try_join};
use tracing::{error, info, warn};

use crate::emit::{BuilderEvent, OpRejectionReason, SkipReason};

/// A user op must be valid for at least this long into the future to be included.
const TIME_RANGE_BUFFER: Duration = Duration::from_secs(60);
/// Extra buffer percent to add on the bundle transaction gas estimate to be sure it will be enough
const BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT: u64 = 5;

#[derive(Debug, Default)]
pub(crate) struct Bundle {
    pub(crate) ops_per_aggregator: Vec<UserOpsPerAggregator>,
    pub(crate) gas_estimate: U256,
    pub(crate) gas_fees: GasFees,
    pub(crate) expected_storage: ExpectedStorage,
    pub(crate) rejected_ops: Vec<UserOperation>,
    pub(crate) entity_updates: Vec<EntityUpdate>,
}

impl Bundle {
    pub(crate) fn len(&self) -> usize {
        self.ops_per_aggregator
            .iter()
            .map(|ops| ops.user_ops.len())
            .sum()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ops_per_aggregator.is_empty()
    }

    pub(crate) fn iter_ops(&self) -> impl Iterator<Item = &UserOperation> + '_ {
        self.ops_per_aggregator.iter().flat_map(|ops| &ops.user_ops)
    }
}

#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait BundleProposer: Send + Sync + 'static {
    async fn make_bundle(&self, required_fees: Option<GasFees>) -> anyhow::Result<Bundle>;
}

#[derive(Debug)]
pub(crate) struct BundleProposerImpl<S, E, P, C>
where
    S: Simulator,
    E: EntryPoint,
    P: Provider,
    C: PoolServer,
{
    builder_index: u64,
    pool: C,
    simulator: S,
    entry_point: E,
    provider: Arc<P>,
    settings: Settings,
    fee_estimator: FeeEstimator<P>,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
}

#[derive(Debug)]
pub(crate) struct Settings {
    pub(crate) chain_id: u64,
    pub(crate) max_bundle_size: u64,
    pub(crate) max_bundle_gas: u64,
    pub(crate) beneficiary: Address,
    pub(crate) bundle_priority_fee_overhead_percent: u64,
    pub(crate) priority_fee_mode: PriorityFeeMode,
}

#[async_trait]
impl<S, E, P, C> BundleProposer for BundleProposerImpl<S, E, P, C>
where
    S: Simulator,
    E: EntryPoint,
    P: Provider,
    C: PoolServer,
{
    async fn make_bundle(&self, required_fees: Option<GasFees>) -> anyhow::Result<Bundle> {
        let (ops, block_hash, bundle_fees) = try_join!(
            self.get_ops_from_pool(),
            self.provider
                .get_latest_block_hash()
                .map_err(anyhow::Error::from),
            self.fee_estimator.required_bundle_fees(required_fees)
        )?;

        // Limit the amount of gas in the bundle
        tracing::debug!(
            "Builder index: {}, starting bundle proposal with {} ops",
            self.builder_index,
            ops.len(),
        );

        // Do an initial filtering of ops that we want to simulate.
        let (ops, gas_limit) = self.limit_user_operations_for_simulation(ops);
        tracing::debug!(
            "Builder index: {}, bundle proposal after limit had {} ops and {:?} gas limit",
            self.builder_index,
            ops.len(),
            gas_limit
        );

        // Determine fees required for ops to be included in a bundle, and filter out ops that don't
        // meet the requirements. Simulate unfiltered ops.
        let required_op_fees = self.fee_estimator.required_op_fees(bundle_fees);
        let simulation_futures = ops
            .iter()
            .filter(|op| {
                if op.uo.max_fee_per_gas >= required_op_fees.max_fee_per_gas
                    && op.uo.max_priority_fee_per_gas >= required_op_fees.max_priority_fee_per_gas
                {
                    true
                } else {
                    self.emit(BuilderEvent::skipped_op(
                        self.builder_index,
                        self.op_hash(&op.uo),
                        SkipReason::InsufficientFees {
                            required_fees: required_op_fees,
                            actual_fees: GasFees {
                                max_fee_per_gas: op.uo.max_fee_per_gas,
                                max_priority_fee_per_gas: op.uo.max_priority_fee_per_gas,
                            },
                        },
                    ));
                    false
                }
            })
            .cloned()
            .map(|op| self.simulate_validation(op, block_hash));
        let ops_with_simulations_future = future::join_all(simulation_futures);
        let all_paymaster_addresses = ops.iter().filter_map(|op| op.uo.paymaster());
        let balances_by_paymaster_future =
            self.get_balances_by_paymaster(all_paymaster_addresses, block_hash);
        let (ops_with_simulations, balances_by_paymaster) =
            tokio::join!(ops_with_simulations_future, balances_by_paymaster_future);
        let balances_by_paymaster = balances_by_paymaster?;
        let ops_with_simulations = ops_with_simulations
            .into_iter()
            .filter_map(|result| match result {
                Ok(success) => Some(success),
                Err(error) => {
                    error!("Failed to resimulate op: {error:?}");
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut context = self
            .assemble_context(ops_with_simulations, balances_by_paymaster)
            .await;
        while !context.is_empty() {
            let gas_estimate = self.estimate_gas_rejecting_failed_ops(&mut context).await?;
            if let Some(gas_estimate) = gas_estimate {
                tracing::debug!(
                    "Builder index: {}, bundle proposal succeeded with {} ops and {:?} gas limit",
                    self.builder_index,
                    context.iter_ops().count(),
                    gas_estimate
                );

                let mut expected_storage = ExpectedStorage::default();
                for op in context.iter_ops_with_simulations() {
                    expected_storage.merge(&op.simulation.expected_storage)?;
                }

                return Ok(Bundle {
                    ops_per_aggregator: context.to_ops_per_aggregator(),
                    gas_estimate,
                    gas_fees: bundle_fees,
                    expected_storage,
                    rejected_ops: context.rejected_ops.iter().map(|po| po.0.clone()).collect(),
                    entity_updates: context.entity_updates.into_values().collect(),
                });
            }
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

impl<S, E, P, C> BundleProposerImpl<S, E, P, C>
where
    S: Simulator,
    E: EntryPoint,
    P: Provider,
    C: PoolServer,
{
    pub(crate) fn new(
        builder_index: u64,
        pool: C,
        simulator: S,
        entry_point: E,
        provider: Arc<P>,
        settings: Settings,
        event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    ) -> Self {
        Self {
            builder_index,
            pool,
            simulator,
            entry_point,
            provider: provider.clone(),
            fee_estimator: FeeEstimator::new(
                provider,
                settings.chain_id,
                settings.priority_fee_mode,
                settings.bundle_priority_fee_overhead_percent,
            ),
            settings,
            event_sender,
        }
    }

    async fn simulate_validation(
        &self,
        op: PoolOperation,
        block_hash: H256,
    ) -> anyhow::Result<(PoolOperation, Result<SimulationSuccess, SimulationError>)> {
        let result = self
            .simulator
            .simulate_validation(op.uo.clone(), Some(block_hash), Some(op.expected_code_hash))
            .await;
        match result {
            Ok(success) => Ok((op, Ok(success))),
            Err(error) => match error {
                SimulationError {
                    violation_error: ViolationError::Violations(_),
                    entity_infos: _,
                } => Ok((op, Err(error))),
                SimulationError {
                    violation_error: ViolationError::Other(error),
                    entity_infos: _,
                } => Err(error),
            },
        }
    }

    async fn assemble_context(
        &self,
        ops_with_simulations: Vec<(PoolOperation, Result<SimulationSuccess, SimulationError>)>,
        mut balances_by_paymaster: HashMap<Address, U256>,
    ) -> ProposalContext {
        let all_sender_addresses: HashSet<Address> = ops_with_simulations
            .iter()
            .map(|(op, _)| op.uo.sender)
            .collect();
        let mut groups_by_aggregator = LinkedHashMap::<Option<Address>, AggregatorGroup>::new();
        let mut rejected_ops = Vec::<(UserOperation, EntityInfos)>::new();
        let mut entity_updates: BTreeMap<Address, EntityUpdate> = BTreeMap::new();
        let mut paymasters_to_reject = Vec::<EntityInfo>::new();

        let ov = GasOverheads::default();
        let mut gas_spent = ov.transaction_gas_overhead;
        for (po, simulation) in ops_with_simulations {
            let op = po.clone().uo;
            let simulation = match simulation {
                Ok(simulation) => simulation,
                Err(error) => {
                    self.emit(BuilderEvent::rejected_op(
                        self.builder_index,
                        self.op_hash(&op),
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
                        let infos = entity_infos.map_or(po.entity_infos, |e| e);
                        ProposalContext::add_entity_updates(violations, infos, &mut entity_updates);
                        rejected_ops.push((op, po.entity_infos));
                    }
                    continue;
                }
            };

            // filter time range
            if !simulation
                .valid_time_range
                .contains(Timestamp::now(), TIME_RANGE_BUFFER)
            {
                self.emit(BuilderEvent::skipped_op(
                    self.builder_index,
                    self.op_hash(&op),
                    SkipReason::InvalidTimeRange {
                        valid_range: simulation.valid_time_range,
                    },
                ));
                rejected_ops.push((op, po.entity_infos));
                continue;
            }

            // Skip this op if the bundle does not have enough remaining gas to execute it.
            let required_gas = get_gas_required_for_op(
                gas_spent,
                self.settings.chain_id,
                ov,
                &op,
                simulation.requires_post_op,
            );
            if required_gas > self.settings.max_bundle_gas.into() {
                continue;
            }

            if let Some(&other_sender) = simulation
                .accessed_addresses
                .iter()
                .find(|&address| *address != op.sender && all_sender_addresses.contains(address))
            {
                // Exclude ops that access the sender of another op in the
                // batch, but don't reject them (remove them from pool).
                info!("Excluding op from {:?} because it accessed the address of another sender in the bundle.", op.sender);
                self.emit(BuilderEvent::skipped_op(
                    self.builder_index,
                    self.op_hash(&op),
                    SkipReason::AccessedOtherSender { other_sender },
                ));
                continue;
            }
            if let Some(paymaster) = op.paymaster() {
                let Some(balance) = balances_by_paymaster.get_mut(&paymaster) else {
                    error!("Op had paymaster with unknown balance, but balances should have been loaded for all paymasters in bundle.");
                    continue;
                };
                let max_cost = gas::user_operation_max_gas_cost(&op);
                if *balance < max_cost {
                    info!("Rejected paymaster {paymaster:?} because its balance {balance:?} was too low.");
                    paymasters_to_reject.push(po.entity_infos.paymaster.unwrap());
                    continue;
                } else {
                    *balance -= max_cost;
                }
            }

            // Update the running gas that would need to be be spent to execute the bundle so far.
            gas_spent += gas::user_operation_execution_gas_limit(
                &op,
                self.settings.chain_id,
                false,
                simulation.requires_post_op,
            );

            groups_by_aggregator
                .entry(simulation.aggregator_address())
                .or_default()
                .ops_with_simulations
                .push(OpWithSimulation { op, simulation });
        }
        let mut context = ProposalContext {
            groups_by_aggregator,
            rejected_ops,
            entity_updates,
        };
        for paymaster in paymasters_to_reject {
            // No need to update aggregator signatures because we haven't computed them yet.
            let _ =
                context.reject_entity(Entity::paymaster(paymaster.address), paymaster.is_staked);
        }
        self.compute_all_aggregator_signatures(&mut context).await;
        context
    }

    async fn reject_index(&self, context: &mut ProposalContext, i: usize) {
        let changed_aggregator = context.reject_index(i);
        self.compute_aggregator_signatures(context, &changed_aggregator)
            .await;
    }

    async fn reject_entity(&self, context: &mut ProposalContext, entity: Entity, is_staked: bool) {
        let changed_aggregators = context.reject_entity(entity, is_staked);
        self.compute_aggregator_signatures(context, &changed_aggregators)
            .await;
    }

    async fn compute_all_aggregator_signatures(&self, context: &mut ProposalContext) {
        let aggregators: Vec<_> = context
            .groups_by_aggregator
            .keys()
            .flatten()
            .copied()
            .collect();
        self.compute_aggregator_signatures(context, &aggregators)
            .await;
    }

    async fn compute_aggregator_signatures<'a>(
        &self,
        context: &mut ProposalContext,
        aggregators: impl IntoIterator<Item = &'a Address>,
    ) {
        let signature_futures = aggregators.into_iter().filter_map(|&aggregator| {
            context
                .groups_by_aggregator
                .get(&Some(aggregator))
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
        context: &mut ProposalContext,
    ) -> anyhow::Result<Option<U256>> {
        // sum up the gas needed for all the ops in the bundle
        // and apply an overhead multiplier
        let gas = math::increase_by_percent(
            context.get_bundle_gas_limit(self.settings.chain_id),
            BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT,
        );

        // call handle ops with the bundle to filter any rejected ops before sending
        let handle_ops_out = self
            .entry_point
            .call_handle_ops(
                context.to_ops_per_aggregator(),
                self.settings.beneficiary,
                gas,
            )
            .await
            .context("should call handle ops with candidate bundle")?;
        match handle_ops_out {
            HandleOpsOut::Success => Ok(Some(gas)),
            HandleOpsOut::FailedOp(index, message) => {
                self.emit(BuilderEvent::rejected_op(
                    self.builder_index,
                    self.op_hash(&context.get_op_at(index)?.op),
                    OpRejectionReason::FailedInBundle {
                        message: Arc::new(message.clone()),
                    },
                ));
                self.process_failed_op(context, index, message).await?;
                Ok(None)
            }
            HandleOpsOut::SignatureValidationFailed(aggregator) => {
                info!("Rejected aggregator {aggregator:?} because its signature validation failed during gas estimation.");
                self.reject_entity(context, Entity::aggregator(aggregator), false)
                    .await;
                Ok(None)
            }
            HandleOpsOut::PostOpRevert => {
                warn!("PostOpShortRevert error during gas estimation due to bug in the 0.6 entry point contract. Removing the offending op from the bundle.");
                self.process_post_op_revert(context, gas).await?;
                Ok(None)
            }
        }
    }

    async fn get_ops_from_pool(&self) -> anyhow::Result<Vec<PoolOperation>> {
        // Use builder's index as the shard index to ensure that two builders don't
        // attempt to bundle the same operations.
        //
        // NOTE: this assumes that the pool server has as many shards as there
        // are builders.
        self.pool
            .get_ops(
                self.entry_point.address(),
                self.settings.max_bundle_size,
                self.builder_index,
            )
            .await
            .context("should get ops from pool")
    }

    async fn get_balances_by_paymaster(
        &self,
        addresses: impl Iterator<Item = Address>,
        block_hash: H256,
    ) -> anyhow::Result<HashMap<Address, U256>> {
        let futures = addresses.map(|address| async move {
            let deposit = self
                .entry_point
                .balance_of(address, Some(BlockId::Hash(block_hash)))
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
        group: &AggregatorGroup,
    ) -> (Address, anyhow::Result<Option<Bytes>>) {
        let ops = group
            .ops_with_simulations
            .iter()
            .map(|op_with_simulation| op_with_simulation.op.clone())
            .collect();
        let result = Arc::clone(&self.provider)
            .aggregate_signatures(aggregator, ops)
            .await
            .map_err(anyhow::Error::from);
        (aggregator, result)
    }

    async fn process_failed_op(
        &self,
        context: &mut ProposalContext,
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
                        .map_or(false, |f| f.is_staked),
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
                        .map_or(false, |p| p.is_staked),
                )
                .await;
            }
            _ => {
                info!(
                    "Rejected op because it failed during gas estimation with message {message}."
                );
                self.reject_index(context, index).await;
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
        context: &mut ProposalContext,
        gas: U256,
    ) -> anyhow::Result<()> {
        let agg_groups = context.to_ops_per_aggregator();
        let mut op_index = 0;
        let mut futures: Vec<Pin<Box<dyn Future<Output = Vec<usize>> + Send>>> = vec![];

        for agg_group in agg_groups {
            // For non-aggregated ops, re-simulate each op individually
            if agg_group.aggregator.is_zero() {
                for op in agg_group.user_ops {
                    futures.push(Box::pin(
                        self.check_for_post_op_revert_single_op(op, gas, op_index),
                    ));
                    op_index += 1;
                }
            } else {
                // For aggregated ops, re-simulate the group
                let len = agg_group.user_ops.len();
                futures.push(Box::pin(
                    self.check_for_post_op_revert_agg_ops(agg_group, gas, op_index),
                ));
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
                self.builder_index,
                self.op_hash(&context.get_op_at(index)?.op),
                OpRejectionReason::FailedInBundle {
                    message: Arc::new("post op reverted leading to entry point revert".to_owned()),
                },
            ));
            self.reject_index(context, index).await;
        }

        Ok(())
    }

    async fn check_for_post_op_revert_single_op(
        &self,
        op: UserOperation,
        gas: U256,
        op_index: usize,
    ) -> Vec<usize> {
        let op_hash = self.op_hash(&op);
        let bundle = vec![UserOpsPerAggregator {
            aggregator: Address::zero(),
            signature: Bytes::new(),
            user_ops: vec![op],
        }];
        let ret = self
            .entry_point
            .call_handle_ops(bundle, self.settings.beneficiary, gas)
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
        group: UserOpsPerAggregator,
        gas: U256,
        start_index: usize,
    ) -> Vec<usize> {
        let len = group.user_ops.len();
        let agg = group.aggregator;
        let bundle = vec![group];
        let ret = self
            .entry_point
            .call_handle_ops(bundle, self.settings.beneficiary, gas)
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
        ops: Vec<PoolOperation>,
    ) -> (Vec<PoolOperation>, u64) {
        // Make the bundle gas limit 10% higher here so that we simulate more UOs than we need in case that we end up dropping some UOs later so we can still pack a full bundle
        let mut gas_left = math::increase_by_percent(U256::from(self.settings.max_bundle_gas), 10);
        let mut ops_in_bundle = Vec::new();
        for op in ops {
            // Here we use optimistic gas limits for the UOs by assuming none of the paymaster UOs use postOp calls.
            // This way after simulation once we have determined if each UO actually uses a postOp call or not we can still pack a full bundle
            let gas = gas::user_operation_execution_gas_limit(
                &op.uo,
                self.settings.chain_id,
                false,
                false,
            );
            if gas_left < gas {
                self.emit(BuilderEvent::skipped_op(
                    self.builder_index,
                    self.op_hash(&op.uo),
                    SkipReason::GasLimit,
                ));
                continue;
            }
            gas_left -= gas;
            ops_in_bundle.push(op);
        }
        (
            ops_in_bundle,
            self.settings
                .max_bundle_gas
                .saturating_sub(gas_left.as_u64()),
        )
    }

    fn emit(&self, event: BuilderEvent) {
        let _ = self.event_sender.send(WithEntryPoint {
            entry_point: self.entry_point.address(),
            event,
        });
    }

    fn op_hash(&self, op: &UserOperation) -> H256 {
        op.op_hash(self.entry_point.address(), self.settings.chain_id)
    }
}

#[derive(Debug)]
struct OpWithSimulation {
    op: UserOperation,
    simulation: SimulationSuccess,
}

impl OpWithSimulation {
    fn op_with_replaced_sig(&self) -> UserOperation {
        let mut op = self.op.clone();
        if let Some(aggregator) = &self.simulation.aggregator {
            op.signature = aggregator.signature.clone();
        }
        op
    }
}

/// A struct used internally to represent the current state of a proposed bundle
/// as it goes through iterations. Contains similar data to the
/// `Vec<UserOpsPerAggregator>` that will eventually be passed to the entry
/// point, but contains extra context needed for the computation.
#[derive(Debug)]
struct ProposalContext {
    groups_by_aggregator: LinkedHashMap<Option<Address>, AggregatorGroup>,
    rejected_ops: Vec<(UserOperation, EntityInfos)>,
    // This is a BTreeMap so that the conversion to a Vec<EntityUpdate> is determinisitic, mainly for tests
    entity_updates: BTreeMap<Address, EntityUpdate>,
}

#[derive(Debug, Default)]
struct AggregatorGroup {
    ops_with_simulations: Vec<OpWithSimulation>,
    signature: Bytes,
}

impl ProposalContext {
    fn is_empty(&self) -> bool {
        self.groups_by_aggregator.is_empty()
    }

    fn apply_aggregation_signature_result(
        &mut self,
        aggregator: Address,
        result: anyhow::Result<Option<Bytes>>,
    ) {
        match result {
            Ok(Some(sig)) => self.groups_by_aggregator[&Some(aggregator)].signature = sig,
            Ok(None) => self.reject_aggregator(aggregator),
            Err(error) => {
                error!("Failed to compute aggregator signature: {error}");
                self.groups_by_aggregator.remove(&Some(aggregator));
            }
        }
    }

    fn get_op_at(&self, index: usize) -> anyhow::Result<&OpWithSimulation> {
        let mut remaining_i = index;
        for group in self.groups_by_aggregator.values() {
            if remaining_i < group.ops_with_simulations.len() {
                return Ok(&group.ops_with_simulations[remaining_i]);
            }
            remaining_i -= group.ops_with_simulations.len();
        }
        anyhow::bail!("op at {index} out of bounds")
    }

    /// Returns the address of the op's aggregator if the aggregator's signature
    /// may need to be recomputed.
    #[must_use = "rejected op but did not update aggregator signatures"]
    fn reject_index(&mut self, i: usize) -> Option<Address> {
        let mut remaining_i = i;
        let mut found_aggregator: Option<Option<Address>> = None;
        for (&aggregator, group) in &mut self.groups_by_aggregator {
            if remaining_i < group.ops_with_simulations.len() {
                let rejected = group.ops_with_simulations.remove(remaining_i);
                self.rejected_ops
                    .push((rejected.op, rejected.simulation.entity_infos));
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
            found_aggregator
        }
    }

    /// Returns the addresses of any aggregators whose signature may need to be recomputed.
    #[must_use = "rejected entity but did not update aggregator signatures"]
    fn reject_entity(&mut self, entity: Entity, is_staked: bool) -> Vec<Address> {
        let ret = match entity.kind {
            EntityType::Aggregator => {
                self.reject_aggregator(entity.address);
                vec![]
            }
            EntityType::Paymaster => self.reject_paymaster(entity.address),
            EntityType::Factory => self.reject_factory(entity.address),
            _ => vec![],
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
            },
        );
        ret
    }

    fn reject_aggregator(&mut self, address: Address) {
        self.groups_by_aggregator.remove(&Some(address));
    }

    fn reject_paymaster(&mut self, address: Address) -> Vec<Address> {
        self.filter_reject(|op| op.paymaster() == Some(address))
    }

    fn reject_factory(&mut self, address: Address) -> Vec<Address> {
        self.filter_reject(|op| op.factory() == Some(address))
    }

    /// Reject all ops that match the filter, and return the addresses of any aggregators
    /// whose signature may need to be recomputed.
    fn filter_reject(&mut self, filter: impl Fn(&UserOperation) -> bool) -> Vec<Address> {
        let mut changed_aggregators: Vec<Address> = vec![];
        let mut aggregators_to_remove: Vec<Option<Address>> = vec![];
        for (&aggregator, group) in &mut self.groups_by_aggregator {
            // I sure wish `Vec::drain_filter` were stable.
            let group_uses_rejected_entity =
                group.ops_with_simulations.iter().any(|op| filter(&op.op));
            if group_uses_rejected_entity {
                for op in mem::take(&mut group.ops_with_simulations) {
                    if !filter(&op.op) {
                        group.ops_with_simulations.push(op);
                    }
                }
                if group.ops_with_simulations.is_empty() {
                    aggregators_to_remove.push(aggregator);
                } else if let Some(aggregator) = aggregator {
                    changed_aggregators.push(aggregator);
                }
            }
        }
        for aggregator in aggregators_to_remove {
            self.groups_by_aggregator.remove(&aggregator);
        }
        changed_aggregators
    }

    fn to_ops_per_aggregator(&self) -> Vec<UserOpsPerAggregator> {
        self.groups_by_aggregator
            .iter()
            .map(|(&aggregator, group)| UserOpsPerAggregator {
                user_ops: group
                    .ops_with_simulations
                    .iter()
                    .map(|op| op.op_with_replaced_sig())
                    .collect(),
                aggregator: aggregator.unwrap_or_default(),
                signature: group.signature.clone(),
            })
            .collect()
    }

    fn get_bundle_gas_limit(&self, chain_id: u64) -> U256 {
        let ov = GasOverheads::default();
        let mut gas_spent = ov.transaction_gas_overhead;
        let mut max_gas = U256::zero();
        for op_with_sim in self.iter_ops_with_simulations() {
            let op = &op_with_sim.op;
            let required_gas = get_gas_required_for_op(
                gas_spent,
                chain_id,
                ov,
                op,
                op_with_sim.simulation.requires_post_op,
            );
            max_gas = cmp::max(max_gas, required_gas);
            gas_spent += gas::user_operation_gas_limit(
                op,
                chain_id,
                false,
                op_with_sim.simulation.requires_post_op,
            );
        }
        max_gas
    }

    fn iter_ops_with_simulations(&self) -> impl Iterator<Item = &OpWithSimulation> + '_ {
        self.groups_by_aggregator
            .values()
            .flat_map(|group| &group.ops_with_simulations)
    }

    fn iter_ops(&self) -> impl Iterator<Item = &UserOperation> + '_ {
        self.iter_ops_with_simulations().map(|op| &op.op)
    }

    // Go through the simulation violations for a given op and add all entity updates to pass to the mempool in entity_updates
    fn add_entity_updates(
        violations: Vec<SimulationViolation>,
        entity_infos: EntityInfos,
        entity_updates: &mut BTreeMap<Address, EntityUpdate>,
    ) {
        // [EREP-020] When there is a staked factory any error in validation is attributed to it.
        if entity_infos.factory.map_or(false, |f| f.is_staked) {
            let factory = entity_infos.factory.unwrap();
            entity_updates.insert(
                factory.address,
                EntityUpdate {
                    entity: Entity {
                        kind: EntityType::Factory,
                        address: factory.address,
                    },
                    update_type: EntityUpdateType::StakedInvalidation,
                },
            );
            return;
        }

        // [EREP-030] When there is a staked sender (without a staked factory) any error in validation is attributed to it.
        if entity_infos.sender.is_staked {
            entity_updates.insert(
                entity_infos.sender.address,
                EntityUpdate {
                    entity: Entity {
                        kind: EntityType::Account,
                        address: entity_infos.sender.address,
                    },
                    update_type: EntityUpdateType::StakedInvalidation,
                },
            );
            return;
        }

        // If not a staked factory or sender, attribute errors to each entity directly.
        // For a given op, there can only be a single update per entity so we don't double count the [UREP-030] throttle penalty.
        for violation in violations {
            match violation {
                SimulationViolation::UsedForbiddenOpcode(entity, _, _) => {
                    ProposalContext::add_entity_update(entity, entity_infos, entity_updates)
                }
                SimulationViolation::UsedForbiddenPrecompile(entity, _, _) => {
                    ProposalContext::add_entity_update(entity, entity_infos, entity_updates)
                }
                SimulationViolation::AccessedUndeployedContract(entity, _) => {
                    ProposalContext::add_entity_update(entity, entity_infos, entity_updates)
                }
                SimulationViolation::InvalidStorageAccess(entity, _) => {
                    ProposalContext::add_entity_update(entity, entity_infos, entity_updates)
                }
                SimulationViolation::CalledBannedEntryPointMethod(entity) => {
                    ProposalContext::add_entity_update(entity, entity_infos, entity_updates)
                }
                SimulationViolation::CallHadValue(entity) => {
                    ProposalContext::add_entity_update(entity, entity_infos, entity_updates)
                }
                SimulationViolation::NotStaked(entity, _, _) => {
                    ProposalContext::add_entity_update(entity, entity_infos, entity_updates)
                }
                SimulationViolation::UnintendedRevertWithMessage(entity_type, _, address) => {
                    if let Some(entity_address) = address {
                        ProposalContext::add_entity_update(
                            Entity {
                                kind: entity_type,
                                address: entity_address,
                            },
                            entity_infos,
                            entity_updates,
                        );
                    }
                }
                SimulationViolation::UnintendedRevert(entity_type, address) => {
                    if let Some(entity_address) = address {
                        ProposalContext::add_entity_update(
                            Entity {
                                kind: entity_type,
                                address: entity_address,
                            },
                            entity_infos,
                            entity_updates,
                        );
                    }
                }
                SimulationViolation::OutOfGas(entity) => {
                    ProposalContext::add_entity_update(entity, entity_infos, entity_updates)
                }
                _ => continue,
            }
        }
    }

    // Add an entity update for the entity
    fn add_entity_update(
        entity: Entity,
        entity_infos: EntityInfos,
        update_map: &mut BTreeMap<Address, EntityUpdate>,
    ) {
        let entity_update = EntityUpdate {
            entity,
            update_type: ProposalContext::get_entity_update_type(entity.kind, entity_infos),
        };
        update_map.insert(entity.address, entity_update);
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
}

fn get_gas_required_for_op(
    gas_spent: U256,
    chain_id: u64,
    ov: GasOverheads,
    op: &UserOperation,
    requires_post_op: bool,
) -> U256 {
    let post_exec_req_gas = if requires_post_op {
        cmp::max(op.verification_gas_limit, ov.bundle_transaction_gas_buffer)
    } else {
        ov.bundle_transaction_gas_buffer
    };

    gas_spent
        + gas::user_operation_pre_verification_gas_limit(op, chain_id, false)
        + op.verification_gas_limit * 2
        + op.call_gas_limit
        + post_exec_req_gas
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use ethers::{types::H160, utils::parse_units};
    use rundler_pool::MockPoolServer;
    use rundler_provider::{AggregatorSimOut, MockEntryPoint, MockProvider};
    use rundler_sim::{MockSimulator, SimulationViolation, ViolationError};
    use rundler_types::ValidTimeRange;

    use super::*;

    #[tokio::test]
    async fn test_singleton_valid_bundle() {
        let op = UserOperation {
            pre_verification_gas: 1000.into(),
            verification_gas_limit: 10000.into(),
            call_gas_limit: 100000.into(),
            ..Default::default()
        };

        let bundle = simple_make_bundle(vec![MockOp {
            op: op.clone(),
            simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
        }])
        .await;

        let ov = GasOverheads::default();
        let expected_gas = math::increase_by_percent(
            op.pre_verification_gas
                + op.verification_gas_limit * 2
                + op.call_gas_limit
                + ov.bundle_transaction_gas_buffer
                + ov.transaction_gas_overhead,
            BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT,
        );

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
        let op = UserOperation::default();
        let bundle = simple_make_bundle(vec![MockOp {
            op: op.clone(),
            simulation_result: Box::new(|| {
                Err(SimulationError {
                    violation_error: ViolationError::Violations(vec![]),
                    entity_infos: None,
                })
            }),
        }])
        .await;
        assert!(bundle.ops_per_aggregator.is_empty());
        assert_eq!(bundle.rejected_ops, vec![op]);
    }

    #[tokio::test]
    async fn test_drops_but_not_rejects_on_simulation_failure() {
        let op = UserOperation::default();
        let bundle = simple_make_bundle(vec![MockOp {
            op: op.clone(),
            simulation_result: Box::new(|| {
                Err(SimulationError {
                    violation_error: ViolationError::Other(anyhow!("simulation failed")),
                    entity_infos: None,
                })
            }),
        }])
        .await;
        assert!(bundle.ops_per_aggregator.is_empty());
        assert!(bundle.rejected_ops.is_empty());
    }

    #[tokio::test]
    async fn test_rejects_on_signature_failure() {
        let op = UserOperation::default();
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
            let op = UserOperation::default();
            let bundle = simple_make_bundle(vec![MockOp {
                op: op.clone(),
                simulation_result: Box::new(move || {
                    Ok(SimulationSuccess {
                        valid_time_range: time_range,
                        ..Default::default()
                    })
                }),
            }])
            .await;
            assert!(bundle.ops_per_aggregator.is_empty());
            assert_eq!(bundle.rejected_ops, vec![op]);
        }
    }

    #[tokio::test]
    async fn test_drops_but_not_rejects_op_accessing_another_sender() {
        let op1 = op_with_sender(address(1));
        let op2 = op_with_sender(address(2));
        let bundle = simple_make_bundle(vec![
            MockOp {
                op: op1,
                simulation_result: Box::new(|| {
                    Ok(SimulationSuccess {
                        accessed_addresses: [address(1), address(2)].into(),
                        ..Default::default()
                    })
                }),
            },
            MockOp {
                op: op2.clone(),
                simulation_result: Box::new(|| {
                    Ok(SimulationSuccess {
                        accessed_addresses: [address(2)].into(),
                        ..Default::default()
                    })
                }),
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
    async fn test_drops_but_not_rejects_op_with_too_low_max_priority_fee() {
        // With 10% required overhead on priority fee, op1 should be excluded
        // but op2 accepted.
        let base_fee = U256::from(1000);
        let max_priority_fee_per_gas = U256::from(50);
        let op1 = op_with_sender_and_fees(address(1), 2054.into(), 54.into());
        let op2 = op_with_sender_and_fees(address(2), 2055.into(), 55.into());
        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            base_fee,
            max_priority_fee_per_gas,
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
    async fn test_drops_but_not_rejects_op_with_too_low_max_fee_per_gas() {
        let base_fee = U256::from(1000);
        let max_priority_fee_per_gas = U256::from(50);
        let op1 = op_with_sender_and_fees(address(1), 1054.into(), 55.into());
        let op2 = op_with_sender_and_fees(address(2), 1055.into(), 55.into());
        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            base_fee,
            max_priority_fee_per_gas,
        )
        .await;
        assert_eq!(
            bundle.gas_fees,
            GasFees {
                max_fee_per_gas: 1050.into(),
                max_priority_fee_per_gas: 50.into(),
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
        let unaggregated_op = op_with_sender(address(1));
        let aggregated_op_a1 = op_with_sender(address(2));
        let aggregated_op_a2 = op_with_sender(address(3));
        let aggregated_op_b = op_with_sender(address(4));
        let aggregator_a_address = address(10);
        let aggregator_b_address = address(11);
        let op_a1_aggregated_sig = 11;
        let op_a2_aggregated_sig = 12;
        let op_b_aggregated_sig = 21;
        let aggregator_a_signature = 101;
        let aggregator_b_signature = 102;
        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: unaggregated_op.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: aggregated_op_a1.clone(),
                    simulation_result: Box::new(move || {
                        Ok(SimulationSuccess {
                            aggregator: Some(AggregatorSimOut {
                                address: aggregator_a_address,
                                signature: bytes(op_a1_aggregated_sig),
                            }),
                            ..Default::default()
                        })
                    }),
                },
                MockOp {
                    op: aggregated_op_a2.clone(),
                    simulation_result: Box::new(move || {
                        Ok(SimulationSuccess {
                            aggregator: Some(AggregatorSimOut {
                                address: aggregator_a_address,
                                signature: bytes(op_a2_aggregated_sig),
                            }),
                            ..Default::default()
                        })
                    }),
                },
                MockOp {
                    op: aggregated_op_b.clone(),
                    simulation_result: Box::new(move || {
                        Ok(SimulationSuccess {
                            aggregator: Some(AggregatorSimOut {
                                address: aggregator_b_address,
                                signature: bytes(op_b_aggregated_sig),
                            }),
                            ..Default::default()
                        })
                    }),
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
            U256::zero(),
            U256::zero(),
        )
        .await;
        // Ops should be grouped by aggregator. Further, the `signature` field
        // of each op with an aggregator should be replaced with what was
        // returned from simulation.
        assert_eq!(
            HashSet::from_iter(bundle.ops_per_aggregator),
            HashSet::from([
                UserOpsPerAggregator {
                    user_ops: vec![unaggregated_op],
                    ..Default::default()
                },
                UserOpsPerAggregator {
                    user_ops: vec![
                        UserOperation {
                            signature: bytes(op_a1_aggregated_sig),
                            ..aggregated_op_a1
                        },
                        UserOperation {
                            signature: bytes(op_a2_aggregated_sig),
                            ..aggregated_op_a2
                        }
                    ],
                    aggregator: aggregator_a_address,
                    signature: bytes(aggregator_a_signature)
                },
                UserOpsPerAggregator {
                    user_ops: vec![UserOperation {
                        signature: bytes(op_b_aggregated_sig),
                        ..aggregated_op_b
                    }],
                    aggregator: aggregator_b_address,
                    signature: bytes(aggregator_b_signature)
                },
            ]),
        );
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
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: op3.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: op4.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: op5.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: op6.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
            ],
            vec![],
            vec![
                HandleOpsOut::FailedOp(0, "AA30: reject paymaster".to_string()),
                HandleOpsOut::FailedOp(1, "AA13: reject factory".to_string()),
                HandleOpsOut::Success,
            ],
            vec![deposit, deposit, deposit],
            U256::zero(),
            U256::zero(),
        )
        .await;

        assert_eq!(
            bundle.entity_updates,
            vec![
                EntityUpdate {
                    entity: Entity::paymaster(address(1)),
                    update_type: EntityUpdateType::UnstakedInvalidation,
                },
                EntityUpdate {
                    entity: Entity::factory(address(3)),
                    update_type: EntityUpdateType::UnstakedInvalidation,
                },
            ]
        );
        assert_eq!(bundle.rejected_ops, vec![]);
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op3, op6],
                ..Default::default()
            }]
        );
    }

    #[tokio::test]
    async fn test_bundle_gas_limit_simple() {
        let op1 = op_with_sender_call_gas_limit(address(1), U256::from(5_000_000));
        let op2 = op_with_sender_call_gas_limit(address(2), U256::from(4_000_000));
        let op3 = op_with_sender_call_gas_limit(address(3), U256::from(10_000_000));
        let op4 = op_with_sender_call_gas_limit(address(4), U256::from(10_000_000));
        let deposit = parse_units("1", "ether").unwrap().into();

        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: op1.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: op3.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: op4.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
            ],
            vec![],
            vec![HandleOpsOut::Success],
            vec![deposit, deposit, deposit],
            U256::zero(),
            U256::zero(),
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
        assert_eq!(
            bundle.gas_estimate,
            U256::from(math::increase_by_percent(
                9_000_000 + 5_000 + 21_000,
                BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT
            ))
        );
    }

    #[tokio::test]
    async fn test_bundle_gas_limit() {
        let op1 = op_with_gas(100_000.into(), 100_000.into(), 1_000_000.into(), false);
        let op2 = op_with_gas(100_000.into(), 100_000.into(), 200_000.into(), false);
        let chain_id = 1;
        let mut groups_by_aggregator = LinkedHashMap::new();
        groups_by_aggregator.insert(
            None,
            AggregatorGroup {
                ops_with_simulations: vec![
                    OpWithSimulation {
                        op: op1.clone(),
                        simulation: SimulationSuccess {
                            requires_post_op: false,
                            ..Default::default()
                        },
                    },
                    OpWithSimulation {
                        op: op2.clone(),
                        simulation: SimulationSuccess {
                            requires_post_op: false,
                            ..Default::default()
                        },
                    },
                ],
                signature: Default::default(),
            },
        );
        let context = ProposalContext {
            groups_by_aggregator,
            rejected_ops: vec![],
            entity_updates: BTreeMap::new(),
        };

        // The gas requirement from the execution of the first UO is: g >= p_1 + 2v_1 + c_1 + 5000
        // The gas requirement from the execution of the second UO is: g >= p_1 + v_1 + c_1 + p_2 + 2v_2 + c_2 + 5000
        // The first condition dominates and determines the expected gas limit
        let expected_gas_limit = op1.pre_verification_gas
            + op1.verification_gas_limit * 2
            + op1.call_gas_limit
            + 5_000
            + 21_000;

        assert_eq!(context.get_bundle_gas_limit(chain_id), expected_gas_limit);
    }

    #[tokio::test]
    async fn test_bundle_gas_limit_with_paymaster_op() {
        let op1 = op_with_gas(100_000.into(), 100_000.into(), 1_000_000.into(), true); // has paymaster
        let op2 = op_with_gas(100_000.into(), 100_000.into(), 200_000.into(), false);
        let chain_id = 1;
        let mut groups_by_aggregator = LinkedHashMap::new();
        groups_by_aggregator.insert(
            None,
            AggregatorGroup {
                ops_with_simulations: vec![
                    OpWithSimulation {
                        op: op1.clone(),
                        simulation: SimulationSuccess {
                            requires_post_op: true, // uses postOp
                            ..Default::default()
                        },
                    },
                    OpWithSimulation {
                        op: op2.clone(),
                        simulation: SimulationSuccess {
                            requires_post_op: false,
                            ..Default::default()
                        },
                    },
                ],
                signature: Default::default(),
            },
        );
        let context = ProposalContext {
            groups_by_aggregator,
            rejected_ops: vec![],
            entity_updates: BTreeMap::new(),
        };
        let gas_limit = context.get_bundle_gas_limit(chain_id);

        // The gas requirement from the execution of the first UO is: g >= p_1 + 3v_1 + c_1
        // The gas requirement from the execution of the second UO is: g >= p_1 + 3v_1 + c_1 + p_2 + 2v_2 + c_2 + 5000
        // The first condition dominates and determines the expected gas limit
        let expected_gas_limit = op1.pre_verification_gas
            + op1.verification_gas_limit * 3
            + op1.call_gas_limit
            + op2.pre_verification_gas
            + op2.verification_gas_limit * 2
            + op2.call_gas_limit
            + 21_000
            + 5_000;

        assert_eq!(gas_limit, expected_gas_limit);
    }

    #[tokio::test]
    async fn test_post_op_revert() {
        let op1 = op_with_sender(address(1));
        let bundle = mock_make_bundle(
            vec![MockOp {
                op: op1.clone(),
                simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
            }],
            vec![],
            vec![HandleOpsOut::PostOpRevert, HandleOpsOut::PostOpRevert],
            vec![],
            U256::zero(),
            U256::zero(),
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
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: op2.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
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
            U256::zero(),
            U256::zero(),
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
        let unaggregated_op = op_with_sender(address(1));
        let aggregated_op_a1 = op_with_sender(address(2));
        let aggregated_op_a2 = op_with_sender(address(3));
        let aggregator_a_address = address(10);
        let op_a1_aggregated_sig = 11;
        let op_a2_aggregated_sig = 12;
        let aggregator_a_signature = 101;
        let bundle = mock_make_bundle(
            vec![
                MockOp {
                    op: unaggregated_op.clone(),
                    simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
                },
                MockOp {
                    op: aggregated_op_a1.clone(),
                    simulation_result: Box::new(move || {
                        Ok(SimulationSuccess {
                            aggregator: Some(AggregatorSimOut {
                                address: aggregator_a_address,
                                signature: bytes(op_a1_aggregated_sig),
                            }),
                            ..Default::default()
                        })
                    }),
                },
                MockOp {
                    op: aggregated_op_a2.clone(),
                    simulation_result: Box::new(move || {
                        Ok(SimulationSuccess {
                            aggregator: Some(AggregatorSimOut {
                                address: aggregator_a_address,
                                signature: bytes(op_a2_aggregated_sig),
                            }),
                            ..Default::default()
                        })
                    }),
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
            U256::zero(),
            U256::zero(),
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

    struct MockOp {
        op: UserOperation,
        simulation_result:
            Box<dyn Fn() -> Result<SimulationSuccess, SimulationError> + Send + Sync>,
    }

    struct MockAggregator {
        address: Address,
        signature: Box<dyn Fn() -> anyhow::Result<Option<Bytes>> + Send + Sync>,
    }

    async fn simple_make_bundle(mock_ops: Vec<MockOp>) -> Bundle {
        mock_make_bundle(
            mock_ops,
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            U256::zero(),
            U256::zero(),
        )
        .await
    }

    async fn mock_make_bundle(
        mock_ops: Vec<MockOp>,
        mock_aggregators: Vec<MockAggregator>,
        mock_handle_ops_call_results: Vec<HandleOpsOut>,
        mock_paymaster_deposits: Vec<U256>,
        base_fee: U256,
        max_priority_fee_per_gas: U256,
    ) -> Bundle {
        let entry_point_address = address(123);
        let beneficiary = address(124);
        let current_block_hash = hash(125);
        let expected_code_hash = hash(126);
        let max_bundle_size = mock_ops.len() as u64;
        let ops: Vec<_> = mock_ops
            .iter()
            .map(|MockOp { op, .. }| PoolOperation {
                uo: op.clone(),
                expected_code_hash,
                ..Default::default()
            })
            .collect();

        let mut pool_client = MockPoolServer::new();
        pool_client
            .expect_get_ops()
            .returning(move |_, _, _| Ok(ops.clone()));

        let simulations_by_op: HashMap<_, _> = mock_ops
            .into_iter()
            .map(|op| (op.op.op_hash(entry_point_address, 0), op.simulation_result))
            .collect();
        let mut simulator = MockSimulator::new();
        simulator
            .expect_simulate_validation()
            .withf(move |_, &block_hash, &code_hash| {
                block_hash == Some(current_block_hash) && code_hash == Some(expected_code_hash)
            })
            .returning(move |op, _, _| simulations_by_op[&op.op_hash(entry_point_address, 0)]());
        let mut entry_point = MockEntryPoint::new();
        entry_point
            .expect_address()
            .return_const(entry_point_address);
        for call_res in mock_handle_ops_call_results {
            entry_point
                .expect_call_handle_ops()
                .times(..=1)
                .withf(move |_, &b, _| b == beneficiary)
                .return_once(|_, _, _| Ok(call_res));
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
        let mut provider = MockProvider::new();
        provider
            .expect_get_latest_block_hash()
            .returning(move || Ok(current_block_hash));
        provider
            .expect_get_base_fee()
            .returning(move || Ok(base_fee));
        provider
            .expect_get_max_priority_fee()
            .returning(move || Ok(max_priority_fee_per_gas));
        provider
            .expect_aggregate_signatures()
            .returning(move |address, _| Ok(signatures_by_aggregator[&address]()?));
        let (event_sender, _) = broadcast::channel(16);
        let proposer = BundleProposerImpl::new(
            0,
            pool_client,
            simulator,
            entry_point,
            Arc::new(provider),
            Settings {
                chain_id: 0,
                max_bundle_size,
                max_bundle_gas: 10_000_000,
                beneficiary,
                priority_fee_mode: PriorityFeeMode::PriorityFeeIncreasePercent(10),
                bundle_priority_fee_overhead_percent: 0,
            },
            event_sender,
        );
        proposer
            .make_bundle(None)
            .await
            .expect("should make a bundle")
    }

    fn address(n: u8) -> Address {
        let mut bytes = [0_u8; 20];
        bytes[0] = n;
        H160(bytes)
    }

    fn hash(n: u8) -> H256 {
        let mut bytes = [0_u8; 32];
        bytes[0] = n;
        H256(bytes)
    }

    fn bytes(n: u8) -> Bytes {
        Bytes::from([n])
    }

    fn op_with_sender(sender: Address) -> UserOperation {
        UserOperation {
            sender,
            ..Default::default()
        }
    }

    fn op_with_sender_paymaster(sender: Address, paymaster: Address) -> UserOperation {
        UserOperation {
            sender,
            paymaster_and_data: paymaster.as_bytes().to_vec().into(),
            ..Default::default()
        }
    }

    fn op_with_sender_factory(sender: Address, factory: Address) -> UserOperation {
        UserOperation {
            sender,
            init_code: factory.as_bytes().to_vec().into(),
            ..Default::default()
        }
    }

    fn op_with_sender_and_fees(
        sender: Address,
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
    ) -> UserOperation {
        UserOperation {
            sender,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            ..Default::default()
        }
    }

    fn op_with_sender_call_gas_limit(sender: Address, call_gas_limit: U256) -> UserOperation {
        UserOperation {
            sender,
            call_gas_limit,
            ..Default::default()
        }
    }

    fn op_with_gas(
        pre_verification_gas: U256,
        call_gas_limit: U256,
        verification_gas_limit: U256,
        with_paymaster: bool,
    ) -> UserOperation {
        UserOperation {
            pre_verification_gas,
            call_gas_limit,
            verification_gas_limit,
            paymaster_and_data: if with_paymaster {
                Bytes::from(vec![0; 20])
            } else {
                Default::default()
            },
            ..Default::default()
        }
    }
}
