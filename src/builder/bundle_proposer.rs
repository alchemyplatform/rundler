use std::{
    collections::{HashMap, HashSet},
    mem,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use ethers::types::{Address, Bytes, H256, U256};
use futures::future;
use linked_hash_map::LinkedHashMap;
#[cfg(test)]
use mockall::automock;
use tokio::{sync::broadcast, try_join};
use tonic::{async_trait, transport::Channel};
use tracing::{error, info};

use crate::{
    builder::emit::{BuilderEvent, OpRejectionReason, SkipReason},
    common::{
        contracts::entry_point::UserOpsPerAggregator,
        emit::WithEntryPoint,
        gas::{FeeEstimator, GasFees, PriorityFeeMode},
        math,
        protos::{
            self,
            op_pool::{op_pool_client::OpPoolClient, GetOpsRequest, MempoolOp},
        },
        simulation::{SimulationError, SimulationSuccess, Simulator},
        types::{
            Entity, EntityType, EntryPointLike, ExpectedStorage, HandleOpsOut, ProviderLike,
            Timestamp, UserOperation,
        },
    },
};

/// A user op must be valid for at least this long into the future to be included.
const TIME_RANGE_BUFFER: Duration = Duration::from_secs(60);

const MAX_BUNDLE_GAS_LIMIT: u64 = 10_000_000;
const BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT: u64 = 100;

#[derive(Debug, Default)]
pub struct Bundle {
    pub ops_per_aggregator: Vec<UserOpsPerAggregator>,
    pub gas_estimate: U256,
    pub gas_fees: GasFees,
    pub expected_storage: ExpectedStorage,
    pub rejected_ops: Vec<UserOperation>,
    pub rejected_entities: Vec<Entity>,
}

impl Bundle {
    pub fn len(&self) -> usize {
        self.ops_per_aggregator
            .iter()
            .map(|ops| ops.user_ops.len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.ops_per_aggregator.is_empty()
    }

    pub fn iter_ops(&self) -> impl Iterator<Item = &UserOperation> + '_ {
        self.ops_per_aggregator.iter().flat_map(|ops| &ops.user_ops)
    }
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait BundleProposer: Send + Sync + 'static {
    async fn make_bundle(&self, required_fees: Option<GasFees>) -> anyhow::Result<Bundle>;
}

#[derive(Debug)]
pub struct BundleProposerImpl<S, E, P>
where
    S: Simulator,
    E: EntryPointLike,
    P: ProviderLike,
{
    op_pool: OpPoolClient<Channel>,
    simulator: S,
    entry_point: E,
    provider: Arc<P>,
    chain_id: u64,
    settings: Settings,
    fee_estimator: FeeEstimator<P>,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
}

#[derive(Debug)]
pub struct Settings {
    pub chain_id: u64,
    pub max_bundle_size: u64,
    pub beneficiary: Address,
    pub use_bundle_priority_fee: Option<bool>,
    pub bundle_priority_fee_overhead_percent: u64,
    pub priority_fee_mode: PriorityFeeMode,
}

#[async_trait]
impl<S, E, P> BundleProposer for BundleProposerImpl<S, E, P>
where
    S: Simulator,
    E: EntryPointLike,
    P: ProviderLike,
{
    async fn make_bundle(&self, required_fees: Option<GasFees>) -> anyhow::Result<Bundle> {
        let (ops, block_hash, bundle_fees) = try_join!(
            self.get_ops_from_pool(),
            self.provider.get_latest_block_hash(),
            self.fee_estimator.required_bundle_fees(required_fees)
        )?;

        // Limit the amount of gas in the bundle
        let ops = self.limit_gas_in_bundle(ops);

        // Determine fees required for ops to be included in a bundle, and filter out ops that don't
        // meet the requirements. Simulate unfiltered ops.
        let required_op_fees = self.fee_estimator.required_op_fees(bundle_fees);
        let simulation_futures = ops
            .iter()
            .filter(|op| {
                if op.op.max_fee_per_gas >= required_op_fees.max_fee_per_gas
                    && op.op.max_priority_fee_per_gas >= required_op_fees.max_priority_fee_per_gas
                {
                    true
                } else {
                    self.emit(BuilderEvent::SkippedOp {
                        op_hash: self.op_hash(&op.op),
                        reason: SkipReason::InsufficientFees {
                            required_fees: required_op_fees,
                            actual_fees: GasFees {
                                max_fee_per_gas: op.op.max_fee_per_gas,
                                max_priority_fee_per_gas: op.op.max_priority_fee_per_gas,
                            },
                        },
                    });
                    false
                }
            })
            .cloned()
            .map(|op| self.simulate_validation(op, block_hash));
        let ops_with_simulations_future = future::join_all(simulation_futures);

        let all_paymaster_addresses = ops.iter().filter_map(|op| op.op.paymaster());
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
            let mut expected_storage = ExpectedStorage::default();
            for op in context.iter_ops_with_simulations() {
                expected_storage.merge(&op.simulation.expected_storage)?;
            }
            if let Some(gas_estimate) = gas_estimate {
                return Ok(Bundle {
                    ops_per_aggregator: context.to_ops_per_aggregator(),
                    gas_estimate,
                    gas_fees: bundle_fees,
                    expected_storage,
                    rejected_ops: context.rejected_ops,
                    rejected_entities: context.rejected_entities,
                });
            }
            info!("Bundle gas estimation failed. Retrying after removing rejected op(s).");
        }
        Ok(Bundle {
            rejected_ops: context.rejected_ops,
            rejected_entities: context.rejected_entities,
            gas_fees: bundle_fees,
            ..Default::default()
        })
    }
}

impl<S, E, P> BundleProposerImpl<S, E, P>
where
    S: Simulator,
    E: EntryPointLike,
    P: ProviderLike,
{
    pub fn new(
        op_pool: OpPoolClient<Channel>,
        simulator: S,
        entry_point: E,
        provider: Arc<P>,
        chain_id: u64,
        settings: Settings,
        event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    ) -> Self {
        Self {
            op_pool,
            simulator,
            entry_point,
            provider: provider.clone(),
            chain_id,
            fee_estimator: FeeEstimator::new(
                provider,
                chain_id,
                settings.priority_fee_mode,
                settings.use_bundle_priority_fee,
                settings.bundle_priority_fee_overhead_percent,
            ),
            settings,
            event_sender,
        }
    }

    async fn simulate_validation(
        &self,
        op: OpFromPool,
        block_hash: H256,
    ) -> anyhow::Result<(UserOperation, Result<SimulationSuccess, SimulationError>)> {
        let result = self
            .simulator
            .simulate_validation(op.op.clone(), Some(block_hash), Some(op.expected_code_hash))
            .await;
        match result {
            Ok(success) => Ok((op.op, Ok(success))),
            Err(error) => match error {
                SimulationError::Violations(_) => Ok((op.op, Err(error))),
                SimulationError::Other(error) => Err(error),
            },
        }
    }

    async fn assemble_context(
        &self,
        ops_with_simulations: Vec<(UserOperation, Result<SimulationSuccess, SimulationError>)>,
        mut balances_by_paymaster: HashMap<Address, U256>,
    ) -> ProposalContext {
        let all_sender_addresses: HashSet<Address> = ops_with_simulations
            .iter()
            .map(|(op, _)| op.sender)
            .collect();
        let mut groups_by_aggregator = LinkedHashMap::<Option<Address>, AggregatorGroup>::new();
        let mut rejected_ops = Vec::<UserOperation>::new();
        let mut paymasters_to_reject = Vec::<Address>::new();
        for (op, simulation) in ops_with_simulations {
            let simulation = match simulation {
                Ok(simulation) => simulation,
                Err(error) => {
                    self.emit(BuilderEvent::RejectedOp {
                        op_hash: self.op_hash(&op),
                        reason: OpRejectionReason::FailedRevalidation { error },
                    });
                    rejected_ops.push(op);
                    continue;
                }
            };

            // filter time range
            if !simulation
                .valid_time_range
                .contains(Timestamp::now(), TIME_RANGE_BUFFER)
            {
                self.emit(BuilderEvent::SkippedOp {
                    op_hash: self.op_hash(&op),
                    reason: SkipReason::InvalidTimeRange {
                        valid_range: simulation.valid_time_range,
                    },
                });
                rejected_ops.push(op);
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
                self.emit(BuilderEvent::SkippedOp {
                    op_hash: self.op_hash(&op),
                    reason: SkipReason::AccessedOtherSender { other_sender },
                });
                continue;
            }
            if let Some(paymaster) = op.paymaster() {
                let Some(balance) = balances_by_paymaster.get_mut(&paymaster) else {
                    error!("Op had paymaster with unknown balance, but balances should have been loaded for all paymasters in bundle.");
                    continue;
                };
                let max_cost = op.max_gas_cost();
                if *balance < max_cost {
                    info!("Rejected paymaster {paymaster:?} becauase its balance {balance:?} was too low.");
                    paymasters_to_reject.push(paymaster);
                    continue;
                } else {
                    *balance -= max_cost;
                }
            }
            groups_by_aggregator
                .entry(simulation.aggregator_address())
                .or_default()
                .ops_with_simulations
                .push(OpWithSimulation { op, simulation });
        }
        let mut context = ProposalContext {
            groups_by_aggregator,
            rejected_ops,
            rejected_entities: Vec::new(),
        };
        for paymaster in paymasters_to_reject {
            // No need to update aggregator signatures because we haven't computed them yet.
            let _ = context.reject_entity(Entity::paymaster(paymaster));
        }
        self.compute_all_aggregator_signatures(&mut context).await;
        context
    }

    async fn reject_index(&self, context: &mut ProposalContext, i: usize) {
        let changed_aggregator = context.reject_index(i);
        self.compute_aggregator_signatures(context, &changed_aggregator)
            .await;
    }

    async fn reject_entity(&self, context: &mut ProposalContext, entity: Entity) {
        let changed_aggregators = context.reject_entity(entity);
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
            context.get_total_gas(self.chain_id),
            BUNDLE_TRANSACTION_GAS_OVERHEAD_PERCENT,
        );
        let handle_ops_out = self
            .entry_point
            .call_handle_ops(
                context.to_ops_per_aggregator(),
                self.settings.beneficiary,
                gas,
            )
            .await
            .context("should estimate gas for proposed bundle")?;
        match handle_ops_out {
            HandleOpsOut::Success => Ok(Some(gas)),
            HandleOpsOut::FailedOp(index, message) => {
                self.emit(BuilderEvent::RejectedOp {
                    op_hash: self.op_hash(context.get_op_at(index)?),
                    reason: OpRejectionReason::FailedInBundle {
                        message: Arc::new(message.clone()),
                    },
                });
                self.process_failed_op(context, index, message).await?;
                Ok(None)
            }
            HandleOpsOut::SignatureValidationFailed(aggregator) => {
                info!("Rejected aggregator {aggregator:?} because its signature validation failed during gas estimation.");
                self.reject_entity(context, Entity::aggregator(aggregator))
                    .await;
                Ok(None)
            }
        }
    }

    async fn get_ops_from_pool(&self) -> anyhow::Result<Vec<OpFromPool>> {
        self.op_pool
            .clone()
            .get_ops(GetOpsRequest {
                entry_point: self.entry_point.address().as_bytes().to_vec(),
                max_ops: self.settings.max_bundle_size,
            })
            .await
            .context("should get ops from op pool to bundle")?
            .into_inner()
            .ops
            .into_iter()
            .map(OpFromPool::try_from)
            .collect()
    }

    async fn get_balances_by_paymaster(
        &self,
        addreses: impl Iterator<Item = Address>,
        block_hash: H256,
    ) -> anyhow::Result<HashMap<Address, U256>> {
        let futures = addreses.map(|address| async move {
            let deposit = self.entry_point.get_deposit(address, block_hash).await?;
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
            .await;
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
                let op = context.get_op_at(index)?;
                let factory = op.factory().context("op failed during gas estimation with factory error, but did not include a factory")?;
                info!("Rejected op because it failed during gas estimation with factory {factory:?} error {message}.");
                self.reject_entity(context, Entity::factory(factory)).await;
            }
            // Entrypoint error codes that we want to reject the paymaster for.
            // Note: AA32 is not included as this is a time expiry error.
            "AA30" | "AA31" | "AA33" | "AA34" => {
                let op = context.get_op_at(index)?;
                let paymaster = op.paymaster().context(
                    "op failed during gas estimation with {message}, but had no paymaster",
                )?;
                info!("Rejected op because it failed during gas estimation with a paymaster {paymaster:?} error {message}.");
                self.reject_entity(context, Entity::paymaster(paymaster))
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

    fn limit_gas_in_bundle(&self, ops: Vec<OpFromPool>) -> Vec<OpFromPool> {
        let mut gas_left = U256::from(MAX_BUNDLE_GAS_LIMIT);
        let mut ops_in_bundle = Vec::new();
        for op in ops {
            let gas = op.op.total_execution_gas_limit(self.chain_id);
            if gas_left < gas {
                continue;
            }
            gas_left -= gas;
            ops_in_bundle.push(op);
        }
        ops_in_bundle
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

#[derive(Clone, Debug)]
struct OpFromPool {
    op: UserOperation,
    expected_code_hash: H256,
}

impl TryFrom<MempoolOp> for OpFromPool {
    type Error = anyhow::Error;

    fn try_from(value: MempoolOp) -> Result<Self, Self::Error> {
        Ok(Self {
            op: value
                .uo
                .context("mempool op should contain user operation")?
                .try_into()?,
            expected_code_hash: protos::from_bytes(&value.expected_code_hash)?,
        })
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
    rejected_ops: Vec<UserOperation>,
    rejected_entities: Vec<Entity>,
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

    fn get_op_at(&self, index: usize) -> anyhow::Result<&UserOperation> {
        let mut remaining_i = index;
        for group in self.groups_by_aggregator.values() {
            if remaining_i < group.ops_with_simulations.len() {
                return Ok(&group.ops_with_simulations[remaining_i].op);
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
                self.rejected_ops.push(rejected.op);
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

    /// Returns the addresses of any aggregators whose signature may need to be
    /// recomputed.
    #[must_use = "rejected entity but did not update aggregator signatures"]
    fn reject_entity(&mut self, entity: Entity) -> Vec<Address> {
        let ret = match entity.kind {
            EntityType::Aggregator => {
                self.reject_aggregator(entity.address);
                vec![]
            }
            EntityType::Paymaster => self.reject_paymaster(entity.address),
            EntityType::Factory => self.reject_factory(entity.address),
            _ => vec![],
        };
        self.rejected_entities.push(entity);
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

    fn get_total_gas(&self, chain_id: u64) -> U256 {
        self.iter_ops()
            .map(|op| op.total_execution_gas_limit(chain_id))
            .fold(U256::zero(), |acc, c| acc + c)
    }

    fn iter_ops_with_simulations(&self) -> impl Iterator<Item = &OpWithSimulation> + '_ {
        self.groups_by_aggregator
            .values()
            .flat_map(|group| &group.ops_with_simulations)
    }

    fn iter_ops(&self) -> impl Iterator<Item = &UserOperation> + '_ {
        self.iter_ops_with_simulations().map(|op| &op.op)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use ethers::{types::H160, utils::parse_units};
    use tonic::Response;

    use super::*;
    use crate::common::{
        grpc::mocks::{self, MockOpPool},
        protos::op_pool::GetOpsResponse,
        simulation::{
            AggregatorSimOut, MockSimulator, SimulationError, SimulationSuccess,
            SimulationViolation,
        },
        types::{MockEntryPointLike, MockProviderLike, ValidTimeRange},
    };

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

        let expected_gas = math::increase_by_percent(
            op.pre_verification_gas + op.verification_gas_limit + op.call_gas_limit,
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
            simulation_result: Box::new(|| Err(SimulationError::Violations(vec![]))),
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
                Err(SimulationError::Other(anyhow!("simulation failed")))
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
                Err(SimulationError::Violations(vec![
                    SimulationViolation::InvalidSignature,
                ]))
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
        let bundle = make_bundle(
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
        let bundle = make_bundle(
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
        let bundle = make_bundle(
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

        let bundle = make_bundle(
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
            bundle.rejected_entities,
            vec![Entity::paymaster(address(1)), Entity::factory(address(3)),]
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
    async fn test_bundle_gas_limit() {
        let op1 = op_with_sender_call_gas_limit(address(1), U256::from(5_000_000));
        let op2 = op_with_sender_call_gas_limit(address(2), U256::from(5_000_000));
        let op3 = op_with_sender_call_gas_limit(address(3), U256::from(10_000_000));
        let op4 = op_with_sender_call_gas_limit(address(4), U256::from(10_000_000));
        let deposit = parse_units("1", "ether").unwrap().into();

        let bundle = make_bundle(
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

        assert_eq!(bundle.rejected_entities, vec![]);
        assert_eq!(bundle.rejected_ops, vec![]);
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op1, op2],
                ..Default::default()
            }]
        );
        assert_eq!(bundle.gas_estimate, U256::from(20_000_000));
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
        make_bundle(
            mock_ops,
            vec![],
            vec![HandleOpsOut::Success],
            vec![],
            U256::zero(),
            U256::zero(),
        )
        .await
    }

    async fn make_bundle(
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
        let mut op_pool = MockOpPool::new();
        let ops: Vec<_> = mock_ops
            .iter()
            .map(|MockOp { op, .. }| MempoolOp {
                uo: Some(op.into()),
                expected_code_hash: expected_code_hash.as_bytes().to_vec(),
                ..Default::default()
            })
            .collect();
        op_pool
            .expect_get_ops()
            .return_once(|_| Ok(Response::new(GetOpsResponse { ops })));
        let op_pool_handle = mocks::mock_op_pool_client(op_pool).await;
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
        let mut entry_point = MockEntryPointLike::new();
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
                .expect_get_deposit()
                .times(..=1)
                .return_once(move |_, _| Ok(deposit));
        }

        let signatures_by_aggregator: HashMap<_, _> = mock_aggregators
            .into_iter()
            .map(|agg| (agg.address, agg.signature))
            .collect();
        let mut provider = MockProviderLike::new();
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
            .returning(move |address, _| signatures_by_aggregator[&address]());
        let (event_sender, _) = broadcast::channel(16);
        let proposer = BundleProposerImpl::new(
            op_pool_handle.client.clone(),
            simulator,
            entry_point,
            Arc::new(provider),
            0,
            Settings {
                chain_id: 0,
                max_bundle_size,
                beneficiary,
                use_bundle_priority_fee: Some(true),
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
}
