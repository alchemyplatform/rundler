use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use ethers::types::{Address, Bytes, H256, U256};
use futures::future;
use linked_hash_map::LinkedHashMap;
#[cfg(test)]
use mockall::automock;
use tonic::{async_trait, transport::Channel};
use tracing::error;

use crate::common::{
    contracts::entry_point::UserOpsPerAggregator,
    protos::{
        self,
        op_pool::{op_pool_client::OpPoolClient, GetOpsRequest, MempoolOp},
    },
    simulation::{SimulationError, SimulationSuccess, Simulator},
    types::{EntryPointLike, HandleOpsOut, ProviderLike, Timestamp, UserOperation},
};

/// A user op must be valid for at least this long into the future to be included.
const TIME_RANGE_BUFFER: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct Bundle {
    pub ops_per_aggregator: Vec<UserOpsPerAggregator>,
    pub gas_estimate: U256,
    pub expected_storage_slots: HashMap<Address, HashMap<U256, U256>>,
    pub rejected_ops: Vec<UserOperation>,
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait BundleProposer {
    async fn make_bundle(&self) -> anyhow::Result<Bundle>;
}

#[derive(Debug)]
pub struct BundleProposerImpl<S, E, P>
where
    S: Simulator,
    E: EntryPointLike,
    P: ProviderLike,
{
    bundle_size: u64,
    beneficiary: Address,
    op_pool: OpPoolClient<Channel>,
    simulator: S,
    entry_point: E,
    provider: Arc<P>,
}

#[async_trait]
impl<S, E, P> BundleProposer for BundleProposerImpl<S, E, P>
where
    S: Simulator,
    E: EntryPointLike,
    P: ProviderLike,
{
    async fn make_bundle(&self) -> anyhow::Result<Bundle> {
        let ops = self
            .op_pool
            .clone()
            .get_ops(GetOpsRequest {
                entry_point: self.entry_point.address().as_bytes().to_vec(),
                max_ops: self.bundle_size,
            })
            .await
            .context("should get ops from op pool to bundle")?
            .into_inner()
            .ops;
        let block_hash = self.provider.get_latest_block_hash().await?;
        let simulation_futures = ops
            .iter()
            .cloned()
            .map(|op| self.simulate_validation(op, block_hash));
        let ops_with_simulations = future::join_all(simulation_futures).await;
        let ops_with_simulations = ops_with_simulations
            .into_iter()
            .filter_map(|result| match result {
                Ok(success) => Some(success),
                Err(error) => {
                    error!("Failed to resimulate op: {error}");
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut context = self.assemble_context(ops_with_simulations).await;
        while !context.is_empty() {
            let gas_estimate = self.estimate_gas_rejecting_failed_ops(&mut context).await?;
            if let Some(gas_estimate) = gas_estimate {
                return Ok(Bundle {
                    ops_per_aggregator: context.to_ops_per_aggregator(),
                    gas_estimate,
                    expected_storage_slots: HashMap::default(), // TODO: actually compute this
                    rejected_ops: context.rejected_ops,
                });
            }
        }
        Ok(Bundle {
            rejected_ops: context.rejected_ops,
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
    // TODO: Remove the allow directive after we start using this.
    #[allow(dead_code)]
    pub fn new(
        bundle_size: u64,
        beneficiary: Address,
        op_pool: OpPoolClient<Channel>,
        simulator: S,
        entry_point: E,
        provider: Arc<P>,
    ) -> Self {
        Self {
            bundle_size,
            beneficiary,
            op_pool,
            simulator,
            entry_point,
            provider,
        }
    }

    async fn simulate_validation(
        &self,
        op: MempoolOp,
        block_hash: H256,
    ) -> anyhow::Result<(UserOperation, Option<SimulationSuccess>)> {
        let op = OpFromPool::try_from(op)?;
        let result = self
            .simulator
            .simulate_validation(op.op.clone(), Some(block_hash), Some(op.expected_code_hash))
            .await;
        match result {
            Ok(success) => Ok((
                op.op,
                Some(success).filter(|success| {
                    !success.signature_failed
                        && success
                            .valid_time_range
                            .contains(Timestamp::now(), TIME_RANGE_BUFFER)
                }),
            )),
            Err(error) => match error {
                SimulationError::Violations(_) => Ok((op.op, None)),
                SimulationError::Other(error) => Err(error),
            },
        }
    }

    async fn assemble_context(
        &self,
        ops_with_simulations: Vec<(UserOperation, Option<SimulationSuccess>)>,
    ) -> ProposalContext {
        let all_sender_addresses: HashSet<Address> = ops_with_simulations
            .iter()
            .map(|(op, _)| op.sender)
            .collect();
        let mut groups_by_aggregator = LinkedHashMap::<Option<Address>, AggregatorGroup>::new();
        let mut rejected_ops = Vec::<UserOperation>::new();
        for (op, simulation) in ops_with_simulations {
            let Some(simulation) = simulation else {
                rejected_ops.push(op);
                continue;
            };
            if simulation
                .accessed_addresses
                .iter()
                .any(|&address| address != op.sender && all_sender_addresses.contains(&address))
            {
                // Exclude ops that access the sender of another op in the
                // batch, but don't reject them (remove them from pool).
                continue;
            }
            groups_by_aggregator
                .entry(simulation.aggregator_address())
                .or_default()
                .ops_with_simulations
                .push(OpWithSimulation { op, simulation });
            // TODO: Track paymaster balances
        }
        let mut context = ProposalContext {
            groups_by_aggregator,
            rejected_ops,
        };
        self.compute_aggregator_signatures(&mut context).await;
        context
    }

    async fn compute_aggregator_signatures(&self, context: &mut ProposalContext) {
        let signature_futures =
            context
                .groups_by_aggregator
                .iter()
                .filter_map(|(option_address, group)| {
                    option_address.map(|address| self.aggregate_signatures(address, group))
                });
        let signatures = future::join_all(signature_futures).await;
        for (aggregator, result) in signatures {
            context.apply_aggregation_signature_result(aggregator, result);
        }
    }

    async fn reject_index(&self, context: &mut ProposalContext, i: usize) {
        let mut remaining_i = i;
        let mut found_aggregator: Option<Option<Address>> = None;
        for (&aggregator, group) in &mut context.groups_by_aggregator {
            if remaining_i < group.ops_with_simulations.len() {
                let rejected = group.ops_with_simulations.remove(remaining_i);
                context.rejected_ops.push(rejected.op);
                found_aggregator = Some(aggregator);
                break;
            }
            remaining_i -= group.ops_with_simulations.len();
        }
        let Some(found_aggregator) = found_aggregator else {
            error!("The entry point indicated a failed op at index {i}, but the bundle size is only {}", i - remaining_i);
            return;
        };
        // If we just removed the last op from a group, delete that group.
        // Otherwise, the signature is invalidated and we need to recompute it.
        if context.groups_by_aggregator[&found_aggregator]
            .ops_with_simulations
            .is_empty()
        {
            context.groups_by_aggregator.remove(&found_aggregator);
        } else if let Some(aggregator) = found_aggregator {
            let (_, sig_result) = self
                .aggregate_signatures(aggregator, &context.groups_by_aggregator[&found_aggregator])
                .await;
            context.apply_aggregation_signature_result(aggregator, sig_result);
        }
    }

    /// Estimates the gas needed to send this bundle. If successful, returns the
    /// amount of gas, but if not then mutates the context to remove whichever
    /// op(s) caused the failure.
    async fn estimate_gas_rejecting_failed_ops(
        &self,
        context: &mut ProposalContext,
    ) -> anyhow::Result<Option<U256>> {
        let handle_ops_out = self
            .entry_point
            .estimate_handle_ops_gas(context.to_ops_per_aggregator(), self.beneficiary)
            .await
            .context("should estimate gas for proposed bundle")?;
        match handle_ops_out {
            HandleOpsOut::SuccessWithGas(gas) => Ok(Some(gas)),
            HandleOpsOut::FailedOp(index, _message) => {
                // TODO: look at message to see if caused by a factory or
                // paymaster. If so, return something to purge the op pool of
                // all other ops using that entity.
                self.reject_index(context, index).await;
                Ok(None)
            }
            HandleOpsOut::SignatureValidationFailed(aggregator) => {
                context.reject_aggregator(aggregator);
                Ok(None)
            }
        }
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

    fn reject_aggregator(&mut self, address: Address) {
        let rejected = self.groups_by_aggregator.remove(&Some(address));
        let Some(rejected) = rejected else {
            error!("tried to reject ops from aggregator {address}, but no such ops exist in bundle");
            return;
        };
        let rejected_ops = rejected.ops_with_simulations.into_iter().map(|op| op.op);
        self.rejected_ops.extend(rejected_ops);
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
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use ethers::types::H160;
    use tonic::Response;

    use super::*;
    use crate::common::{
        grpc::mocks::{self, MockOpPool},
        protos::op_pool::GetOpsResponse,
        simulation::{AggregatorSimOut, MockSimulator, SimulationError, SimulationSuccess},
        types::{MockEntryPointLike, MockProviderLike, ValidTimeRange},
    };

    #[tokio::test]
    async fn test_singleton_valid_bundle() {
        let op = UserOperation::default();
        let bundle = simple_make_bundle(vec![MockOp {
            op: op.clone(),
            simulation_result: Box::new(|| Ok(SimulationSuccess::default())),
        }])
        .await;
        assert_eq!(
            bundle.ops_per_aggregator,
            vec![UserOpsPerAggregator {
                user_ops: vec![op],
                ..Default::default()
            }]
        );
        assert_eq!(bundle.gas_estimate, default_estimated_gas());
    }

    #[tokio::test]
    async fn test_rejects_on_violation() {
        let op = UserOperation::default();
        let bundle = simple_make_bundle(vec![MockOp {
            op: op.clone(),
            simulation_result: Box::new(|| Err(SimulationError::Violations(vec![]))),
        }])
        .await;
        assert_eq!(bundle.ops_per_aggregator, vec![]);
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
        assert_eq!(bundle.ops_per_aggregator, vec![]);
        assert_eq!(bundle.rejected_ops, vec![]);
    }

    #[tokio::test]
    async fn test_rejects_on_signature_failure() {
        let op = UserOperation::default();
        let bundle = simple_make_bundle(vec![MockOp {
            op: op.clone(),
            simulation_result: Box::new(|| {
                Ok(SimulationSuccess {
                    signature_failed: true,
                    ..Default::default()
                })
            }),
        }])
        .await;
        assert_eq!(bundle.ops_per_aggregator, vec![]);
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
            assert_eq!(bundle.ops_per_aggregator, vec![]);
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
        assert_eq!(bundle.rejected_ops, vec![])
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
            vec![HandleOpsOut::SuccessWithGas(default_estimated_gas())],
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
            vec![HandleOpsOut::SuccessWithGas(default_estimated_gas())],
        )
        .await
    }

    async fn make_bundle(
        mock_ops: Vec<MockOp>,
        mock_aggregators: Vec<MockAggregator>,
        mock_estimate_gasses: Vec<HandleOpsOut>,
    ) -> Bundle {
        let entry_point_address = address(123);
        let beneficiary_address = address(124);
        let current_block_hash = hash(125);
        let expected_code_hash = hash(126);
        let bundle_size = mock_ops.len() as u64;
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
            .map(|op| (op.op, op.simulation_result))
            .collect();
        let mut simulator = MockSimulator::new();
        simulator
            .expect_simulate_validation()
            .withf(move |_, &block_hash, &code_hash| {
                block_hash == Some(current_block_hash) && code_hash == Some(expected_code_hash)
            })
            .returning(move |op, _, _| simulations_by_op[&op]());
        let mut entry_point = MockEntryPointLike::new();
        entry_point
            .expect_address()
            .return_const(entry_point_address);
        for estimated_gas in mock_estimate_gasses {
            entry_point
                .expect_estimate_handle_ops_gas()
                .times(..=1)
                .withf(move |_, &beneficiary| beneficiary == beneficiary_address)
                .return_once(|_, _| Ok(estimated_gas));
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
            .expect_aggregate_signatures()
            .returning(move |address, _| signatures_by_aggregator[&address]());
        let proposer = BundleProposerImpl::new(
            bundle_size,
            beneficiary_address,
            op_pool_handle.client.clone(),
            simulator,
            entry_point,
            Arc::new(provider),
        );
        proposer.make_bundle().await.expect("should make a bundle")
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

    fn default_estimated_gas() -> U256 {
        20000.into()
    }
}
