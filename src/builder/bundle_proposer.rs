use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use ethers::types::{Address, Bytes, H256, U256};
use futures::future;
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
    simulation::{AggregatorSimOut, SimulationError, SimulationSuccess, Simulator},
    types::{ProviderLike, Timestamp, UserOperation},
};

/// A user op must be valid for at least this long into the future to be included.
const TIME_RANGE_BUFFER: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct Bundle {
    pub ops_per_aggregator: Vec<UserOpsPerAggregator>,
    pub expected_storage_slots: HashMap<Address, HashMap<U256, U256>>,
    pub rejected_ops: Vec<UserOperation>,
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait BundleProposer: Send + Sync {
    async fn make_bundle(&self) -> anyhow::Result<Bundle>;
}

#[derive(Debug)]
pub struct BundleProposerImpl<S: Simulator, P: ProviderLike> {
    entry_point_address: Address,
    bundle_size: u64,
    op_pool: OpPoolClient<Channel>,
    simulator: S,
    provider: Arc<P>,
}

#[async_trait]
impl<S: Simulator, P: ProviderLike> BundleProposer for BundleProposerImpl<S, P> {
    async fn make_bundle(&self) -> anyhow::Result<Bundle> {
        let ops = self
            .op_pool
            .clone()
            .get_ops(GetOpsRequest {
                entry_point: self.entry_point_address.as_bytes().to_vec(),
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
        Ok(self.assemble_ops(ops_with_simulations).await)
    }
}

impl<S: Simulator, P: ProviderLike> BundleProposerImpl<S, P> {
    // TODO: Remove the allow directive after we start using this.
    #[allow(dead_code)]
    pub fn new(
        entry_point_address: Address,
        bundle_size: u64,
        op_pool: OpPoolClient<Channel>,
        simulator: S,
        provider: Arc<P>,
    ) -> Self {
        Self {
            entry_point_address,
            bundle_size,
            op_pool,
            simulator,
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

    async fn assemble_ops(
        &self,
        ops_with_simulations: Vec<(UserOperation, Option<SimulationSuccess>)>,
    ) -> Bundle {
        let all_sender_addresses: HashSet<Address> = ops_with_simulations
            .iter()
            .map(|(op, _)| op.sender)
            .collect();
        let mut ops_without_aggregator = Vec::<UserOperation>::new();
        let mut ops_by_aggregator = HashMap::<Address, Vec<AggregatedOp>>::new();
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
                // Exclude ops that access the sender of another op in the batch.
                continue;
            }
            if let Some(AggregatorSimOut { address, signature }) = simulation.aggregator {
                ops_by_aggregator
                    .entry(address)
                    .or_default()
                    .push(AggregatedOp { op, signature });
            } else {
                ops_without_aggregator.push(op);
            }
            // TODO: Track paymaster balances
        }
        let mut signed_ops_by_aggregator = Vec::<UserOpsPerAggregator>::new();
        if !ops_without_aggregator.is_empty() {
            signed_ops_by_aggregator.push(UserOpsPerAggregator {
                user_ops: ops_without_aggregator,
                aggregator: Address::default(),
                signature: Bytes::default(),
            });
        }
        let aggregation_futures = ops_by_aggregator.iter().map(|(&aggregator, ops)| {
            self.aggregate_signatures(aggregator, ops.iter().map(|op| op.op.clone()).collect())
        });
        let aggregation_signatures = future::join_all(aggregation_futures).await;
        for (aggregator, signature) in aggregation_signatures {
            match signature {
                Ok(Some(signature)) => signed_ops_by_aggregator.push(UserOpsPerAggregator {
                    user_ops: ops_by_aggregator
                        .remove(&aggregator)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|op| op.with_replaced_signature())
                        .collect(),
                    aggregator,
                    signature,
                }),
                Ok(None) => {
                    rejected_ops.extend(
                        ops_by_aggregator
                            .remove(&aggregator)
                            .unwrap_or_default()
                            .into_iter()
                            .map(|op| op.op),
                    );
                }
                Err(error) => {
                    error!("Failed to compute aggregator signature: {error}");
                }
            }
        }
        Bundle {
            ops_per_aggregator: signed_ops_by_aggregator,
            expected_storage_slots: Default::default(), // TODO: actually compute storage slots
            rejected_ops,
        }
    }

    async fn aggregate_signatures(
        &self,
        aggregator: Address,
        ops: Vec<UserOperation>,
    ) -> (Address, anyhow::Result<Option<Bytes>>) {
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

#[derive(Clone, Debug)]
struct AggregatedOp {
    op: UserOperation,
    signature: Bytes,
}

impl AggregatedOp {
    fn with_replaced_signature(self) -> UserOperation {
        let Self { mut op, signature } = self;
        op.signature = signature;
        op
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
        simulation::{MockSimulator, SimulationError, SimulationSuccess},
        types::{MockProviderLike, ValidTimeRange},
    };

    #[tokio::test]
    async fn test_singleton_valid_bundle() {
        let op = UserOperation::default();
        let bundle = make_bundle(vec![MockOp {
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
    }

    #[tokio::test]
    async fn test_rejects_on_violation() {
        let op = UserOperation::default();
        let bundle = make_bundle(vec![MockOp {
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
        let bundle = make_bundle(vec![MockOp {
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
        let bundle = make_bundle(vec![MockOp {
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
            let bundle = make_bundle(vec![MockOp {
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
        let bundle = make_bundle(vec![
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
        let bundle = make_bundle_with_aggregators(
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

    async fn make_bundle(mock_ops: Vec<MockOp>) -> Bundle {
        make_bundle_with_aggregators(mock_ops, vec![]).await
    }

    #[allow(clippy::mutable_key_type)]
    async fn make_bundle_with_aggregators(
        mock_ops: Vec<MockOp>,
        mock_aggregators: Vec<MockAggregator>,
    ) -> Bundle {
        let entry_point_address = address(123);
        let current_block_hash = hash(124);
        let expected_code_hash = hash(125);
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
            entry_point_address,
            bundle_size,
            op_pool_handle.client.clone(),
            simulator,
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
}
