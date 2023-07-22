use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use ethers::types::{Address, H256};
use parking_lot::RwLock;
use tonic::async_trait;

use super::{
    error::{MempoolError, MempoolResult},
    pool::PoolInner,
    reputation::{Reputation, ReputationManager, ReputationStatus},
    Mempool, OperationOrigin, PoolConfig, PoolOperation,
};
use crate::{
    common::{
        contracts::i_entry_point::IEntryPointEvents,
        precheck::Prechecker,
        simulation::Simulator,
        types::{Entity, UserOperation},
    },
    op_pool::event::NewBlockEvent,
};

/// The number of blocks that a throttled operation is allowed to be in the mempool
const THROTTLED_OPS_BLOCK_LIMIT: u64 = 10;

/// User Operation Mempool
///
/// Wrapper around a pool object that implements thread-safety
/// via a RwLock. Safe to call from multiple threads. Methods
/// block on write locks.
pub struct UoPool<R: ReputationManager, P: Prechecker, S: Simulator> {
    entry_point: Address,
    reputation: Arc<R>,
    state: RwLock<UoPoolState>,
    prechecker: P,
    simulator: S,
}

struct UoPoolState {
    pool: PoolInner,
    throttled_ops: HashMap<H256, u64>,
    block_number: u64,
}

impl<R, P, S> UoPool<R, P, S>
where
    R: ReputationManager,
    P: Prechecker,
    S: Simulator,
{
    pub fn new(args: PoolConfig, reputation: Arc<R>, prechecker: P, simulator: S) -> Self {
        Self {
            entry_point: args.entry_point,
            reputation,
            state: RwLock::new(UoPoolState {
                pool: PoolInner::new(args),
                throttled_ops: HashMap::new(),
                block_number: 0,
            }),
            prechecker,
            simulator,
        }
    }
}

#[async_trait]
impl<R, P, S> Mempool for UoPool<R, P, S>
where
    R: ReputationManager,
    P: Prechecker,
    S: Simulator,
{
    fn entry_point(&self) -> Address {
        self.entry_point
    }

    fn on_new_block(&self, new_block: &NewBlockEvent) {
        let mut state = self.state.write();
        tracing::info!(
            "New block: {:?} with {} entrypoint events",
            new_block.number,
            new_block.events.len()
        );

        if let Some(events) = new_block.events.get(&self.entry_point) {
            for event in events {
                if let IEntryPointEvents::UserOperationEventFilter(uo_event) = &event.contract_event
                {
                    let op_hash = uo_event.user_op_hash.into();
                    if let Some(op) = state.pool.remove_operation_by_hash(op_hash) {
                        for e in op.staked_entities() {
                            self.reputation.add_included(e.address);
                        }
                    }

                    // Remove throttled ops that were included in the block
                    state.throttled_ops.remove(&op_hash);
                }
            }
        }

        // Remove throttled ops that are too old
        let new_block_number = new_block.number.as_u64();
        let mut to_remove = HashSet::new();
        for (hash, block) in state.throttled_ops.iter() {
            if new_block_number - block > THROTTLED_OPS_BLOCK_LIMIT {
                to_remove.insert(*hash);
            }
        }
        for hash in to_remove {
            state.pool.remove_operation_by_hash(hash);
            state.throttled_ops.remove(&hash);
        }

        state.block_number = new_block_number;
    }

    async fn add_operation(
        &self,
        _origin: OperationOrigin,
        op: UserOperation,
    ) -> MempoolResult<H256> {
        // TODO(danc) aggregator throttling is not implemented
        // TODO(danc) catch ops with aggregators prior to simulation

        // Check if op has a throttled/banned entity
        let mut throttled = false;
        for e in op.entities() {
            match self.reputation.status(e.address) {
                ReputationStatus::Ok => {}
                ReputationStatus::Throttled => {
                    if self.state.read().pool.address_count(e.address) > 0 {
                        return Err(MempoolError::EntityThrottled(e));
                    }
                    throttled = true;
                }
                ReputationStatus::Banned => {
                    return Err(MempoolError::EntityThrottled(e));
                }
            }
        }

        // Check if op is replacing another op, and if so, ensure its fees are high enough
        self.state.read().pool.check_replacement_fees(&op)?;

        // Prechecks
        self.prechecker.check(&op).await?;

        // Simulation
        let sim_result = self
            .simulator
            .simulate_validation(op.clone(), None, None)
            .await?;

        if sim_result.signature_failed {
            return Err(MempoolError::InvalidSignature);
        } else if let Some(agg) = &sim_result.aggregator {
            return Err(MempoolError::UnsupportedAggregator(agg.address));
        }

        let pool_op = PoolOperation {
            uo: op,
            aggregator: None,
            valid_time_range: sim_result.valid_time_range,
            expected_code_hash: sim_result.code_hash,
            sim_block_hash: sim_result.block_hash,
            entities_needing_stake: sim_result.entities_needing_stake,
            account_is_staked: sim_result.account_is_staked,
        };

        // Update reputation
        for e in pool_op.entities() {
            if pool_op.is_staked(e.kind) {
                self.reputation.add_seen(e.address);
            }
        }

        // Add op to pool
        let mut state = self.state.write();
        let hash = state.pool.add_operation(pool_op)?;
        let bn = state.block_number;
        if throttled {
            state.throttled_ops.insert(hash, bn);
        }

        Ok(hash)
    }

    fn remove_operations(&self, hashes: &[H256]) {
        // hold the lock for the duration of the operation
        let mut state = self.state.write();
        for hash in hashes {
            state.pool.remove_operation_by_hash(*hash);
        }
    }

    fn remove_entity(&self, entity: Entity) {
        self.state.write().pool.remove_entity(entity);
    }

    fn best_operations(&self, max: usize) -> Vec<Arc<PoolOperation>> {
        // get the best operations from the pool
        let ordered_ops = self.state.read().pool.best_operations();
        // keep track of senders to avoid sending multiple ops from the same sender
        let mut senders = HashSet::<Address>::new();

        ordered_ops
            .into_iter()
            .filter(|op| {
                // filter out ops from senders we've already seen
                senders.insert(op.uo.sender)
            })
            .take(max)
            .collect()
    }

    fn all_operations(&self, max: usize) -> Vec<Arc<PoolOperation>> {
        self.state.read().pool.best_operations().take(max).collect()
    }

    fn clear(&self) {
        self.state.write().pool.clear()
    }

    fn dump_reputation(&self) -> Vec<Reputation> {
        self.reputation.dump_reputation()
    }

    fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64) {
        self.reputation
            .set_reputation(address, ops_seen, ops_included)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{
            precheck::{self, MockPrechecker, PrecheckError, PrecheckViolation},
            simulation::{
                self, MockSimulator, SimulationError, SimulationSuccess, SimulationViolation,
            },
            types::UserOperation,
        },
        op_pool::mempool::reputation::MockReputationManager,
    };

    #[tokio::test]
    async fn add_single_op() {
        let op = create_op(Address::random(), 0, 0);
        let ops = vec![op.clone()];
        let uos = vec![op.op.clone()];
        let pool = create_pool(ops);

        let hash = pool
            .add_operation(OperationOrigin::Local, op.op)
            .await
            .unwrap();
        check_ops(pool.best_operations(1), uos);
        pool.remove_operations(&[hash]);
        assert_eq!(pool.best_operations(1), vec![]);
    }

    #[tokio::test]
    async fn add_multiple_ops() {
        let ops = vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ];
        let uos = ops.iter().map(|op| op.op.clone()).collect::<Vec<_>>();
        let pool = create_pool(ops);

        let mut hashes = vec![];
        for op in &uos {
            let hash = pool
                .add_operation(OperationOrigin::Local, op.clone())
                .await
                .unwrap();
            hashes.push(hash);
        }
        check_ops(pool.best_operations(3), uos);
        pool.remove_operations(&hashes);
        assert_eq!(pool.best_operations(3), vec![]);
    }

    #[tokio::test]
    async fn clear() {
        let ops = vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ];
        let uos = ops.iter().map(|op| op.op.clone()).collect::<Vec<_>>();
        let pool = create_pool(ops);

        for op in &uos {
            let _ = pool
                .add_operation(OperationOrigin::Local, op.clone())
                .await
                .unwrap();
        }
        check_ops(pool.best_operations(3), uos);
        pool.clear();
        assert_eq!(pool.best_operations(3), vec![]);
    }

    #[tokio::test]
    async fn banned_reputation() {
        let op = create_op_with_errors(
            Address::random(),
            0,
            0,
            ReputationStatus::Banned,
            None,
            None,
        );
        let ops = vec![op.clone()];
        let pool = create_pool(ops);

        match pool.add_operation(OperationOrigin::Local, op.op).await {
            Err(MempoolError::EntityThrottled(_)) => {}
            _ => panic!("Expected EntityThrottled error"),
        }
        assert_eq!(pool.best_operations(1), vec![]);
    }

    #[tokio::test]
    async fn precheck_error() {
        let op = create_op_with_errors(
            Address::random(),
            0,
            0,
            ReputationStatus::Ok,
            Some(PrecheckViolation::InitCodeTooShort(0)),
            None,
        );
        let ops = vec![op.clone()];
        let pool = create_pool(ops);

        match pool.add_operation(OperationOrigin::Local, op.op).await {
            Err(MempoolError::PrecheckViolation(PrecheckViolation::InitCodeTooShort(_))) => {}
            _ => panic!("Expected InitCodeTooShort error"),
        }
        assert_eq!(pool.best_operations(1), vec![]);
    }

    #[tokio::test]
    async fn simulation_error() {
        let op = create_op_with_errors(
            Address::random(),
            0,
            0,
            ReputationStatus::Ok,
            None,
            Some(SimulationViolation::DidNotRevert),
        );
        let ops = vec![op.clone()];
        let pool = create_pool(ops);

        match pool.add_operation(OperationOrigin::Local, op.op).await {
            Err(MempoolError::SimulationViolation(SimulationViolation::DidNotRevert)) => {}
            _ => panic!("Expected DidNotRevert error"),
        }
        assert_eq!(pool.best_operations(1), vec![]);
    }

    #[derive(Clone, Debug)]
    struct OpWithErrors {
        op: UserOperation,
        reputation: ReputationStatus,
        precheck_error: Option<PrecheckViolation>,
        simulation_error: Option<SimulationViolation>,
    }

    fn create_pool(
        ops: Vec<OpWithErrors>,
    ) -> UoPool<impl ReputationManager, impl Prechecker, impl Simulator> {
        let mut reputation = MockReputationManager::new();
        let mut simulator = MockSimulator::new();
        let mut prechecker = MockPrechecker::new();
        for op in ops {
            reputation.expect_status().returning(move |_| op.reputation);
            prechecker.expect_check().returning(move |_| {
                if let Some(error) = &op.precheck_error {
                    Err(PrecheckError::Violations(vec![error.clone()]))
                } else {
                    Ok(())
                }
            });
            simulator
                .expect_simulate_validation()
                .returning(move |_, _, _| {
                    if let Some(error) = &op.simulation_error {
                        Err(SimulationError::Violations(vec![error.clone()]))
                    } else {
                        Ok(SimulationSuccess {
                            signature_failed: false,
                            ..Default::default()
                        })
                    }
                });
        }

        let args = PoolConfig {
            entry_point: Address::random(),
            chain_id: 1,
            max_userops_per_sender: 16,
            min_replacement_fee_increase_percentage: 10,
            max_size_of_pool_bytes: 10000,
            blocklist: None,
            allowlist: None,
            precheck_settings: precheck::Settings::default(),
            sim_settings: simulation::Settings::default(),
            mempool_channel_configs: HashMap::new(),
        };
        UoPool::new(args, Arc::new(reputation), prechecker, simulator)
    }

    fn create_op(sender: Address, nonce: usize, max_fee_per_gas: usize) -> OpWithErrors {
        OpWithErrors {
            op: UserOperation {
                sender,
                nonce: nonce.into(),
                max_fee_per_gas: max_fee_per_gas.into(),
                ..UserOperation::default()
            },
            reputation: ReputationStatus::Ok,
            precheck_error: None,
            simulation_error: None,
        }
    }

    fn create_op_with_errors(
        sender: Address,
        nonce: usize,
        max_fee_per_gas: usize,
        reputation: ReputationStatus,
        precheck_error: Option<PrecheckViolation>,
        simulation_error: Option<SimulationViolation>,
    ) -> OpWithErrors {
        OpWithErrors {
            op: UserOperation {
                sender,
                nonce: nonce.into(),
                max_fee_per_gas: max_fee_per_gas.into(),
                ..UserOperation::default()
            },
            reputation,
            precheck_error,
            simulation_error,
        }
    }

    fn check_ops(ops: Vec<Arc<PoolOperation>>, expected: Vec<UserOperation>) {
        assert_eq!(ops.len(), expected.len());
        for (actual, expected) in ops.into_iter().zip(expected) {
            assert_eq!(actual.uo, expected);
        }
    }
}
