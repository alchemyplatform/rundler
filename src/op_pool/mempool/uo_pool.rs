use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use ethers::types::{Address, H256};
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tonic::async_trait;
use tracing::info;

use super::{
    error::{MempoolError, MempoolResult},
    pool::PoolInner,
    reputation::{Reputation, ReputationManager, ReputationStatus},
    Mempool, OperationOrigin, PoolConfig, PoolOperation,
};
use crate::{
    common::{
        emit::WithEntryPoint,
        precheck::Prechecker,
        simulation::Simulator,
        types::{Entity, UserOperation, ValidTimeRange},
    },
    op_pool::{
        chain::ChainUpdate,
        emit::{EntityReputation, EntityStatus, EntitySummary, OpPoolEvent, OpRemovalReason},
    },
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
    chain_id: u64,
    reputation: Arc<R>,
    state: RwLock<UoPoolState>,
    event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
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
    pub fn new(
        args: PoolConfig,
        reputation: Arc<R>,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        prechecker: P,
        simulator: S,
    ) -> Self {
        Self {
            entry_point: args.entry_point,
            chain_id: args.chain_id,
            reputation,
            state: RwLock::new(UoPoolState {
                pool: PoolInner::new(args),
                throttled_ops: HashMap::new(),
                block_number: 0,
            }),
            event_sender,
            prechecker,
            simulator,
        }
    }

    fn emit(&self, event: OpPoolEvent) {
        let _ = self.event_sender.send(WithEntryPoint {
            entry_point: self.entry_point,
            event,
        });
    }
}

#[async_trait]
impl<R, P, S> Mempool for UoPool<R, P, S>
where
    R: ReputationManager,
    P: Prechecker,
    S: Simulator,
{
    fn on_chain_update(&self, update: &ChainUpdate) {
        let mut state = self.state.write();
        let deduped_ops = update.deduped_ops();
        let mined_ops = deduped_ops
            .mined_ops
            .iter()
            .filter(|op| op.entry_point == self.entry_point);
        let unmined_ops = deduped_ops
            .unmined_ops
            .iter()
            .filter(|op| op.entry_point == self.entry_point);
        let mut mined_op_count = 0;
        let mut unmined_op_count = 0;
        for op in mined_ops {
            if op.entry_point != self.entry_point {
                continue;
            }

            // Remove throttled ops that were included in the block
            state.throttled_ops.remove(&op.hash);
            if let Some(op) = state
                .pool
                .mine_operation(op.hash, update.latest_block_number)
            {
                for entity in op.staked_entities() {
                    self.reputation.add_included(entity.address);
                }
                mined_op_count += 1;
            }
        }
        for op in unmined_ops {
            if op.entry_point != self.entry_point {
                continue;
            }

            if let Some(op) = state.pool.unmine_operation(op.hash) {
                for entity in op.staked_entities() {
                    self.reputation.remove_included(entity.address);
                }
                unmined_op_count += 1;
            }
        }
        if mined_op_count > 0 {
            info!(
                "{mined_op_count} op(s) mined on entry point {:?} when advancing to block with number {}, hash {:?}.",
                self.entry_point,
                update.latest_block_number,
                update.latest_block_hash,
            );
        }
        if unmined_op_count > 0 {
            info!(
                "{unmined_op_count} op(s) unmined in reorg on entry point {:?} when advancing to block with number {}, hash {:?}.",
                self.entry_point,
                update.latest_block_number,
                update.latest_block_hash,
            );
        }
        UoPoolMetrics::update_ops_seen(
            mined_op_count as isize - unmined_op_count as isize,
            self.entry_point,
        );
        UoPoolMetrics::increment_unmined_operations(unmined_op_count, self.entry_point);

        state
            .pool
            .forget_mined_operations_before_block(update.earliest_remembered_block_number);
        // Remove throttled ops that are too old
        let mut to_remove = HashSet::new();
        for (hash, block) in state.throttled_ops.iter() {
            if update.latest_block_number - block > THROTTLED_OPS_BLOCK_LIMIT {
                to_remove.insert(*hash);
            }
        }
        for hash in to_remove {
            state.pool.remove_operation_by_hash(hash);
            state.throttled_ops.remove(&hash);
        }
        state.block_number = update.latest_block_number;
    }

    fn entry_point(&self) -> Address {
        self.entry_point
    }

    async fn add_operation(
        &self,
        origin: OperationOrigin,
        op: UserOperation,
    ) -> MempoolResult<H256> {
        // TODO(danc) aggregator throttling is not implemented
        // TODO(danc) catch ops with aggregators prior to simulation

        let mut rejected_entity: Option<Entity> = None;
        let mut entity_summary = EntitySummary::default();

        // Check if op has a throttled/banned entity
        let mut throttled = false;
        for entity in op.entities() {
            let address = entity.address;
            let reputation = match self.reputation.status(address) {
                ReputationStatus::Ok => EntityReputation::Ok,
                ReputationStatus::Throttled => {
                    if self.state.read().pool.address_count(address) > 0 {
                        rejected_entity = Some(entity);
                        EntityReputation::ThrottledAndRejected
                    } else {
                        throttled = true;
                        EntityReputation::ThrottledButOk
                    }
                }
                ReputationStatus::Banned => {
                    rejected_entity = Some(entity);
                    EntityReputation::Banned
                }
            };
            entity_summary.set_status(
                entity.kind,
                EntityStatus {
                    address,
                    reputation,
                },
            );
        }

        let emit_event = {
            let op_cpy = op.clone();
            move |block_number: u64,
                  error: Option<String>,
                  valid_time_range: Option<ValidTimeRange>| {
                self.emit(OpPoolEvent::ReceivedOp {
                    op_hash: op_cpy.op_hash(self.entry_point, self.chain_id),
                    op: op_cpy,
                    block_number,
                    origin,
                    valid_after: valid_time_range.map(|v| v.valid_after),
                    valid_until: valid_time_range.map(|v| v.valid_until),
                    entities: entity_summary,
                    error: error.map(Arc::new),
                })
            }
        };

        if let Some(entity) = rejected_entity {
            let error = MempoolError::EntityThrottled(entity);
            emit_event(
                self.state.read().block_number,
                Some(error.to_string()),
                None,
            );
            return Err(MempoolError::EntityThrottled(entity));
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
        if let Some(agg) = &sim_result.aggregator {
            return Err(MempoolError::UnsupportedAggregator(agg.address));
        }
        let valid_time_range = sim_result.valid_time_range;
        let pool_op = PoolOperation {
            uo: op,
            aggregator: None,
            valid_time_range,
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
        emit_event(bn, None, Some(valid_time_range));
        Ok(hash)
    }

    fn remove_operations(&self, hashes: &[H256]) {
        let mut count = 0;
        let mut removed_hashes = vec![];
        {
            let mut state = self.state.write();
            for hash in hashes {
                if state.pool.remove_operation_by_hash(*hash).is_some() {
                    count += 1;
                    removed_hashes.push(*hash);
                }
            }
        }

        for hash in removed_hashes {
            self.emit(OpPoolEvent::RemovedOp {
                op_hash: hash,
                reason: OpRemovalReason::Requested,
            })
        }
        UoPoolMetrics::increment_removed_operations(count, self.entry_point);
    }

    fn remove_entity(&self, entity: Entity) {
        let removed_op_hashes = self.state.write().pool.remove_entity(entity);
        let count = removed_op_hashes.len();
        self.emit(OpPoolEvent::RemovedEntity { entity });
        for op_hash in removed_op_hashes {
            self.emit(OpPoolEvent::RemovedOp {
                op_hash,
                reason: OpRemovalReason::EntityRemoved { entity },
            })
        }
        UoPoolMetrics::increment_removed_operations(count, self.entry_point);
        UoPoolMetrics::increment_removed_entities(self.entry_point);
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

struct UoPoolMetrics {}

impl UoPoolMetrics {
    fn update_ops_seen(num_ops: isize, entry_point: Address) {
        metrics::increment_gauge!("op_pool_ops_seen", num_ops as f64, "entrypoint" => entry_point.to_string());
    }

    fn increment_unmined_operations(num_ops: usize, entry_point: Address) {
        metrics::counter!("op_pool_unmined_operations", num_ops as u64, "entrypoint" => entry_point.to_string());
    }

    fn increment_removed_operations(num_ops: usize, entry_point: Address) {
        metrics::counter!("op_pool_removed_operations", num_ops as u64, "entrypoint" => entry_point.to_string());
    }

    fn increment_removed_entities(entry_point: Address) {
        metrics::increment_counter!("op_pool_removed_entities", "entrypoint" => entry_point.to_string());
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
        op_pool::{chain::MinedOp, mempool::reputation::MockReputationManager},
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
    async fn chain_update_mine() {
        let (pool, uos) = create_pool_insert_ops(vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ])
        .await;
        check_ops(pool.best_operations(3), uos.clone());

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: H256::random(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: pool.entry_point,
                hash: uos[0].op_hash(pool.entry_point, 1),
                sender: uos[0].sender,
                nonce: uos[0].nonce,
            }],
            unmined_ops: vec![],
        });

        check_ops(pool.best_operations(3), uos[1..].to_vec());
    }

    #[tokio::test]
    async fn chain_update_mine_unmine() {
        let (pool, uos) = create_pool_insert_ops(vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ])
        .await;
        check_ops(pool.best_operations(3), uos.clone());

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: H256::random(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: pool.entry_point,
                hash: uos[0].op_hash(pool.entry_point, 1),
                sender: uos[0].sender,
                nonce: uos[0].nonce,
            }],
            unmined_ops: vec![],
        });
        check_ops(pool.best_operations(3), uos.clone()[1..].to_vec());

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: H256::random(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![],
            unmined_ops: vec![MinedOp {
                entry_point: pool.entry_point,
                hash: uos[0].op_hash(pool.entry_point, 1),
                sender: uos[0].sender,
                nonce: uos[0].nonce,
            }],
        });
        check_ops(pool.best_operations(3), uos);
    }

    #[tokio::test]
    async fn chain_update_wrong_ep() {
        let (pool, uos) = create_pool_insert_ops(vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ])
        .await;
        check_ops(pool.best_operations(3), uos.clone());

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: H256::random(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: Address::random(),
                hash: uos[0].op_hash(pool.entry_point, 1),
                sender: uos[0].sender,
                nonce: uos[0].nonce,
            }],
            unmined_ops: vec![],
        });

        check_ops(pool.best_operations(3), uos);
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
        let ret = pool.add_operation(OperationOrigin::Local, op.op).await;
        match ret {
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
                        Ok(SimulationSuccess::default())
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
        let (event_sender, _) = broadcast::channel(4);
        UoPool::new(
            args,
            Arc::new(reputation),
            event_sender,
            prechecker,
            simulator,
        )
    }

    async fn create_pool_insert_ops(
        ops: Vec<OpWithErrors>,
    ) -> (
        UoPool<impl ReputationManager, impl Prechecker, impl Simulator>,
        Vec<UserOperation>,
    ) {
        let uos = ops.iter().map(|op| op.op.clone()).collect::<Vec<_>>();
        let pool = create_pool(ops);
        for op in &uos {
            let _ = pool
                .add_operation(OperationOrigin::Local, op.clone())
                .await
                .unwrap();
        }
        (pool, uos)
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
