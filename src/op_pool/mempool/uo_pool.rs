use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use ethers::types::{Address, H256};
use itertools::Itertools;
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
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
        types::{Entity, UserOperation},
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

    pub async fn run(
        self: Arc<Self>,
        mut chain_events: broadcast::Receiver<Arc<ChainUpdate>>,
        shutdown_token: CancellationToken,
    ) {
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    tracing::info!("Shutting down UoPool");
                    break;
                }
                update = chain_events.recv() => {
                    if let Ok(update) = update {
                        self.on_chain_update(&update);
                    }
                }
            }
        }
    }

    fn emit(&self, event: OpPoolEvent) {
        let _ = self.event_sender.send(WithEntryPoint {
            entry_point: self.entry_point,
            event,
        });
    }

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
                // Only account for a staked entity once
                for entity_addr in op.staked_entities().map(|e| e.address).unique() {
                    self.reputation.add_included(entity_addr);
                }
                mined_op_count += 1;
            }
        }
        for op in unmined_ops {
            if op.entry_point != self.entry_point {
                continue;
            }

            if let Some(op) = state.pool.unmine_operation(op.hash) {
                // Only account for a staked entity once
                for entity_addr in op.staked_entities().map(|e| e.address).unique() {
                    self.reputation.add_included(entity_addr);
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

    async fn add_operation(
        &self,
        origin: OperationOrigin,
        op: UserOperation,
    ) -> MempoolResult<H256> {
        // TODO(danc) aggregator reputation is not implemented
        // TODO(danc) catch ops with aggregators prior to simulation and reject

        // Check reputation of entities in involved in the operation
        // If throttled, entity can have 1 inflight operation at a time, else reject
        // If banned, reject
        let mut entity_summary = EntitySummary::default();
        let mut throttled = false;
        for entity in op.entities() {
            let address = entity.address;
            let reputation = match self.reputation.status(address) {
                ReputationStatus::Ok => EntityReputation::Ok,
                ReputationStatus::Throttled => {
                    if self.state.read().pool.address_count(address) > 0 {
                        return Err(MempoolError::EntityThrottled(entity));
                    } else {
                        throttled = true;
                        EntityReputation::ThrottledButOk
                    }
                }
                ReputationStatus::Banned => {
                    return Err(MempoolError::EntityThrottled(entity));
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

        // Add op to pool
        let mut state = self.state.write();
        let hash = state.pool.add_operation(pool_op.clone())?;
        let bn = state.block_number;
        if throttled {
            state.throttled_ops.insert(hash, bn);
        }

        // Update reputation
        pool_op
            .staked_entities()
            .map(|e| e.address)
            .unique()
            .for_each(|a| self.reputation.add_seen(a));

        // If an entity was throttled, track with throttled ops
        if throttled {
            state.throttled_ops.insert(hash, bn);
        }

        let op_hash = pool_op.uo.op_hash(self.entry_point, self.chain_id);
        let valid_after = pool_op.valid_time_range.valid_after;
        let valid_until = pool_op.valid_time_range.valid_until;
        self.emit(OpPoolEvent::ReceivedOp {
            op_hash,
            op: pool_op.uo,
            block_number: bn,
            origin,
            valid_after,
            valid_until,
            entities: entity_summary,
            error: None,
        });

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
            types::{EntityType, UserOperation},
        },
        op_pool::chain::MinedOp,
    };

    const THROTTLE_SLACK: u64 = 5;
    const BAN_SLACK: u64 = 10;

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
    async fn test_account_reputation() {
        let address = Address::random();
        let (pool, uos) = create_pool_insert_ops(vec![
            create_op_with_errors(address, 0, 2, None, None, true),
            create_op_with_errors(address, 1, 2, None, None, true),
            create_op_with_errors(address, 1, 2, None, None, true),
        ])
        .await;
        // Only return 1 op per sender
        check_ops(pool.best_operations(3), vec![uos[0].clone()]);

        let rep = pool.dump_reputation();
        assert_eq!(rep.len(), 1);
        assert_eq!(rep[0].address, address);
        assert_eq!(rep[0].ops_seen, 2); // 2 ops seen, 1 rejected at insert
        assert_eq!(rep[0].ops_included, 0); // No ops included yet

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

        let rep = pool.dump_reputation();
        assert_eq!(rep.len(), 1);
        assert_eq!(rep[0].address, address);
        assert_eq!(rep[0].ops_seen, 2); // 2 ops seen, 1 rejected at insert
        assert_eq!(rep[0].ops_included, 1); // 1 op included
    }

    #[tokio::test]
    async fn test_throttled_account() {
        let address = Address::random();

        let ops = vec![
            create_op_with_errors(address, 0, 2, None, None, true),
            create_op_with_errors(address, 1, 2, None, None, true),
        ];
        let uos = ops.iter().map(|op| op.op.clone()).collect::<Vec<_>>();
        let pool = create_pool(ops);
        // Past throttle slack
        pool.set_reputation(address, 1 + THROTTLE_SLACK, 0);

        // First op should be included
        pool.add_operation(OperationOrigin::Local, uos[0].clone())
            .await
            .unwrap();
        check_ops(pool.best_operations(1), vec![uos[0].clone()]);

        // Second op should be thorottled
        let ret = pool
            .add_operation(OperationOrigin::Local, uos[1].clone())
            .await;
        assert!(ret.is_err());
        match ret.unwrap_err() {
            MempoolError::EntityThrottled(entity) => {
                assert_eq!(entity.address, address);
                assert_eq!(entity.kind, EntityType::Account)
            }
            _ => panic!("Expected throttled error"),
        }

        // Mine first op
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

        // Second op should be included
        pool.add_operation(OperationOrigin::Local, uos[1].clone())
            .await
            .unwrap();
        check_ops(pool.best_operations(1), vec![uos[1].clone()]);
    }

    #[tokio::test]
    async fn test_banned_account() {
        let address = Address::random();

        let op = create_op_with_errors(address, 0, 2, None, None, true);
        let uo = op.op.clone();
        let pool = create_pool(vec![op]);
        // Past ban slack
        pool.set_reputation(address, 1 + BAN_SLACK, 0);

        // First op should be banned
        let ret = pool.add_operation(OperationOrigin::Local, uo.clone()).await;
        assert!(ret.is_err());
        match ret.unwrap_err() {
            MempoolError::EntityThrottled(entity) => {
                assert_eq!(entity.address, address);
                assert_eq!(entity.kind, EntityType::Account)
            }
            _ => panic!("Expected throttled error"),
        }
    }

    #[tokio::test]
    async fn precheck_error() {
        let op = create_op_with_errors(
            Address::random(),
            0,
            0,
            Some(PrecheckViolation::InitCodeTooShort(0)),
            None,
            false,
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
            None,
            Some(SimulationViolation::DidNotRevert),
            false,
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
        precheck_error: Option<PrecheckViolation>,
        simulation_error: Option<SimulationViolation>,
        staked: bool,
    }

    fn create_pool(
        ops: Vec<OpWithErrors>,
    ) -> UoPool<impl ReputationManager, impl Prechecker, impl Simulator> {
        let reputation = Arc::new(MockReputationManager::new(THROTTLE_SLACK, BAN_SLACK));
        let mut simulator = MockSimulator::new();
        let mut prechecker = MockPrechecker::new();
        for op in ops {
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
                            account_is_staked: op.staked,
                            ..SimulationSuccess::default()
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
        let (event_sender, _) = broadcast::channel(4);
        UoPool::new(args, reputation, event_sender, prechecker, simulator)
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
            let _ = pool.add_operation(OperationOrigin::Local, op.clone()).await;
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
            precheck_error: None,
            simulation_error: None,
            staked: false,
        }
    }

    fn create_op_with_errors(
        sender: Address,
        nonce: usize,
        max_fee_per_gas: usize,
        precheck_error: Option<PrecheckViolation>,
        simulation_error: Option<SimulationViolation>,
        staked: bool,
    ) -> OpWithErrors {
        OpWithErrors {
            op: UserOperation {
                sender,
                nonce: nonce.into(),
                max_fee_per_gas: max_fee_per_gas.into(),
                ..UserOperation::default()
            },
            precheck_error,
            simulation_error,
            staked,
        }
    }

    fn check_ops(ops: Vec<Arc<PoolOperation>>, expected: Vec<UserOperation>) {
        assert_eq!(ops.len(), expected.len());
        for (actual, expected) in ops.into_iter().zip(expected) {
            assert_eq!(actual.uo, expected);
        }
    }

    #[derive(Default, Clone)]
    struct MockReputationManager {
        throttling_slack: u64,
        ban_slack: u64,
        counts: Arc<RwLock<Counts>>,
    }

    #[derive(Default)]
    struct Counts {
        seen: HashMap<Address, u64>,
        included: HashMap<Address, u64>,
    }

    impl MockReputationManager {
        fn new(throttling_slack: u64, ban_slack: u64) -> Self {
            Self {
                throttling_slack,
                ban_slack,
                ..Self::default()
            }
        }
    }

    impl ReputationManager for MockReputationManager {
        fn status(&self, address: Address) -> ReputationStatus {
            let counts = self.counts.read();

            let seen = *counts.seen.get(&address).unwrap_or(&0);
            let included = *counts.included.get(&address).unwrap_or(&0);
            let diff = seen.saturating_sub(included);
            if diff > self.ban_slack {
                ReputationStatus::Banned
            } else if diff > self.throttling_slack {
                ReputationStatus::Throttled
            } else {
                ReputationStatus::Ok
            }
        }

        fn add_seen(&self, address: Address) {
            *self.counts.write().seen.entry(address).or_default() += 1;
        }

        fn add_included(&self, address: Address) {
            *self.counts.write().included.entry(address).or_default() += 1;
        }

        fn remove_included(&self, address: Address) {
            let mut counts = self.counts.write();
            let included = counts.included.entry(address).or_default();
            *included = included.saturating_sub(1);
        }

        fn dump_reputation(&self) -> Vec<Reputation> {
            self.counts
                .read()
                .seen
                .iter()
                .map(|(address, ops_seen)| Reputation {
                    address: *address,
                    ops_seen: *ops_seen,
                    ops_included: *self.counts.read().included.get(address).unwrap_or(&0),
                    status: self.status(*address),
                })
                .collect()
        }

        fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64) {
            let mut counts = self.counts.write();
            counts.seen.insert(address, ops_seen);
            counts.included.insert(address, ops_included);
        }
    }
}
