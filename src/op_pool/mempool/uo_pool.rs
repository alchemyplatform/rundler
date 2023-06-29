use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use ethers::types::{Address, H256};
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use super::{
    error::{MempoolError, MempoolResult},
    pool::PoolInner,
    Mempool, OperationOrigin, PoolConfig, PoolOperation,
};
use crate::{
    common::{contracts::i_entry_point::IEntryPointEvents, emit::WithEntryPoint, types::Entity},
    op_pool::{
        emit::{EntityReputation, EntityStatus, EntitySummary, OpPoolEvent, OpRemovalReason},
        event::NewBlockEvent,
        reputation::{Reputation, ReputationManager, ReputationStatus},
    },
};

/// The number of blocks that a throttled operation is allowed to be in the mempool
const THROTTLED_OPS_BLOCK_LIMIT: u64 = 10;

/// User Operation Mempool
///
/// Wrapper around a pool object that implements thread-safety
/// via a RwLock. Safe to call from multiple threads. Methods
/// block on write locks.
pub struct UoPool<R: ReputationManager> {
    entry_point: Address,
    chain_id: u64,
    reputation: Arc<R>,
    state: RwLock<UoPoolState>,
    event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
}

struct UoPoolState {
    pool: PoolInner,
    throttled_ops: HashMap<H256, u64>,
    block_number: u64,
}

impl<R> UoPool<R>
where
    R: ReputationManager,
{
    pub fn new(
        args: PoolConfig,
        reputation: Arc<R>,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
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
        }
    }

    pub async fn run(
        self: Arc<Self>,
        mut new_block_events: broadcast::Receiver<Arc<NewBlockEvent>>,
        shutdown_token: CancellationToken,
    ) {
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    tracing::info!("Shutting down UoPool");
                    break;
                }
                new_block = new_block_events.recv() => {
                    if let Ok(new_block) = new_block {
                        self.on_new_block(&new_block);
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
}

impl<R> Mempool for UoPool<R>
where
    R: ReputationManager,
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
        for event in &new_block.events {
            if let IEntryPointEvents::UserOperationEventFilter(uo_event) = &event.contract_event {
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

    fn add_operation(&self, origin: OperationOrigin, op: PoolOperation) -> MempoolResult<H256> {
        let mut throttled = false;
        let mut rejected_entity: Option<Entity> = None;
        let mut entity_summary = EntitySummary::default();
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
            let needs_stake = op.is_staked(entity.kind);
            if needs_stake {
                self.reputation.add_seen(address);
            }
            entity_summary.set_status(
                entity.kind,
                EntityStatus {
                    address,
                    needs_stake,
                    reputation,
                },
            );
        }

        let emit_event = {
            let op_hash = op.uo.op_hash(self.entry_point, self.chain_id);
            let valid_after = op.valid_time_range.valid_after;
            let valid_until = op.valid_time_range.valid_until;
            let op = op.uo.clone();
            move |block_number: u64, error: Option<String>| {
                self.emit(OpPoolEvent::ReceivedOp {
                    op_hash,
                    op,
                    block_number,
                    origin,
                    valid_after,
                    valid_until,
                    entities: entity_summary,
                    error: error.map(Arc::new),
                })
            }
        };

        if let Some(entity) = rejected_entity {
            let error = MempoolError::EntityThrottled(entity);
            emit_event(self.state.read().block_number, Some(error.to_string()));
            return Err(MempoolError::EntityThrottled(entity));
        }
        let mut state = self.state.write();
        let bn = state.block_number;
        let hash = match state.pool.add_operation(op) {
            Ok(hash) => hash,
            Err(error) => {
                emit_event(bn, Some(error.to_string()));
                return Err(error);
            }
        };
        if throttled {
            state.throttled_ops.insert(hash, bn);
        }
        emit_event(bn, None);
        Ok(hash)
    }

    fn add_operations(
        &self,
        _origin: OperationOrigin,
        operations: impl IntoIterator<Item = PoolOperation>,
    ) -> Vec<MempoolResult<H256>> {
        self.state.write().pool.add_operations(operations)
    }

    fn remove_operations<'a>(&self, hashes: impl IntoIterator<Item = &'a H256>) {
        // hold the lock for the duration of the operation
        let mut state = self.state.write();
        for hash in hashes {
            state.pool.remove_operation_by_hash(*hash);
        }
    }

    fn remove_entity(&self, entity: Entity) {
        let removed_op_hashes = self.state.write().pool.remove_entity(entity);
        self.emit(OpPoolEvent::RemovedEntity { entity });
        for op_hash in removed_op_hashes {
            self.emit(OpPoolEvent::RemovedOp {
                op_hash,
                reason: OpRemovalReason::EntityRemoved { entity },
            })
        }
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
    use crate::common::types::UserOperation;

    #[test]
    fn add_single_op() {
        let pool = create_pool();
        let op = create_op(Address::random(), 0, 0);
        let hash = pool
            .add_operation(OperationOrigin::Local, op.clone())
            .unwrap();
        check_ops(pool.best_operations(1), vec![op]);
        pool.remove_operations(&vec![hash]);
        assert_eq!(pool.best_operations(1), vec![]);
    }

    #[test]
    fn add_multiple_ops() {
        let pool = create_pool();
        let ops = vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ];
        let res = pool.add_operations(OperationOrigin::Local, ops.clone());
        let hashes: Vec<H256> = res.into_iter().map(|r| r.unwrap()).collect();
        check_ops(pool.best_operations(3), ops);
        pool.remove_operations(&hashes);
        assert_eq!(pool.best_operations(3), vec![]);
    }

    #[test]
    fn clear() {
        let pool = create_pool();
        let ops = vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ];
        pool.add_operations(OperationOrigin::Local, ops.clone());
        check_ops(pool.best_operations(3), ops);
        pool.clear();
        assert_eq!(pool.best_operations(3), vec![]);
    }

    fn create_pool() -> UoPool<MockReputationManager> {
        let args = PoolConfig {
            entry_point: Address::random(),
            chain_id: 1,
            max_userops_per_sender: 16,
            min_replacement_fee_increase_percentage: 10,
            max_size_of_pool_bytes: 10000,
            blocklist: None,
            allowlist: None,
        };
        let (event_sender, _) = broadcast::channel(4);
        UoPool::new(args, mock_reputation(), event_sender)
    }

    fn create_op(sender: Address, nonce: usize, max_fee_per_gas: usize) -> PoolOperation {
        PoolOperation {
            uo: UserOperation {
                sender,
                nonce: nonce.into(),
                max_fee_per_gas: max_fee_per_gas.into(),
                ..UserOperation::default()
            },
            ..PoolOperation::default()
        }
    }

    fn check_ops(ops: Vec<Arc<PoolOperation>>, expected: Vec<PoolOperation>) {
        assert_eq!(ops.len(), expected.len());
        for (actual, expected) in ops.into_iter().zip(expected) {
            assert_eq!(actual.uo, expected.uo);
        }
    }

    fn mock_reputation() -> Arc<MockReputationManager> {
        Arc::new(MockReputationManager::default())
    }

    #[derive(Default, Clone)]
    struct MockReputationManager;

    impl ReputationManager for MockReputationManager {
        fn status(&self, _address: Address) -> ReputationStatus {
            ReputationStatus::Ok
        }

        fn add_seen(&self, _address: Address) {}

        fn add_included(&self, _address: Address) {}

        fn dump_reputation(&self) -> Vec<Reputation> {
            vec![]
        }

        fn set_reputation(&self, _address: Address, _ops_seen: u64, _ops_included: u64) {}
    }
}
