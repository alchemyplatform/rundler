use super::{
    error::{MempoolError, MempoolResult},
    pool::PoolInner,
    Mempool, NewBlockEvent, OperationOrigin, PoolOperation,
};
use crate::{
    common::{
        contracts::entry_point::EntryPointEvents,
        protos::op_pool::{Reputation, ReputationStatus},
        types::Entity,
    },
    op_pool::reputation::ReputationManager,
};
use anyhow::Context;
use ethers::types::{Address, H256, U256};
use parking_lot::RwLock;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use strum::IntoEnumIterator;
use tokio::sync::broadcast;

/// The number of blocks that a throttled operation is allowed to be in the mempool
const THROTTLED_OPS_BLOCK_LIMIT: u64 = 10;

/// User Operation Mempool
///
/// Wrapper around a pool object that implements thread-safety
/// via a RwLock. Safe to call from multiple threads. Methods
/// block on write locks.
pub struct UoPool<R: ReputationManager> {
    pool: RwLock<PoolInner>,
    entry_point: Address,
    reputation: Arc<R>,
    throttled_ops: RwLock<HashMap<H256, u64>>,
    block_number: RwLock<u64>,
}

impl<R> UoPool<R>
where
    R: ReputationManager,
{
    pub fn new(entry_point: Address, chain_id: U256, reputation: Arc<R>) -> Self {
        Self {
            pool: RwLock::new(PoolInner::new(entry_point, chain_id)),
            entry_point,
            reputation,
            throttled_ops: RwLock::new(HashMap::new()),
            block_number: RwLock::new(0),
        }
    }

    pub async fn run(
        self: Arc<Self>,
        mut new_block_events: broadcast::Receiver<Arc<NewBlockEvent>>,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = shutdown.recv() => {
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
}

impl<R> Mempool for UoPool<R>
where
    R: ReputationManager,
{
    fn entry_point(&self) -> Address {
        self.entry_point
    }

    fn on_new_block(&self, new_block: &NewBlockEvent) {
        let mut pool = self.pool.write();
        tracing::debug!("New block: {:?}", new_block.number);
        for event in &new_block.events {
            if let EntryPointEvents::UserOperationEventFilter(uo_event) = &event.contract_event {
                let op_hash = uo_event.user_op_hash.into();
                if let Some(op) = pool.remove_operation_by_hash(op_hash) {
                    for entity in Entity::iter() {
                        if op.requires_stake(entity) {
                            match op.entity_address(entity) {
                                Some(e) => self.reputation.add_included(e),
                                None => {
                                    tracing::error!("Entity address not found for entity {entity:?} in operation {op:?}");
                                }
                            }
                        }
                    }
                }

                // Remove throttled ops that were included in the block
                self.throttled_ops.write().remove(&op_hash);
            }
        }

        // Remove throttled ops that are too old
        let new_block_number = new_block.number.as_u64();
        let mut throttled_ops = self.throttled_ops.write();
        let mut to_remove = HashSet::new();
        for (hash, block) in throttled_ops.iter() {
            if new_block_number - block > THROTTLED_OPS_BLOCK_LIMIT {
                to_remove.insert(*hash);
            }
        }

        let mut pool = self.pool.write();
        for hash in to_remove {
            pool.remove_operation_by_hash(hash);
            throttled_ops.remove(&hash);
        }

        *self.block_number.write() = new_block_number;
    }

    fn add_operation(&self, _origin: OperationOrigin, op: PoolOperation) -> MempoolResult<H256> {
        let mut throttled = false;
        for entity in &op.entities_needing_stake {
            let addr = op
                .entity_address(*entity)
                .context(format!("entity {entity} should be present in operation"))?;
            match self.reputation.status(addr) {
                ReputationStatus::Ok => {}
                ReputationStatus::Throttled => {
                    if self.pool.read().address_count(addr) > 0 {
                        return Err(MempoolError::EntityThrottled(*entity, addr));
                    }
                    throttled = true;
                }
                ReputationStatus::Banned => {
                    return Err(MempoolError::EntityThrottled(*entity, addr));
                }
            }
            self.reputation.add_seen(addr);
        }

        let hash = self.pool.write().add_operation(op)?;

        if throttled {
            self.throttled_ops
                .write()
                .insert(hash, *self.block_number.read());
        }

        Ok(hash)
    }

    fn add_operations(
        &self,
        _origin: OperationOrigin,
        operations: impl IntoIterator<Item = PoolOperation>,
    ) -> Vec<MempoolResult<H256>> {
        self.pool.write().add_operations(operations)
    }

    fn remove_operations<'a>(&self, hashes: impl IntoIterator<Item = &'a H256>) {
        // hold the lock for the duration of the operation
        let mut lg = self.pool.write();
        for hash in hashes {
            lg.remove_operation_by_hash(*hash);
        }
    }

    fn best_operations(&self, max: usize) -> Vec<Arc<PoolOperation>> {
        // get the best operations from the pool
        let ordered_ops = self.pool.read().best_operations();
        // keep track of senders to avoid sending multiple ops from the same sender
        let mut senders = HashSet::<Address>::new();

        ordered_ops
            .into_iter()
            .filter(|op| {
                // filter out ops from senders we've already seen
                let sender = op.uo.sender;
                if senders.contains(&sender) {
                    false
                } else {
                    senders.insert(sender);
                    true
                }
            })
            .take(max)
            .collect()
    }

    fn clear(&self) {
        self.pool.write().clear()
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
    use crate::common::protos::op_pool::{Reputation, ReputationStatus};
    use crate::common::types::UserOperation;

    use super::*;

    #[test]
    fn test_add_single_op() {
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
    fn test_add_multiple_ops() {
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
    fn test_clear() {
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
        UoPool::new(Address::zero(), 1.into(), mock_reputation())
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
