use super::{pool::PoolInner, Mempool, NewBlockEvent, OperationOrigin};
use crate::{
    common::{contracts::entry_point::EntryPointEvents, types::UserOperation},
    op_pool::reputation::ReputationManager,
};
use ethers::types::{Address, H256, U256};
use parking_lot::RwLock;
use std::sync::Arc;

/// User Operation Mempool
///
/// Wrapper around a pool object that implements thread-safety
/// via a RwLock. Safe to call from multiple threads. Methods
/// block on write locks.
pub struct UoPool<R: ReputationManager> {
    pool: RwLock<PoolInner>,
    entry_point: Address,
    #[allow(dead_code)] // TODO(danc): remove once implemented
    reputation: Arc<R>,
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
        }
    }
}

impl<R> Mempool for UoPool<R>
where
    R: ReputationManager,
{
    type ReputationManagerType = R;

    fn entry_point(&self) -> Address {
        self.entry_point
    }

    fn on_new_block(&self, new_block: &NewBlockEvent) {
        let mut pool = self.pool.write();
        tracing::debug!("New block: {:?}", new_block.number);
        for event in &new_block.events {
            match &event.contract_event {
                EntryPointEvents::UserOperationEventFilter(event) => {
                    pool.remove_operation_by_hash(event.user_op_hash.into());
                }
                EntryPointEvents::AccountDeployedFilter(_) => todo!(),
                EntryPointEvents::SignatureAggregatorChangedFilter(_) => todo!(),
                _ => {}
            }
        }
    }

    fn add_operation(
        &self,
        _origin: OperationOrigin,
        operation: UserOperation,
    ) -> anyhow::Result<H256> {
        // TODO(danc): update reputation
        self.pool.write().add_operation(operation)
    }

    fn add_operations(
        &self,
        _origin: OperationOrigin,
        operations: impl IntoIterator<Item = UserOperation>,
    ) -> Vec<anyhow::Result<H256>> {
        // TODO(danc): update reputation
        self.pool.write().add_operations(operations)
    }

    fn remove_operations<'a>(&self, hashes: impl IntoIterator<Item = &'a H256>) {
        // hold the lock for the duration of the operation
        let mut lg = self.pool.write();
        for hash in hashes {
            lg.remove_operation_by_hash(*hash);
        }
    }

    fn best_operations(&self, max: usize) -> Vec<Arc<UserOperation>> {
        // TODO(danc): use reputation to filter out ops
        self.pool.read().best_operations(max)
    }

    fn clear(&self) {
        self.pool.write().clear()
    }
}

#[cfg(test)]
mod tests {
    use crate::common::protos::op_pool::{Reputation, ReputationStatus};

    use super::*;

    #[test]
    fn test_add_single_op() {
        let pool = UoPool::new(Address::zero(), 1.into(), mock_reputation());
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
        let pool = UoPool::new(Address::zero(), 1.into(), mock_reputation());
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
        let pool = UoPool::new(Address::zero(), 1.into(), mock_reputation());
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

    fn create_op(sender: Address, nonce: usize, max_fee_per_gas: usize) -> UserOperation {
        UserOperation {
            sender,
            nonce: nonce.into(),
            max_fee_per_gas: max_fee_per_gas.into(),
            ..UserOperation::default()
        }
    }

    fn check_ops(ops: Vec<Arc<UserOperation>>, expected: Vec<UserOperation>) {
        assert_eq!(ops.len(), expected.len());
        for (actual, expected) in ops.into_iter().zip(expected) {
            assert_eq!(*actual, expected);
        }
    }

    fn mock_reputation() -> Arc<MockReputationManager> {
        Arc::new(MockReputationManager::default())
    }

    #[derive(Default, Clone)]
    struct MockReputationManager;

    impl ReputationManager for MockReputationManager {
        fn on_new_block(&self, _new_block: &NewBlockEvent) {}

        fn status(&self, _address: Address) -> ReputationStatus {
            ReputationStatus::Ok
        }

        fn add_seen<'a>(&self, _addresses: impl IntoIterator<Item = &'a Address>) {}

        fn dump_reputation(&self) -> Vec<Reputation> {
            vec![]
        }

        fn set_reputation(&self, _address: Address, _ops_seen: u64, _ops_included: u64) {}
    }
}
