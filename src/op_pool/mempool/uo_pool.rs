use super::{pool::PoolInner, Mempool, OnNewBlockEvent, OperationOrigin};
use crate::common::types::UserOperation;
use ethers::types::{Address, H256, U256};
use parking_lot::RwLock;
use std::sync::Arc;

/// User Operation Mempool
///
/// Wrapper around a pool object that implements thread-safety
/// via a RwLock. Safe to call from multiple threads. Methods
/// block on write locks.
pub struct UoPool {
    pool: RwLock<PoolInner>,
    entry_point: Address,
}

impl UoPool {
    pub fn new(entry_point: Address, chain_id: U256) -> Self {
        Self {
            pool: RwLock::new(PoolInner::new(entry_point, chain_id)),
            entry_point,
        }
    }
}

impl Mempool for UoPool {
    fn entry_point(&self) -> Address {
        self.entry_point
    }

    fn on_new_block(&self, event: OnNewBlockEvent) {
        self.remove_operations(&event.mined_operations);
    }

    fn add_operation(
        &self,
        _origin: OperationOrigin,
        operation: UserOperation,
    ) -> anyhow::Result<H256> {
        self.pool.write().add_operation(operation)
    }

    fn add_operations(
        &self,
        _origin: OperationOrigin,
        operations: impl IntoIterator<Item = UserOperation>,
    ) -> Vec<anyhow::Result<H256>> {
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
        self.pool.read().best_operations(max)
    }

    fn clear(&self) {
        self.pool.write().clear()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_single_op() {
        let pool = UoPool::new(Address::zero(), 1.into());
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
        let pool = UoPool::new(Address::zero(), 1.into());
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
    fn test_new_block() {
        let pool = UoPool::new(Address::zero(), 1.into());
        let ops = vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ];
        let res = pool.add_operations(OperationOrigin::Local, ops);
        let hashes = res.into_iter().map(|r| r.unwrap()).collect();
        pool.on_new_block(OnNewBlockEvent {
            mined_operations: hashes,
        });
        assert_eq!(pool.best_operations(3), vec![]);
    }

    #[test]
    fn test_clear() {
        let pool = UoPool::new(Address::zero(), 1.into());
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
}
