use super::{
    error::MempoolResult, pool::PoolInner, Mempool, NewBlockEvent, OperationOrigin, PoolOperation,
};
use crate::{
    common::{
        contracts::entry_point::EntryPointEvents,
        protos::op_pool::{Reputation, ReputationStatus},
        types::UserOperation,
    },
    op_pool::reputation::ReputationManager,
};
use ethers::types::{Address, H256, U256};
use parking_lot::RwLock;
use std::{collections::HashSet, sync::Arc};
use tokio::sync::broadcast;

/// User Operation Mempool
///
/// Wrapper around a pool object that implements thread-safety
/// via a RwLock. Safe to call from multiple threads. Methods
/// block on write locks.
pub struct UoPool<R: ReputationManager> {
    pool: RwLock<PoolInner>,
    entry_point: Address,
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

    fn get_op_addresses(op: &PoolOperation) -> Vec<Address> {
        let mut addrs = vec![op.uo.sender];
        if let Some(paymaster) = UserOperation::get_address_from_field(&op.uo.paymaster_and_data) {
            addrs.push(paymaster);
        }
        if let Some(factory) = UserOperation::get_address_from_field(&op.uo.init_code) {
            addrs.push(factory);
        }
        if let Some(agg) = op.aggregator {
            addrs.push(agg);
        }
        addrs
    }

    fn is_throttled(&self, op: &PoolOperation) -> bool {
        let addrs = Self::get_op_addresses(op);
        addrs
            .iter()
            .any(|addr| self.reputation.status(*addr) != ReputationStatus::Ok)
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
            match &event.contract_event {
                EntryPointEvents::UserOperationEventFilter(uo_event) => {
                    if pool.remove_operation_by_hash(uo_event.user_op_hash.into()) {
                        let mut addrs = vec![uo_event.sender];
                        if !uo_event.paymaster.is_zero() {
                            addrs.push(uo_event.paymaster);
                        }
                        if let Some(agg) = self.reputation.get_aggregator(event.txn_hash) {
                            addrs.push(agg);
                        }
                        self.reputation.add_included(&addrs);
                    }
                }
                EntryPointEvents::AccountDeployedFilter(deploy_event) => {
                    self.reputation.add_included(&[deploy_event.factory]);
                }
                EntryPointEvents::SignatureAggregatorChangedFilter(aggregator_change_event) => {
                    let agg = if aggregator_change_event.aggregator.is_zero() {
                        None
                    } else {
                        Some(aggregator_change_event.aggregator)
                    };
                    self.reputation.set_aggregator(agg, event.txn_hash);
                }
                _ => {}
            }
        }
    }

    fn add_operation(&self, _origin: OperationOrigin, op: PoolOperation) -> MempoolResult<H256> {
        let addrs = Self::get_op_addresses(&op);
        self.reputation.add_seen(&addrs);
        self.pool.write().add_operation(op)
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
                // filter out ops from senders we've already seen, or that have been throttled due to reputation
                let sender = op.uo.sender;
                if senders.contains(&sender) || self.is_throttled(op) {
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

        fn add_seen<'a>(&self, _addresses: impl IntoIterator<Item = &'a Address>) {}

        fn add_included<'a>(&self, _addresses: impl IntoIterator<Item = &'a Address>) {}

        fn set_aggregator(&self, _aggregator: Option<Address>, _txn_hash: H256) {}

        fn get_aggregator(&self, _txn_hash: H256) -> Option<Address> {
            None
        }

        fn dump_reputation(&self) -> Vec<Reputation> {
            vec![]
        }

        fn set_reputation(&self, _address: Address, _ops_seen: u64, _ops_included: u64) {}
    }
}
