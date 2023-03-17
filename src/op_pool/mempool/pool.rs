use crate::common::types::{UserOperation, UserOperationId};
use ethers::{
    abi::Address,
    types::{H256, U256},
};
use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, BTreeSet, HashMap},
    sync::Arc,
};

use super::{
    error::{MempoolError, MempoolResult},
    PoolOperation,
};

/// The maximum number of operations a sender can have in the mempool
const MAX_MEMPOOL_USEROPS_PER_SENDER: usize = 16;

/// Pool of user operations
#[derive(Debug)]
pub struct PoolInner {
    // Address of the entry point this pool targets
    entry_point: Address,
    // Chain ID this pool targets
    chain_id: U256,
    // Operations by hash
    by_hash: HashMap<H256, OrderedPoolOperation>,
    // Operations by operation ID
    by_id: HashMap<UserOperationId, OrderedPoolOperation>,
    // Best operations, sorted by gas price
    best: BTreeSet<OrderedPoolOperation>,
    // Count of operations by sender
    count_by_address: HashMap<Address, usize>,
    // Submission ID counter
    submission_id: u64,
}

impl PoolInner {
    pub fn new(entry_point: Address, chain_id: U256) -> Self {
        Self {
            by_hash: HashMap::new(),
            by_id: HashMap::new(),
            best: BTreeSet::new(),
            count_by_address: HashMap::new(),
            entry_point,
            chain_id,
            submission_id: 0,
        }
    }

    pub fn add_operation(&mut self, op: PoolOperation) -> MempoolResult<H256> {
        // Check for replacement by ID
        if let Some(pool_op) = self.by_id.get(&op.uo.id()) {
            // replace only if higher gas
            if pool_op.uo().max_priority_fee_per_gas <= op.uo.max_priority_fee_per_gas
                && pool_op.uo().max_fee_per_gas <= op.uo.max_fee_per_gas
            {
                self.best.remove(pool_op);
                self.by_hash
                    .remove(&pool_op.uo().op_hash(self.entry_point, self.chain_id));
            } else {
                return Err(MempoolError::ReplacementUnderpriced(
                    pool_op.uo().max_priority_fee_per_gas,
                    pool_op.uo().max_fee_per_gas,
                ));
            }
        }

        // Check sender count in mempool
        if *self.count_by_address.get(&op.uo.sender).unwrap_or(&0) >= MAX_MEMPOOL_USEROPS_PER_SENDER
        {
            return Err(MempoolError::MaxOperationsReached(
                MAX_MEMPOOL_USEROPS_PER_SENDER,
                op.uo.sender,
            ));
        }

        // update counts
        for (_, addr) in op.entities() {
            *self.count_by_address.entry(addr).or_insert(0) += 1;
        }

        // create and insert ordered operation
        let pool_op = OrderedPoolOperation {
            po: Arc::new(op),
            submission_id: self.next_submission_id(),
        };
        let hash = pool_op.uo().op_hash(self.entry_point, self.chain_id);
        self.by_hash.insert(hash, pool_op.clone());
        self.by_id.insert(pool_op.uo().id(), pool_op.clone());
        self.best.insert(pool_op);

        Ok(hash)
    }

    pub fn add_operations(
        &mut self,
        operations: impl IntoIterator<Item = PoolOperation>,
    ) -> Vec<MempoolResult<H256>> {
        operations
            .into_iter()
            .map(|op| self.add_operation(op))
            .collect()
    }

    pub fn best_operations(&self) -> impl Iterator<Item = Arc<PoolOperation>> {
        self.best.clone().into_iter().map(|v| v.po)
    }

    pub fn address_count(&self, address: Address) -> usize {
        self.count_by_address.get(&address).copied().unwrap_or(0)
    }

    pub fn remove_operation_by_hash(&mut self, hash: H256) -> Option<Arc<PoolOperation>> {
        if let Some(op) = self.by_hash.remove(&hash) {
            self.by_id.remove(&op.uo().id());
            self.best.remove(&op);

            for (_, addr) in op.po.entities() {
                self.decrement_address_count(addr);
            }

            return Some(op.po);
        }

        None
    }

    pub fn clear(&mut self) {
        self.by_hash.clear();
        self.by_id.clear();
        self.best.clear();
        self.count_by_address.clear();
    }

    fn decrement_address_count(&mut self, address: Address) {
        if let Entry::Occupied(mut count_entry) = self.count_by_address.entry(address) {
            *count_entry.get_mut() -= 1;
            if *count_entry.get() == 0 {
                count_entry.remove_entry();
            }
        }
    }

    fn next_submission_id(&mut self) -> u64 {
        let id = self.submission_id;
        self.submission_id += 1;
        id
    }
}

/// Wrapper around PoolOperation that adds a submission ID to implement
/// a custom ordering for the best operations
#[derive(Debug, Clone)]
struct OrderedPoolOperation {
    po: Arc<PoolOperation>,
    submission_id: u64,
}

impl OrderedPoolOperation {
    fn uo(&self) -> &UserOperation {
        &self.po.uo
    }
}

impl Eq for OrderedPoolOperation {}

impl Ord for OrderedPoolOperation {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort by gas price descending then by id ascending
        other
            .uo()
            .max_fee_per_gas
            .cmp(&self.uo().max_fee_per_gas)
            .then_with(|| self.submission_id.cmp(&other.submission_id))
    }
}

impl PartialOrd for OrderedPoolOperation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OrderedPoolOperation {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use ethers::types::Bytes;

    use super::*;

    #[test]
    fn add_single_op() {
        let mut pool = PoolInner::new(Address::zero(), 1.into());
        let op = create_op(Address::random(), 0, 1);
        let hash = pool.add_operation(op.clone()).unwrap();

        check_map_entry(pool.by_hash.get(&hash), Some(&op));
        check_map_entry(pool.by_id.get(&op.uo.id()), Some(&op));
        check_map_entry(pool.best.iter().next(), Some(&op));
    }

    #[test]
    fn add_multiple_ops() {
        let mut pool = PoolInner::new(Address::zero(), 1.into());
        let ops = vec![
            create_op(Address::random(), 0, 1),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 3),
        ];

        let mut hashes = vec![];
        for op in ops.iter() {
            hashes.push(pool.add_operation(op.clone()).unwrap());
        }

        for (hash, op) in hashes.iter().zip(&ops) {
            check_map_entry(pool.by_hash.get(hash), Some(op));
            check_map_entry(pool.by_id.get(&op.uo.id()), Some(op));
        }

        // best should be sorted by gas
        assert_eq!(pool.best.len(), 3);
        check_map_entry(pool.best.iter().next(), Some(&ops[2]));
        check_map_entry(pool.best.iter().nth(1), Some(&ops[1]));
        check_map_entry(pool.best.iter().nth(2), Some(&ops[0]));
    }

    #[test]
    fn best_ties() {
        let mut pool = PoolInner::new(Address::zero(), 1.into());
        let ops = vec![
            create_op(Address::random(), 0, 1),
            create_op(Address::random(), 0, 1),
            create_op(Address::random(), 0, 1),
        ];

        let mut hashes = vec![];
        for op in ops.iter() {
            hashes.push(pool.add_operation(op.clone()).unwrap());
        }

        // best should be sorted by gas, then by submission id
        assert_eq!(pool.best.len(), 3);
        check_map_entry(pool.best.iter().next(), Some(&ops[0]));
        check_map_entry(pool.best.iter().nth(1), Some(&ops[1]));
        check_map_entry(pool.best.iter().nth(2), Some(&ops[2]));
    }

    #[test]
    fn remove_op() {
        let mut pool = PoolInner::new(Address::zero(), 1.into());
        let ops = vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ];

        let mut hashes = vec![];
        for op in ops.iter() {
            hashes.push(pool.add_operation(op.clone()).unwrap());
        }

        assert!(pool.remove_operation_by_hash(hashes[0]).is_some());
        check_map_entry(pool.by_hash.get(&hashes[0]), None);
        check_map_entry(pool.best.iter().next(), Some(&ops[1]));

        assert!(pool.remove_operation_by_hash(hashes[1]).is_some());
        check_map_entry(pool.by_hash.get(&hashes[1]), None);
        check_map_entry(pool.best.iter().next(), Some(&ops[2]));

        assert!(pool.remove_operation_by_hash(hashes[2]).is_some());
        check_map_entry(pool.by_hash.get(&hashes[2]), None);
        check_map_entry(pool.best.iter().next(), None);

        assert!(pool.remove_operation_by_hash(hashes[0]).is_none());
        assert!(pool.remove_operation_by_hash(hashes[1]).is_none());
        assert!(pool.remove_operation_by_hash(hashes[2]).is_none());
    }

    #[test]
    fn too_many_ops() {
        let mut pool = PoolInner::new(Address::zero(), 1.into());
        let addr = Address::random();
        for i in 0..MAX_MEMPOOL_USEROPS_PER_SENDER {
            let op = create_op(addr, i, 1);
            pool.add_operation(op).unwrap();
        }

        let op = create_op(addr, MAX_MEMPOOL_USEROPS_PER_SENDER, 1);
        assert!(pool.add_operation(op).is_err());
    }

    #[test]
    fn address_count() {
        let mut pool = PoolInner::new(Address::zero(), 1.into());
        let sender = Address::random();
        let paymaster = Address::random();
        let factory = Address::random();
        let aggregator = Address::random();

        let mut op = create_op(sender, 0, 1);
        op.uo.paymaster_and_data = Bytes::from(paymaster.as_bytes().to_vec());
        op.uo.init_code = Bytes::from(factory.as_bytes().to_vec());
        op.aggregator = Some(aggregator);

        let count = 5;
        let mut hashes = vec![];
        for i in 0..count {
            let mut op = op.clone();
            op.uo.nonce = i.into();
            hashes.push(pool.add_operation(op).unwrap());
        }

        assert_eq!(pool.address_count(sender), 5);
        assert_eq!(pool.address_count(paymaster), 5);
        assert_eq!(pool.address_count(factory), 5);
        assert_eq!(pool.address_count(aggregator), 5);

        for hash in hashes.iter() {
            assert!(pool.remove_operation_by_hash(*hash).is_some());
        }

        assert_eq!(pool.address_count(sender), 0);
        assert_eq!(pool.address_count(paymaster), 0);
        assert_eq!(pool.address_count(factory), 0);
        assert_eq!(pool.address_count(aggregator), 0);
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

    fn check_map_entry(actual: Option<&OrderedPoolOperation>, expected: Option<&PoolOperation>) {
        match (actual, expected) {
            (Some(actual), Some(expected)) => assert_eq!(*actual.po, *expected),
            (None, None) => (),
            _ => panic!("Expected {expected:?}, got {actual:?}"),
        }
    }
}
