use crate::common::types::{UserOperation, UserOperationId};
use ethers::{
    abi::Address,
    types::{H256, U256},
};
use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, BTreeSet, HashMap, HashSet},
    ops::Deref,
    sync::Arc,
};

const MAX_MEMPOOL_USEROPS_PER_SENDER: usize = 1;

/// Pool of user operations
#[derive(Debug)]
pub struct PoolInner {
    // Address of the entry point this pool targets
    entry_point: Address,
    // Chain ID this pool targets
    chain_id: U256,
    // Operations by hash
    by_hash: HashMap<H256, PoolOperation>,
    // Operations by operation ID
    by_id: HashMap<UserOperationId, PoolOperation>,
    // Best operations, sorted by gas price
    best: BTreeSet<PoolOperation>,
    // Count of operations by sender
    count_by_sender: HashMap<Address, usize>,
    // Submission ID counter
    submission_id: u64,
}

impl PoolInner {
    pub fn new(entry_point: Address, chain_id: U256) -> Self {
        Self {
            by_hash: HashMap::new(),
            by_id: HashMap::new(),
            best: BTreeSet::new(),
            count_by_sender: HashMap::new(),
            entry_point,
            chain_id,
            submission_id: 0,
        }
    }

    pub fn add_operation(&mut self, operation: UserOperation) -> anyhow::Result<H256> {
        // Check for replacement by ID
        if let Some(old_op) = self.by_id.get(&operation.id()) {
            // replace only if higher gas
            if old_op.max_priority_fee_per_gas <= operation.max_priority_fee_per_gas
                && old_op.max_fee_per_gas <= operation.max_fee_per_gas
            {
                self.best.remove(old_op);
                self.by_hash
                    .remove(&old_op.op_hash(self.entry_point, self.chain_id));
            } else {
                anyhow::bail!("Operation with higher gas already in mempool");
            }
        }

        // Check sender count and reject if too many, else increment
        let sender_count = self.count_by_sender.entry(operation.sender).or_insert(0);
        if *sender_count >= MAX_MEMPOOL_USEROPS_PER_SENDER {
            anyhow::bail!(
                "Sender already has {MAX_MEMPOOL_USEROPS_PER_SENDER} operations in mempool, cannot add more"
            );
        }
        *sender_count += 1;

        let pool_op = PoolOperation {
            op: Arc::new(operation),
            submission_id: self.next_submission_id(),
        };
        let hash = pool_op.op_hash(self.entry_point, self.chain_id);
        self.by_hash.insert(hash, pool_op.clone());
        self.by_id.insert(pool_op.id(), pool_op.clone());
        self.best.insert(pool_op);

        Ok(hash)
    }

    pub fn add_operations(
        &mut self,
        operations: impl IntoIterator<Item = UserOperation>,
    ) -> Vec<anyhow::Result<H256>> {
        operations
            .into_iter()
            .map(|op| self.add_operation(op))
            .collect()
    }

    pub fn best_operations(&self, max: usize) -> Vec<Arc<UserOperation>> {
        if max == 0 {
            return vec![];
        }

        // Only add one op per sender
        let mut senders = HashSet::new();

        let mut best = Vec::new();
        for operation in self.best.iter() {
            if senders.contains(&operation.sender) {
                continue;
            }
            best.push(operation.clone().into());
            senders.insert(operation.sender);

            if best.len() == max {
                break;
            }
        }

        best
    }

    pub fn remove_operation_by_hash(&mut self, hash: H256) {
        if let Entry::Occupied(e) = self.by_hash.entry(hash) {
            self.by_id.remove(&e.get().id());
            self.best.remove(e.get());

            if let Entry::Occupied(mut count_entry) = self.count_by_sender.entry(e.get().sender) {
                *count_entry.get_mut() -= 1;
                if *count_entry.get() == 0 {
                    count_entry.remove_entry();
                }
            }

            e.remove_entry();
        }
    }

    pub fn clear(&mut self) {
        self.by_hash.clear();
        self.by_id.clear();
        self.best.clear();
        self.count_by_sender.clear();
    }

    fn next_submission_id(&mut self) -> u64 {
        let id = self.submission_id;
        self.submission_id += 1;
        id
    }
}

// Wrapper type to implement a custom Ord of UserOperations for PoolInner
#[derive(Debug, Clone)]
struct PoolOperation {
    op: Arc<UserOperation>,
    submission_id: u64,
}

impl Deref for PoolOperation {
    type Target = Arc<UserOperation>;

    fn deref(&self) -> &Self::Target {
        &self.op
    }
}

impl Eq for PoolOperation {}

impl Ord for PoolOperation {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort by gas price descending
        // then by id ascending
        other
            .max_fee_per_gas
            .cmp(&self.max_fee_per_gas)
            .then_with(|| self.submission_id.cmp(&other.submission_id))
    }
}

impl PartialOrd for PoolOperation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PoolOperation {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl From<PoolOperation> for Arc<UserOperation> {
    fn from(po: PoolOperation) -> Self {
        po.op
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_single_op() {
        let mut pool = PoolInner::new(Address::zero(), 1.into());
        let op = UserOperation::default();
        let hash = pool.add_operation(op.clone()).unwrap();

        check_map_entry(pool.by_hash.get(&hash), Some(&op));
        check_map_entry(pool.by_id.get(&op.id()), Some(&op));
        check_map_entry(pool.best.iter().next(), Some(&op));
    }

    #[test]
    fn test_add_multiple_ops() {
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
            check_map_entry(pool.by_id.get(&op.id()), Some(op));
        }

        // best should be sorted by gas
        assert_eq!(pool.best.len(), 3);
        check_map_entry(pool.best.iter().next(), Some(&ops[2]));
        check_map_entry(pool.best.iter().nth(1), Some(&ops[1]));
        check_map_entry(pool.best.iter().nth(2), Some(&ops[0]));
    }

    #[test]
    fn test_best_ties() {
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
    fn test_remove_op() {
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

        pool.remove_operation_by_hash(hashes[0]);
        check_map_entry(pool.by_hash.get(&hashes[0]), None);
        check_map_entry(pool.best.iter().next(), Some(&ops[1]));

        pool.remove_operation_by_hash(hashes[1]);
        check_map_entry(pool.by_hash.get(&hashes[1]), None);
        check_map_entry(pool.best.iter().next(), Some(&ops[2]));

        pool.remove_operation_by_hash(hashes[2]);
        check_map_entry(pool.by_hash.get(&hashes[2]), None);
        check_map_entry(pool.best.iter().next(), None);
    }

    fn create_op(sender: Address, nonce: usize, max_fee_per_gas: usize) -> UserOperation {
        UserOperation {
            sender,
            nonce: nonce.into(),
            max_fee_per_gas: max_fee_per_gas.into(),
            ..UserOperation::default()
        }
    }

    fn check_map_entry(actual: Option<&PoolOperation>, expected: Option<&UserOperation>) {
        match (actual, expected) {
            (Some(actual), Some(expected)) => assert_eq!(*actual.op, *expected),
            (None, None) => (),
            _ => panic!("Expected {expected:?}, got {actual:?}"),
        }
    }
}
