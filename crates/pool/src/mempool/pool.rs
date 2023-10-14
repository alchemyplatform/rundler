// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, BTreeSet, HashMap},
    sync::Arc,
};

use anyhow::Context;
use ethers::{
    abi::Address,
    types::{H256, U256},
};
use rundler_types::{Entity, UserOperation, UserOperationId};
use rundler_utils::math;
use tracing::info;

use super::{
    error::{MempoolError, MempoolResult},
    size::SizeTracker,
    PoolConfig, PoolOperation,
};

#[derive(Debug, Clone)]
pub(crate) struct PoolInnerConfig {
    entry_point: Address,
    chain_id: u64,
    max_userops_per_sender: usize,
    max_size_of_pool_bytes: usize,
    min_replacement_fee_increase_percentage: u64,
}

impl From<PoolConfig> for PoolInnerConfig {
    fn from(config: PoolConfig) -> Self {
        Self {
            entry_point: config.entry_point,
            chain_id: config.chain_id,
            max_userops_per_sender: config.max_userops_per_sender,
            max_size_of_pool_bytes: config.max_size_of_pool_bytes,
            min_replacement_fee_increase_percentage: config.min_replacement_fee_increase_percentage,
        }
    }
}

/// Pool of user operations
#[derive(Debug)]
pub(crate) struct PoolInner {
    /// Pool settings
    config: PoolInnerConfig,
    /// Operations by hash
    by_hash: HashMap<H256, OrderedPoolOperation>,
    /// Operations by operation ID
    by_id: HashMap<UserOperationId, OrderedPoolOperation>,
    /// Best operations, sorted by gas price
    best: BTreeSet<OrderedPoolOperation>,
    /// Removed operations, temporarily kept around in case their blocks are
    /// reorged away. Stored along with the block number at which it was
    /// removed.
    mined_at_block_number_by_hash: HashMap<H256, (OrderedPoolOperation, u64)>,
    /// Removed operation hashes sorted by block number, so we can forget them
    /// when enough new blocks have passed.
    mined_hashes_with_block_numbers: BTreeSet<(u64, H256)>,
    /// Count of operations by sender
    count_by_address: HashMap<Address, usize>,
    /// Submission ID counter
    submission_id: u64,
    /// keeps track of the size of the pool in bytes
    pool_size: SizeTracker,
    /// keeps track of the size of the removed cache in bytes
    cache_size: SizeTracker,
}

impl PoolInner {
    pub(crate) fn new(config: PoolInnerConfig) -> Self {
        Self {
            config,
            by_hash: HashMap::new(),
            by_id: HashMap::new(),
            best: BTreeSet::new(),
            mined_at_block_number_by_hash: HashMap::new(),
            mined_hashes_with_block_numbers: BTreeSet::new(),
            count_by_address: HashMap::new(),
            submission_id: 0,
            pool_size: SizeTracker::default(),
            cache_size: SizeTracker::default(),
        }
    }

    /// Returns hash of operation to replace if operation is a replacement
    pub(crate) fn check_replacement(&self, op: &UserOperation) -> MempoolResult<Option<H256>> {
        // Check if operation already known
        if self
            .by_hash
            .contains_key(&op.op_hash(self.config.entry_point, self.config.chain_id))
        {
            return Err(MempoolError::OperationAlreadyKnown);
        }

        if let Some(pool_op) = self.by_id.get(&op.id()) {
            let (replacement_priority_fee, replacement_fee) =
                self.get_min_replacement_fees(pool_op.uo());

            if op.max_priority_fee_per_gas < replacement_priority_fee
                || op.max_fee_per_gas < replacement_fee
            {
                return Err(MempoolError::ReplacementUnderpriced(
                    pool_op.uo().max_priority_fee_per_gas,
                    pool_op.uo().max_fee_per_gas,
                ));
            }

            Ok(Some(
                pool_op
                    .uo()
                    .op_hash(self.config.entry_point, self.config.chain_id),
            ))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn add_operation(&mut self, op: PoolOperation) -> MempoolResult<H256> {
        let ret = self.add_operation_internal(Arc::new(op), None);
        self.update_metrics();
        ret
    }

    pub(crate) fn best_operations(&self) -> impl Iterator<Item = Arc<PoolOperation>> {
        self.best.clone().into_iter().map(|v| v.po)
    }

    pub(crate) fn address_count(&self, address: Address) -> usize {
        self.count_by_address.get(&address).copied().unwrap_or(0)
    }

    pub(crate) fn remove_operation_by_hash(&mut self, hash: H256) -> Option<Arc<PoolOperation>> {
        let ret = self.remove_operation_internal(hash, None);
        self.update_metrics();
        ret
    }

    pub(crate) fn mine_operation(
        &mut self,
        hash: H256,
        block_number: u64,
    ) -> Option<Arc<PoolOperation>> {
        let ret = self.remove_operation_internal(hash, Some(block_number));
        self.update_metrics();
        ret
    }

    pub(crate) fn unmine_operation(&mut self, hash: H256) -> Option<Arc<PoolOperation>> {
        let (op, block_number) = self.mined_at_block_number_by_hash.remove(&hash)?;
        self.mined_hashes_with_block_numbers
            .remove(&(block_number, hash));
        if let Err(error) = self.put_back_unmined_operation(op.clone()) {
            info!("Could not put back unmined operation: {error}");
        };
        self.update_metrics();
        Some(op.po)
    }

    /// Removes all operations using the given entity, returning the hashes of
    /// the removed operations.
    pub(crate) fn remove_entity(&mut self, entity: Entity) -> Vec<H256> {
        let to_remove = self
            .by_hash
            .iter()
            .filter(|(_, uo)| uo.po.contains_entity(&entity))
            .map(|(hash, _)| *hash)
            .collect::<Vec<_>>();
        for &hash in &to_remove {
            self.remove_operation_internal(hash, None);
        }
        self.update_metrics();
        to_remove
    }

    pub(crate) fn forget_mined_operations_before_block(&mut self, block_number: u64) {
        while let Some(&(bn, hash)) = self
            .mined_hashes_with_block_numbers
            .first()
            .filter(|(bn, _)| *bn < block_number)
        {
            if let Some((op, _)) = self.mined_at_block_number_by_hash.remove(&hash) {
                self.cache_size -= op.mem_size();
            }
            self.mined_hashes_with_block_numbers.remove(&(bn, hash));
        }
        self.update_metrics();
    }

    pub(crate) fn clear(&mut self) {
        self.by_hash.clear();
        self.by_id.clear();
        self.best.clear();
        self.mined_at_block_number_by_hash.clear();
        self.mined_hashes_with_block_numbers.clear();
        self.count_by_address.clear();
        self.pool_size = SizeTracker::default();
        self.cache_size = SizeTracker::default();
        self.update_metrics();
    }

    fn enforce_size(&mut self) -> anyhow::Result<Vec<H256>> {
        let mut removed = Vec::new();

        while self.pool_size > self.config.max_size_of_pool_bytes {
            if let Some(worst) = self.best.pop_last() {
                let hash = worst
                    .uo()
                    .op_hash(self.config.entry_point, self.config.chain_id);

                let _ = self
                    .remove_operation_internal(hash, None)
                    .context("should have removed the worst operation")?;

                removed.push(hash);
            }
        }

        Ok(removed)
    }

    fn put_back_unmined_operation(&mut self, op: OrderedPoolOperation) -> MempoolResult<H256> {
        self.add_operation_internal(op.po, Some(op.submission_id))
    }

    fn add_operation_internal(
        &mut self,
        op: Arc<PoolOperation>,
        submission_id: Option<u64>,
    ) -> MempoolResult<H256> {
        // Check if operation already known or replacing an existing operation
        // if replacing, remove the existing operation
        if let Some(hash) = self.check_replacement(&op.uo)? {
            self.remove_operation_by_hash(hash);
        }

        // Check sender count in mempool. If sender has too many operations, must be staked
        if *self.count_by_address.get(&op.uo.sender).unwrap_or(&0)
            >= self.config.max_userops_per_sender
            && !op.account_is_staked
        {
            return Err(MempoolError::MaxOperationsReached(
                self.config.max_userops_per_sender,
                op.uo.sender,
            ));
        }

        let pool_op = OrderedPoolOperation {
            po: op,
            submission_id: submission_id.unwrap_or_else(|| self.next_submission_id()),
        };

        // update counts
        for e in pool_op.po.entities() {
            *self.count_by_address.entry(e.address).or_insert(0) += 1;
        }

        // create and insert ordered operation
        let hash = pool_op
            .uo()
            .op_hash(self.config.entry_point, self.config.chain_id);
        self.pool_size += pool_op.mem_size();
        self.by_hash.insert(hash, pool_op.clone());
        self.by_id.insert(pool_op.uo().id(), pool_op.clone());
        self.best.insert(pool_op);

        let removed = self
            .enforce_size()
            .context("should have succeeded in resizing the pool")?;

        if removed.contains(&hash) {
            Err(MempoolError::DiscardedOnInsert)?;
        }

        Ok(hash)
    }

    fn remove_operation_internal(
        &mut self,
        hash: H256,
        block_number: Option<u64>,
    ) -> Option<Arc<PoolOperation>> {
        let op = self.by_hash.remove(&hash)?;
        self.by_id.remove(&op.uo().id());
        self.best.remove(&op);
        if let Some(block_number) = block_number {
            self.cache_size += op.mem_size();
            self.mined_at_block_number_by_hash
                .insert(hash, (op.clone(), block_number));
            self.mined_hashes_with_block_numbers
                .insert((block_number, hash));
        }
        for e in op.po.entities() {
            self.decrement_address_count(e.address);
        }

        self.pool_size -= op.mem_size();
        Some(op.po)
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

    fn get_min_replacement_fees(&self, op: &UserOperation) -> (U256, U256) {
        let replacement_priority_fee = math::increase_by_percent(
            op.max_priority_fee_per_gas,
            self.config.min_replacement_fee_increase_percentage,
        );
        let replacement_fee = math::increase_by_percent(
            op.max_fee_per_gas,
            self.config.min_replacement_fee_increase_percentage,
        );
        (replacement_priority_fee, replacement_fee)
    }

    fn update_metrics(&self) {
        PoolMetrics::set_pool_metrics(
            self.by_hash.len(),
            self.pool_size.0,
            self.config.entry_point,
        );
        PoolMetrics::set_cache_metrics(
            self.mined_hashes_with_block_numbers.len(),
            self.cache_size.0,
            self.config.entry_point,
        );
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

    fn mem_size(&self) -> usize {
        std::mem::size_of::<OrderedPoolOperation>() + self.po.mem_size()
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

struct PoolMetrics {}

impl PoolMetrics {
    fn set_pool_metrics(num_ops: usize, size_bytes: isize, entry_point: Address) {
        metrics::gauge!("op_pool_num_ops_in_pool", num_ops as f64, "entrypoint_addr" => entry_point.to_string());
        metrics::gauge!("op_pool_size_bytes", size_bytes as f64, "entrypoint_addr" => entry_point.to_string());
    }
    fn set_cache_metrics(num_ops: usize, size_bytes: isize, entry_point: Address) {
        metrics::gauge!("op_pool_num_ops_in_cache", num_ops as f64, "entrypoint_addr" => entry_point.to_string());
        metrics::gauge!("op_pool_cache_size_bytes", size_bytes as f64, "entrypoint_addr" => entry_point.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_single_op() {
        let mut pool = PoolInner::new(conf());
        let op = create_op(Address::random(), 0, 1);
        let hash = pool.add_operation(op.clone()).unwrap();

        check_map_entry(pool.by_hash.get(&hash), Some(&op));
        check_map_entry(pool.by_id.get(&op.uo.id()), Some(&op));
        check_map_entry(pool.best.iter().next(), Some(&op));
    }

    #[test]
    fn add_multiple_ops() {
        let mut pool = PoolInner::new(conf());
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
        let mut pool = PoolInner::new(conf());
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
        let mut pool = PoolInner::new(conf());
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
    fn remove_account() {
        let mut pool = PoolInner::new(conf());
        let account = Address::random();
        let ops = vec![
            create_op(account, 0, 3),
            create_op(account, 1, 2),
            create_op(account, 2, 1),
        ];
        for mut op in ops.into_iter() {
            op.aggregator = Some(account);
            pool.add_operation(op.clone()).unwrap();
        }
        assert_eq!(pool.by_hash.len(), 3);

        pool.remove_entity(Entity::account(account));
        assert!(pool.by_hash.is_empty());
        assert!(pool.by_id.is_empty());
        assert!(pool.best.is_empty());
    }

    #[test]
    fn remove_aggregator() {
        let mut pool = PoolInner::new(conf());
        let agg = Address::random();
        let ops = vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ];
        for mut op in ops.into_iter() {
            op.aggregator = Some(agg);
            pool.add_operation(op.clone()).unwrap();
        }
        assert_eq!(pool.by_hash.len(), 3);

        pool.remove_entity(Entity::aggregator(agg));
        assert!(pool.by_hash.is_empty());
        assert!(pool.by_id.is_empty());
        assert!(pool.best.is_empty());
    }

    #[test]
    fn remove_paymaster() {
        let mut pool = PoolInner::new(conf());
        let paymaster = Address::random();
        let ops = vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ];
        for mut op in ops.into_iter() {
            op.uo.paymaster_and_data = paymaster.as_bytes().to_vec().into();
            pool.add_operation(op.clone()).unwrap();
        }
        assert_eq!(pool.by_hash.len(), 3);

        pool.remove_entity(Entity::paymaster(paymaster));
        assert!(pool.by_hash.is_empty());
        assert!(pool.by_id.is_empty());
        assert!(pool.best.is_empty());
    }

    #[test]
    fn too_many_ops() {
        let args = conf();
        let mut pool = PoolInner::new(args.clone());
        let addr = Address::random();
        for i in 0..args.max_userops_per_sender {
            let op = create_op(addr, i, 1);
            pool.add_operation(op).unwrap();
        }

        let op = create_op(addr, args.max_userops_per_sender, 1);
        assert!(pool.add_operation(op).is_err());
    }

    #[test]
    fn address_count() {
        let mut pool = PoolInner::new(conf());
        let sender = Address::random();
        let paymaster = Address::random();
        let factory = Address::random();
        let aggregator = Address::random();

        let mut op = create_op(sender, 0, 1);
        op.uo.paymaster_and_data = paymaster.as_bytes().to_vec().into();
        op.uo.init_code = factory.as_bytes().to_vec().into();
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

    #[test]
    fn pool_full_new_replaces_worst() {
        let args = conf();
        let mut pool = PoolInner::new(args.clone());
        for i in 0..20 {
            let op = create_op(Address::random(), i, i + 1);
            pool.add_operation(op).unwrap();
        }

        // on greater gas, new op should win
        let op = create_op(Address::random(), args.max_size_of_pool_bytes, 2);
        let result = pool.add_operation(op);
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn pool_full_worst_remains() {
        let args = conf();
        let mut pool = PoolInner::new(args.clone());
        for i in 0..20 {
            let op = create_op(Address::random(), i, i + 1);
            pool.add_operation(op).unwrap();
        }

        let op = create_op(Address::random(), args.max_userops_per_sender, 1);
        assert!(pool.add_operation(op).is_err());

        // on equal gas, worst should remain because it came first
        let op = create_op(Address::random(), args.max_userops_per_sender, 2);
        let result = pool.add_operation(op);
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn replace_op_underpriced() {
        let mut pool = PoolInner::new(conf());
        let sender = Address::random();
        let mut po1 = create_op(sender, 0, 100);
        po1.uo.max_priority_fee_per_gas = 100.into();
        let _ = pool.add_operation(po1.clone()).unwrap();

        let mut po2 = create_op(sender, 0, 101);
        po2.uo.max_priority_fee_per_gas = 101.into();
        let res = pool.add_operation(po2);
        assert!(res.is_err());
        match res.err().unwrap() {
            MempoolError::ReplacementUnderpriced(a, b) => {
                assert_eq!(a, 100.into());
                assert_eq!(b, 100.into());
            }
            _ => panic!("wrong error"),
        }

        assert_eq!(pool.address_count(sender), 1);
        assert_eq!(
            pool.pool_size,
            OrderedPoolOperation {
                po: Arc::new(po1),
                submission_id: 0
            }
            .mem_size()
        );
    }

    #[test]
    fn replace_op() {
        let mut pool = PoolInner::new(conf());
        let sender = Address::random();
        let paymaster1 = Address::random();
        let mut po1 = create_op(sender, 0, 10);
        po1.uo.max_priority_fee_per_gas = 10.into();
        po1.uo.paymaster_and_data = paymaster1.as_bytes().to_vec().into();
        let _ = pool.add_operation(po1).unwrap();
        assert_eq!(pool.address_count(paymaster1), 1);

        let paymaster2 = Address::random();
        let mut po2 = create_op(sender, 0, 11);
        po2.uo.max_priority_fee_per_gas = 11.into();
        po2.uo.paymaster_and_data = paymaster2.as_bytes().to_vec().into();
        let _ = pool.add_operation(po2.clone()).unwrap();

        assert_eq!(pool.address_count(sender), 1);
        assert_eq!(pool.address_count(paymaster1), 0);
        assert_eq!(pool.address_count(paymaster2), 1);
        assert_eq!(
            pool.pool_size,
            OrderedPoolOperation {
                po: Arc::new(po2),
                submission_id: 0
            }
            .mem_size()
        );
    }

    #[test]
    fn test_already_known() {
        let mut pool = PoolInner::new(conf());
        let sender = Address::random();
        let mut po1 = create_op(sender, 0, 10);
        po1.uo.max_priority_fee_per_gas = 10.into();
        let _ = pool.add_operation(po1.clone()).unwrap();

        let res = pool.add_operation(po1);
        assert!(res.is_err());
        match res.err().unwrap() {
            MempoolError::OperationAlreadyKnown => (),
            _ => panic!("wrong error"),
        }
    }

    fn conf() -> PoolInnerConfig {
        PoolInnerConfig {
            entry_point: Address::random(),
            chain_id: 1,
            max_userops_per_sender: 16,
            min_replacement_fee_increase_percentage: 10,
            max_size_of_pool_bytes: 20 * mem_size_of_ordered_pool_op(),
        }
    }

    fn mem_size_of_ordered_pool_op() -> usize {
        OrderedPoolOperation {
            po: Arc::new(create_op(Address::random(), 1, 1)),
            submission_id: 1,
        }
        .mem_size()
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
