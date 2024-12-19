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
    collections::{hash_map::Entry, BTreeSet, HashMap, HashSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Address, B256};
use anyhow::Context;
use metrics::{Gauge, Histogram};
use metrics_derive::Metrics;
use parking_lot::RwLock;
use rundler_provider::DAGasOracleSync;
use rundler_sim::FeeUpdate;
use rundler_types::{
    chain::ChainSpec,
    da::DAGasBlockData,
    pool::{MempoolError, PoolOperation},
    Entity, EntityType, Timestamp, UserOperation, UserOperationId, UserOperationVariant,
};
use rundler_utils::{emit::WithEntryPoint, math};
use tokio::sync::broadcast;
use tracing::{info, warn};

use super::{entity_tracker::EntityCounter, size::SizeTracker, MempoolResult, PoolConfig};
use crate::{chain::MinedOp, emit::OpRemovalReason, PoolEvent};

#[derive(Debug, Clone)]
pub(crate) struct PoolInnerConfig {
    chain_spec: ChainSpec,
    entry_point: Address,
    max_size_of_pool_bytes: usize,
    min_replacement_fee_increase_percentage: u32,
    throttled_entity_mempool_count: u64,
    throttled_entity_live_blocks: u64,
    da_gas_tracking_enabled: bool,
}

impl From<PoolConfig> for PoolInnerConfig {
    fn from(config: PoolConfig) -> Self {
        Self {
            chain_spec: config.chain_spec,
            entry_point: config.entry_point,
            max_size_of_pool_bytes: config.max_size_of_pool_bytes,
            min_replacement_fee_increase_percentage: config.min_replacement_fee_increase_percentage,
            throttled_entity_mempool_count: config.throttled_entity_mempool_count,
            throttled_entity_live_blocks: config.throttled_entity_live_blocks,
            da_gas_tracking_enabled: config.da_gas_tracking_enabled,
        }
    }
}

/// Pool of user operations
#[derive(Debug)]
pub(crate) struct PoolInner<D> {
    /// Pool settings
    config: PoolInnerConfig,
    /// DA Gas Oracle
    da_gas_oracle: Option<D>,
    /// Operations by hash
    by_hash: HashMap<B256, Arc<OrderedPoolOperation>>,
    /// Operations by operation ID
    by_id: HashMap<UserOperationId, Arc<OrderedPoolOperation>>,
    /// Best operations, sorted by gas price
    best: BTreeSet<Arc<OrderedPoolOperation>>,
    /// Time to mine info
    time_to_mine: HashMap<B256, TimeToMineInfo>,
    /// Removed operations, temporarily kept around in case their blocks are
    /// reorged away. Stored along with the block number at which it was
    /// removed.
    mined_at_block_number_by_hash: HashMap<B256, (Arc<OrderedPoolOperation>, u64)>,
    /// Removed operation hashes sorted by block number, so we can forget them
    /// when enough new blocks have passed.
    mined_hashes_with_block_numbers: BTreeSet<(u64, B256)>,
    /// Count of operations by entity address
    count_by_address: HashMap<Address, EntityCounter>,
    /// Submission ID counter
    submission_id: u64,
    /// keeps track of the size of the pool in bytes
    pool_size: SizeTracker,
    /// keeps track of the size of the removed cache in bytes
    cache_size: SizeTracker,
    /// The time of the previous block
    prev_sys_block_time: Duration,
    /// The number of the previous block
    prev_block_number: u64,
    /// The metrics of pool.
    metrics: PoolMetrics,
    /// Event sender
    event_sender: broadcast::Sender<WithEntryPoint<PoolEvent>>,
}

impl<D> PoolInner<D>
where
    D: DAGasOracleSync,
{
    pub(crate) fn new(
        config: PoolInnerConfig,
        da_gas_oracle: Option<D>,
        event_sender: broadcast::Sender<WithEntryPoint<PoolEvent>>,
    ) -> Self {
        let entry_point = config.entry_point.to_string();
        Self {
            config,
            da_gas_oracle,
            by_hash: HashMap::new(),
            by_id: HashMap::new(),
            best: BTreeSet::new(),
            time_to_mine: HashMap::new(),
            mined_at_block_number_by_hash: HashMap::new(),
            mined_hashes_with_block_numbers: BTreeSet::new(),
            count_by_address: HashMap::new(),
            submission_id: 0,
            pool_size: SizeTracker::default(),
            cache_size: SizeTracker::default(),
            prev_sys_block_time: Duration::default(),
            prev_block_number: 0,
            metrics: PoolMetrics::new_with_labels(&[("entry_point", entry_point)]),
            event_sender,
        }
    }

    fn emit(&self, event: PoolEvent) {
        let _ = self.event_sender.send(WithEntryPoint {
            entry_point: self.config.entry_point,
            event,
        });
    }

    /// Returns hash of operation to replace if operation is a replacement
    pub(crate) fn check_replacement(
        &self,
        op: &UserOperationVariant,
    ) -> MempoolResult<Option<B256>> {
        // Check if operation already known
        if self
            .by_hash
            .contains_key(&op.hash(self.config.entry_point, self.config.chain_spec.id))
        {
            return Err(MempoolError::OperationAlreadyKnown);
        }

        if let Some(pool_op) = self.by_id.get(&op.id()) {
            let (replacement_priority_fee, replacement_fee) =
                self.get_min_replacement_fees(pool_op.uo());

            if op.max_priority_fee_per_gas() < replacement_priority_fee
                || op.max_fee_per_gas() < replacement_fee
            {
                return Err(MempoolError::ReplacementUnderpriced(
                    pool_op.uo().max_priority_fee_per_gas(),
                    pool_op.uo().max_fee_per_gas(),
                ));
            }

            Ok(Some(
                pool_op
                    .uo()
                    .hash(self.config.entry_point, self.config.chain_spec.id),
            ))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn add_operation(
        &mut self,
        op: PoolOperation,
        required_pvg: u128,
    ) -> MempoolResult<B256> {
        // only eligibility criteria is required PVG which is enabled when da_gas_tracking is enabled
        let is_eligible = if self.config.da_gas_tracking_enabled && self.da_gas_oracle.is_some() {
            if op.uo.pre_verification_gas() < required_pvg {
                self.emit(PoolEvent::UpdatedDAData {
                    op_hash: op
                        .uo
                        .hash(self.config.entry_point, self.config.chain_spec.id),
                    eligible: false,
                    required_pvg,
                    actual_pvg: op.uo.pre_verification_gas(),
                });
                false
            } else {
                true
            }
        } else {
            true
        };

        // only eligibility requirement is if the op has required pvg
        let pool_op = Arc::new(OrderedPoolOperation::new(
            Arc::new(op),
            self.next_submission_id(),
            is_eligible,
        ));

        let hash = self.add_operation_internal(pool_op)?;
        Ok(hash)
    }

    pub(crate) fn best_operations(&self) -> impl Iterator<Item = Arc<PoolOperation>> + '_ {
        self.best.iter().filter_map(|p| {
            if p.eligible() {
                Some(p.po.clone())
            } else {
                None
            }
        })
    }

    /// Does maintenance on the pool.
    ///
    /// 1) Removes all operations using the given entity, returning the hashes of the removed operations.
    /// 2) Updates time to mine stats for all operations in the pool.
    ///
    /// NOTE: This method is O(n) where n is the number of operations in the pool.
    /// It should be called sparingly (e.g. when a block is mined).
    pub(crate) fn do_maintenance(
        &mut self,
        block_number: u64,
        block_timestamp: Timestamp,
        block_da_data: Option<&DAGasBlockData>,
        gas_fees: FeeUpdate,
    ) {
        let sys_block_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch");

        let block_delta_time = sys_block_time.saturating_sub(self.prev_sys_block_time);
        let block_delta_height = block_number.saturating_sub(self.prev_block_number);
        let mut expired = Vec::new();
        let mut num_candidates = 0;
        let mut events = vec![];

        for (hash, op) in &mut self.by_hash {
            if op.po.valid_time_range.valid_until < block_timestamp {
                events.push(PoolEvent::RemovedOp {
                    op_hash: *hash,
                    reason: OpRemovalReason::Expired {
                        valid_until: op.po.valid_time_range.valid_until,
                    },
                });
                expired.push(*hash);
                continue;
            }

            if self.da_gas_oracle.is_some() && block_da_data.is_some() {
                let da_gas_oracle = self.da_gas_oracle.as_ref().unwrap();
                let block_da_data = block_da_data.unwrap();

                let required_da_gas = da_gas_oracle.calc_da_gas_sync(
                    &op.po.da_gas_data,
                    block_da_data,
                    op.uo().gas_price(gas_fees.base_fee),
                );

                let required_pvg = op.uo().required_pre_verification_gas(
                    &self.config.chain_spec,
                    1,
                    required_da_gas,
                );
                let actual_pvg = op.uo().pre_verification_gas();

                if actual_pvg < required_pvg {
                    if op.eligible() {
                        op.set_ineligible();
                        events.push(PoolEvent::UpdatedDAData {
                            op_hash: *hash,
                            eligible: false,
                            required_pvg,
                            actual_pvg,
                        });
                    }
                    continue;
                } else if !op.eligible() {
                    op.set_eligible();
                    events.push(PoolEvent::UpdatedDAData {
                        op_hash: *hash,
                        eligible: true,
                        required_pvg,
                        actual_pvg,
                    });
                }
            }

            if op.uo().max_fee_per_gas() < gas_fees.uo_fees.max_fee_per_gas
                || op.uo().max_priority_fee_per_gas() < gas_fees.uo_fees.max_priority_fee_per_gas
            {
                // don't mark as ineligible, but also not a candidate
                continue;
            }

            // Op is a candidate, update time to mine and candidate count
            if let Some(ttm) = self.time_to_mine.get_mut(hash) {
                ttm.increase(block_delta_time, block_delta_height);
            }
            num_candidates += 1;
        }

        for hash in expired {
            self.remove_operation_by_hash(hash);
        }
        for event in events {
            self.emit(event);
        }

        self.metrics.num_candidates.set(num_candidates as f64);
        self.prev_block_number = block_number;
        self.prev_sys_block_time = sys_block_time;
        self.update_metrics();
    }

    pub(crate) fn address_count(&self, address: &Address) -> usize {
        if let Some(entity) = self.count_by_address.get(address) {
            return entity.total();
        };

        0
    }

    pub(crate) fn get_operation_by_hash(&self, hash: B256) -> Option<Arc<PoolOperation>> {
        self.by_hash.get(&hash).map(|o| o.po.clone())
    }

    pub(crate) fn get_operation_by_id(&self, id: &UserOperationId) -> Option<Arc<PoolOperation>> {
        self.by_id.get(id).map(|o| o.po.clone())
    }

    pub(crate) fn remove_operation_by_hash(&mut self, hash: B256) -> Option<Arc<PoolOperation>> {
        self.remove_operation_internal(hash, None)
    }

    // STO-040
    pub(crate) fn check_multiple_roles_violation(
        &self,
        uo: &UserOperationVariant,
    ) -> MempoolResult<()> {
        if let Some(ec) = self.count_by_address.get(&uo.sender()) {
            if ec.includes_non_sender() {
                return Err(MempoolError::SenderAddressUsedAsAlternateEntity(
                    uo.sender(),
                ));
            }
        }

        for e in uo.entities() {
            match e.kind {
                EntityType::Factory | EntityType::Paymaster | EntityType::Aggregator => {
                    if let Some(ec) = self.count_by_address.get(&e.address) {
                        if ec.sender().gt(&0) {
                            return Err(MempoolError::MultipleRolesViolation(e));
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    // STO-041
    pub(crate) fn check_associated_storage(
        &self,
        accessed_storage: &HashSet<Address>,
        uo: &UserOperationVariant,
    ) -> MempoolResult<()> {
        for storage_address in accessed_storage {
            if let Some(ec) = self.count_by_address.get(storage_address) {
                if ec.sender().gt(&0) && storage_address.ne(&uo.sender()) {
                    // Reject UO if the sender is also an entity in another UO in the mempool
                    for entity in uo.entities() {
                        if storage_address.eq(&entity.address) {
                            return Err(MempoolError::AssociatedStorageIsAlternateSender);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) fn mine_operation(
        &mut self,
        mined_op: &MinedOp,
        block_number: u64,
    ) -> Option<Arc<PoolOperation>> {
        let tx_in_pool = self.by_id.get(&mined_op.id())?;

        // TODO(danc): there is a bug here with replacements.
        // UO1 is replaced by UO2, they both have the same ID.
        // UO1 was bundled before UO2 replaced it, and eventually UO1 gets mined.
        // UO2 should be removed from the pool, but since the hashes don't match, it will
        // stay in the pool forever as `remove_operation_internal` is hash based.
        // Time to mine will also fail because UO1's hash was removed from the pool.

        if let Some(time_to_mine) = self.time_to_mine.get(&mined_op.hash) {
            self.metrics
                .time_to_mine
                .record(time_to_mine.candidate_for_time.as_secs_f64());
            self.metrics
                .blocks_to_mine
                .record(time_to_mine.candidate_for_blocks as f64);
        } else {
            warn!("Could not find time to mine for {:?}", mined_op.hash);
        }

        let hash = tx_in_pool
            .uo()
            .hash(mined_op.entry_point, self.config.chain_spec.id);

        self.remove_operation_internal(hash, Some(block_number))
    }

    pub(crate) fn unmine_operation(&mut self, mined_op: &MinedOp) -> Option<Arc<PoolOperation>> {
        let hash = mined_op.hash;
        let (op, block_number) = self.mined_at_block_number_by_hash.remove(&hash)?;
        self.mined_hashes_with_block_numbers
            .remove(&(block_number, hash));

        if let Err(error) = self.add_operation_internal(op.clone()) {
            info!("Could not put back unmined operation: {error}");
        };
        Some(op.po.clone())
    }

    /// Remove all but THROTTLED_ENTITY_MEMPOOL_COUNT operations that are within THROTTLED_ENTITY_LIVE_BLOCKS of head
    /// using the given entity, returning the hashes of the removed operations.
    pub(crate) fn throttle_entity(
        &mut self,
        entity: Entity,
        current_block_number: u64,
    ) -> Vec<B256> {
        let mut uos_kept = self.config.throttled_entity_mempool_count;
        let to_remove = self
            .best
            .iter()
            .filter(|o| {
                // We want to remove ops that use the throttled entity and are older than THROTTLED_ENTITY_LIVE_BLOCKS behind head, or if we already have kept THROTTLED_ENTITY_MEMPOOL_COUNT ops
                if o.po.contains_entity(&entity) {
                    if o.po.sim_block_number + self.config.throttled_entity_live_blocks
                        < current_block_number
                        || uos_kept == 0
                    {
                        return true;
                    }
                    uos_kept = uos_kept.saturating_sub(1);
                }
                false
            })
            .map(|o| {
                o.po.uo
                    .hash(self.config.entry_point, self.config.chain_spec.id)
            })
            .collect::<Vec<_>>();
        for &hash in &to_remove {
            self.remove_operation_internal(hash, None);
        }
        to_remove
    }

    /// Removes all operations using the given entity, returning the hashes of
    /// the removed operations.
    pub(crate) fn remove_entity(&mut self, entity: Entity) -> Vec<B256> {
        let to_remove = self
            .by_hash
            .iter()
            .filter(|(_, uo)| uo.po.contains_entity(&entity))
            .map(|(hash, _)| *hash)
            .collect::<Vec<_>>();
        for &hash in &to_remove {
            self.remove_operation_internal(hash, None);
        }
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
    }

    pub(crate) fn clear(&mut self) {
        self.by_hash.clear();
        self.by_id.clear();
        self.best.clear();
        self.time_to_mine.clear();
        self.mined_at_block_number_by_hash.clear();
        self.mined_hashes_with_block_numbers.clear();
        self.count_by_address.clear();
        self.pool_size = SizeTracker::default();
        self.cache_size = SizeTracker::default();
        self.update_metrics();
    }

    fn enforce_size(&mut self) -> anyhow::Result<Vec<B256>> {
        let mut removed = Vec::new();

        while self.pool_size > self.config.max_size_of_pool_bytes {
            if let Some(worst) = self.best.pop_last() {
                let hash = worst
                    .uo()
                    .hash(self.config.entry_point, self.config.chain_spec.id);

                let _ = self
                    .remove_operation_internal(hash, None)
                    .context("should have removed the worst operation")?;

                removed.push(hash);
            }
        }

        Ok(removed)
    }

    fn add_operation_internal(
        &mut self,
        pool_op: Arc<OrderedPoolOperation>,
    ) -> MempoolResult<B256> {
        // Check if operation already known or replacing an existing operation
        // if replacing, remove the existing operation
        if let Some(hash) = self.check_replacement(pool_op.uo())? {
            self.remove_operation_by_hash(hash);
        }

        // update counts
        for e in pool_op.po.entities() {
            self.count_by_address
                .entry(e.address)
                .or_default()
                .increment_entity_count(&e.kind);
        }

        // create and insert ordered operation
        let hash = pool_op
            .uo()
            .hash(self.config.entry_point, self.config.chain_spec.id);
        self.pool_size += pool_op.mem_size();
        self.by_hash.insert(hash, pool_op.clone());
        self.by_id.insert(pool_op.uo().id(), pool_op.clone());
        self.best.insert(pool_op);
        self.time_to_mine.insert(hash, TimeToMineInfo::new());

        let removed = self
            .enforce_size()
            .context("should have succeeded in resizing the pool")?;
        for hash in &removed {
            self.emit(PoolEvent::RemovedOp {
                op_hash: *hash,
                reason: OpRemovalReason::PoolSizeExceeded,
            });
        }

        if removed.contains(&hash) {
            Err(MempoolError::DiscardedOnInsert)?;
        }

        self.update_metrics();
        Ok(hash)
    }

    fn remove_operation_internal(
        &mut self,
        hash: B256,
        block_number: Option<u64>,
    ) -> Option<Arc<PoolOperation>> {
        let op = self.by_hash.remove(&hash)?;
        let id = &op.po.uo.id();
        self.by_id.remove(id);
        self.best.remove(&op);
        self.time_to_mine.remove(&hash);

        if let Some(block_number) = block_number {
            self.cache_size += op.mem_size();
            self.mined_at_block_number_by_hash
                .insert(hash, (op.clone(), block_number));
            self.mined_hashes_with_block_numbers
                .insert((block_number, hash));
        }

        for e in op.po.entities() {
            self.decrement_address_count(e.address, &e.kind);
        }

        self.pool_size -= op.mem_size();
        self.update_metrics();
        Some(op.po.clone())
    }

    fn decrement_address_count(&mut self, address: Address, entity: &EntityType) {
        if let Entry::Occupied(mut count_entry) = self.count_by_address.entry(address) {
            count_entry.get_mut().decrement_entity_count(entity);
            if count_entry.get().total() == 0 {
                count_entry.remove_entry();
            }
        }
    }

    fn next_submission_id(&mut self) -> u64 {
        let id = self.submission_id;
        self.submission_id += 1;
        id
    }

    fn get_min_replacement_fees(&self, op: &UserOperationVariant) -> (u128, u128) {
        let replacement_priority_fee = math::increase_by_percent(
            op.max_priority_fee_per_gas(),
            self.config.min_replacement_fee_increase_percentage,
        );
        let replacement_fee = math::increase_by_percent(
            op.max_fee_per_gas(),
            self.config.min_replacement_fee_increase_percentage,
        );
        (replacement_priority_fee, replacement_fee)
    }

    fn update_metrics(&self) {
        self.metrics.num_ops_in_pool.set(self.by_hash.len() as f64);
        self.metrics.size_bytes.set(self.pool_size.0 as f64);

        self.metrics
            .num_ops_in_cache
            .set(self.mined_hashes_with_block_numbers.len() as f64);
        self.metrics.cache_size_bytes.set(self.cache_size.0 as f64);
    }
}

/// Wrapper around PoolOperation that adds a submission ID to implement
/// a custom ordering for the best operations
#[derive(Debug)]
struct OrderedPoolOperation {
    po: Arc<PoolOperation>,
    submission_id: u64,
    eligible: RwLock<bool>,
}

impl OrderedPoolOperation {
    fn new(po: Arc<PoolOperation>, submission_id: u64, eligible: bool) -> Self {
        Self {
            po,
            submission_id,
            eligible: RwLock::new(eligible),
        }
    }

    fn uo(&self) -> &UserOperationVariant {
        &self.po.uo
    }

    fn mem_size(&self) -> usize {
        std::mem::size_of::<Self>() + self.po.mem_size()
    }

    fn eligible(&self) -> bool {
        *self.eligible.read()
    }

    fn set_eligible(&self) {
        *self.eligible.write() = true;
    }

    fn set_ineligible(&self) {
        *self.eligible.write() = false;
    }
}

impl Eq for OrderedPoolOperation {}

impl Ord for OrderedPoolOperation {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort by gas price descending then by id ascending
        other
            .uo()
            .max_fee_per_gas()
            .cmp(&self.uo().max_fee_per_gas())
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

#[derive(Debug, Clone)]
struct TimeToMineInfo {
    candidate_for_blocks: u64,
    candidate_for_time: Duration,
}

impl TimeToMineInfo {
    fn new() -> Self {
        Self {
            candidate_for_blocks: 0,
            candidate_for_time: Duration::default(),
        }
    }

    fn increase(&mut self, block_delta_time: Duration, block_delta_height: u64) {
        self.candidate_for_blocks += block_delta_height;
        self.candidate_for_time += block_delta_time;
    }
}

#[derive(Metrics)]
#[metrics(scope = "op_pool")]
struct PoolMetrics {
    #[metric(describe = "the number of ops in mempool.")]
    num_ops_in_pool: Gauge,
    #[metric(describe = "the size of mempool in bytes.")]
    size_bytes: Gauge,
    #[metric(describe = "the number of ops in mempool cache (mined but not persistent).")]
    num_ops_in_cache: Gauge,
    #[metric(describe = "the size of mempool cache in bytes.")]
    cache_size_bytes: Gauge,
    #[metric(describe = "the number of candidates.")]
    num_candidates: Gauge,
    #[metric(describe = "the duration distribution of a bundle mined.")]
    time_to_mine: Histogram,
    #[metric(describe = "the duration distribution of a blocked mined.")]
    blocks_to_mine: Histogram,
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;
    use rundler_provider::MockDAGasOracleSync;
    use rundler_types::{
        v0_6::UserOperation, EntityInfo, EntityInfos, UserOperation as UserOperationTrait,
        ValidTimeRange,
    };

    use super::*;

    #[test]
    fn add_single_op() {
        let mut pool = pool();
        let op = create_op(Address::random(), 0, 1);
        let hash = pool.add_operation(op.clone(), 0).unwrap();

        check_map_entry(pool.by_hash.get(&hash), Some(&op));
        check_map_entry(pool.by_id.get(&op.uo.id()), Some(&op));
        check_map_entry(pool.best.iter().next(), Some(&op));
    }

    #[test]
    fn test_get_by_hash() {
        let mut pool = pool();
        let op = create_op(Address::random(), 0, 1);
        let hash = pool.add_operation(op.clone(), 0).unwrap();

        let get_op = pool.get_operation_by_hash(hash).unwrap();
        assert_eq!(op, *get_op);

        assert_eq!(pool.get_operation_by_hash(B256::random()), None);
    }

    #[test]
    fn test_get_by_id() {
        let mut pool = pool();
        let op = create_op(Address::random(), 0, 1);
        pool.add_operation(op.clone(), 0).unwrap();
        let id = op.uo.id();

        let get_op = pool.get_operation_by_id(&id).unwrap();
        assert_eq!(op, *get_op);

        let bad_id = UserOperationId {
            sender: Address::random(),
            nonce: U256::ZERO,
        };

        assert_eq!(pool.get_operation_by_id(&bad_id), None);
    }

    #[test]
    fn add_multiple_ops() {
        let mut pool = pool();
        let ops = vec![
            create_op(Address::random(), 0, 1),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 3),
        ];

        let mut hashes = vec![];
        for op in ops.iter() {
            hashes.push(pool.add_operation(op.clone(), 0).unwrap());
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
        let mut pool = pool();
        let ops = vec![
            create_op(Address::random(), 0, 1),
            create_op(Address::random(), 0, 1),
            create_op(Address::random(), 0, 1),
        ];

        let mut hashes = vec![];
        for op in ops.iter() {
            hashes.push(pool.add_operation(op.clone(), 0).unwrap());
        }

        // best should be sorted by gas, then by submission id
        assert_eq!(pool.best.len(), 3);
        check_map_entry(pool.best.iter().next(), Some(&ops[0]));
        check_map_entry(pool.best.iter().nth(1), Some(&ops[1]));
        check_map_entry(pool.best.iter().nth(2), Some(&ops[2]));
    }

    #[test]
    fn remove_op() {
        let mut pool = pool();
        let ops = vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ];

        let mut hashes = vec![];
        for op in ops.iter() {
            hashes.push(pool.add_operation(op.clone(), 0).unwrap());
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
        let mut pool = pool();
        let account = Address::random();
        let ops = vec![
            create_op(account, 0, 3),
            create_op(account, 1, 2),
            create_op(account, 2, 1),
        ];
        for mut op in ops.into_iter() {
            op.aggregator = Some(account);
            pool.add_operation(op.clone(), 0).unwrap();
        }
        assert_eq!(pool.by_hash.len(), 3);

        pool.remove_entity(Entity::account(account));
        assert!(pool.by_hash.is_empty());
        assert!(pool.by_id.is_empty());
        assert!(pool.best.is_empty());
    }

    #[test]
    fn mine_op() {
        let mut pool = pool();
        let sender = Address::random();
        let nonce = 0;

        let op = create_op(sender, nonce, 1);

        let hash = op
            .uo
            .hash(pool.config.entry_point, pool.config.chain_spec.id);

        pool.add_operation(op, 0).unwrap();

        let mined_op = MinedOp {
            paymaster: None,
            actual_gas_cost: U256::ZERO,
            hash,
            entry_point: pool.config.entry_point,
            sender,
            nonce: U256::from(nonce),
        };

        pool.mine_operation(&mined_op, 1);

        assert!(pool.by_hash.is_empty());
        assert!(pool.by_id.is_empty());
        assert!(pool.best.is_empty());
    }

    #[test]
    fn mine_op_with_replacement() {
        let mut pool = pool();
        let sender = Address::random();
        let nonce = 0;

        let op = create_op(sender, nonce, 1);
        let op_2 = create_op(sender, nonce, 2);

        let hash = op_2
            .uo
            .hash(pool.config.entry_point, pool.config.chain_spec.id);

        pool.add_operation(op, 0).unwrap();
        pool.add_operation(op_2, 0).unwrap();

        let mined_op = MinedOp {
            paymaster: None,
            actual_gas_cost: U256::ZERO,
            hash,
            entry_point: pool.config.entry_point,
            sender,
            nonce: U256::from(nonce),
        };

        pool.mine_operation(&mined_op, 1);

        assert!(pool.by_hash.is_empty());
        assert!(pool.by_id.is_empty());
        assert!(pool.best.is_empty());
    }

    #[test]
    fn remove_aggregator() {
        let mut pool = pool();
        let agg = Address::random();
        let ops = vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ];
        for mut op in ops.into_iter() {
            op.aggregator = Some(agg);
            op.entity_infos.aggregator = Some(EntityInfo {
                entity: Entity::aggregator(agg),
                is_staked: false,
            });
            pool.add_operation(op.clone(), 0).unwrap();
        }
        assert_eq!(pool.by_hash.len(), 3);

        pool.remove_entity(Entity::aggregator(agg));
        assert!(pool.by_hash.is_empty());
        assert!(pool.by_id.is_empty());
        assert!(pool.best.is_empty());
    }

    #[test]
    fn remove_paymaster() {
        let mut pool = pool();
        let paymaster = Address::random();
        let ops = vec![
            create_op(Address::random(), 0, 3),
            create_op(Address::random(), 0, 2),
            create_op(Address::random(), 0, 1),
        ];
        for mut op in ops.into_iter() {
            let uo: &mut UserOperation = op.uo.as_mut();

            uo.paymaster_and_data = paymaster.to_vec().into();
            op.entity_infos.paymaster = Some(EntityInfo {
                entity: Entity::paymaster(paymaster),
                is_staked: false,
            });
            pool.add_operation(op.clone(), 0).unwrap();
        }
        assert_eq!(pool.by_hash.len(), 3);

        pool.remove_entity(Entity::paymaster(paymaster));
        assert!(pool.by_hash.is_empty());
        assert!(pool.by_id.is_empty());
        assert!(pool.best.is_empty());
    }

    #[test]
    fn address_count() {
        let mut pool = pool();
        let sender = Address::random();
        let paymaster = Address::random();
        let factory = Address::random();
        let aggregator = Address::random();

        let mut op = create_op(sender, 0, 1);
        let uo: &mut UserOperation = op.uo.as_mut();
        uo.paymaster_and_data = paymaster.to_vec().into();
        op.entity_infos.paymaster = Some(EntityInfo {
            entity: Entity::paymaster(paymaster),
            is_staked: false,
        });
        uo.init_code = factory.to_vec().into();
        op.entity_infos.factory = Some(EntityInfo {
            entity: Entity::factory(factory),
            is_staked: false,
        });
        op.aggregator = Some(aggregator);
        op.entity_infos.aggregator = Some(EntityInfo {
            entity: Entity::aggregator(aggregator),
            is_staked: false,
        });

        let count = 5;
        let mut hashes = vec![];
        for i in 0..count {
            let mut op = op.clone();
            let uo: &mut UserOperation = op.uo.as_mut();
            uo.nonce = U256::from(i);
            hashes.push(pool.add_operation(op, 0).unwrap());
        }

        assert_eq!(pool.address_count(&sender), 5);
        assert_eq!(pool.address_count(&paymaster), 5);
        assert_eq!(pool.address_count(&factory), 5);
        assert_eq!(pool.address_count(&aggregator), 5);

        for hash in hashes.iter() {
            assert!(pool.remove_operation_by_hash(*hash).is_some());
        }

        assert_eq!(pool.address_count(&sender), 0);
        assert_eq!(pool.address_count(&paymaster), 0);
        assert_eq!(pool.address_count(&factory), 0);
        assert_eq!(pool.address_count(&aggregator), 0);
    }

    #[test]
    fn pool_full_new_replaces_worst() {
        let args = conf();
        let mut pool = pool();
        for i in 0..20 {
            let op = create_op(Address::random(), i, (i + 1) as u128);
            pool.add_operation(op, 0).unwrap();
        }

        // on greater gas, new op should win
        let op = create_op(Address::random(), args.max_size_of_pool_bytes, 2);
        let result = pool.add_operation(op, 0);
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn pool_full_worst_remains() {
        let mut pool = pool();
        for i in 0..20 {
            let op = create_op(Address::random(), i, (i + 1) as u128);
            pool.add_operation(op, 0).unwrap();
        }

        let op = create_op(Address::random(), 4, 1);
        assert!(pool.add_operation(op, 0).is_err());

        // on equal gas, worst should remain because it came first
        let op = create_op(Address::random(), 4, 2);
        let result = pool.add_operation(op, 0);
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn replace_op_underpriced() {
        let mut pool = pool();
        let sender = Address::random();
        let mut po1 = create_op(sender, 0, 100);
        let uo1: &mut UserOperation = po1.uo.as_mut();
        uo1.max_priority_fee_per_gas = 100;
        let _ = pool.add_operation(po1.clone(), 0).unwrap();

        let mut po2 = create_op(sender, 0, 101);
        let uo2: &mut UserOperation = po2.uo.as_mut();
        uo2.max_priority_fee_per_gas = 101;
        let res = pool.add_operation(po2, 0);
        assert!(res.is_err());
        match res.err().unwrap() {
            MempoolError::ReplacementUnderpriced(a, b) => {
                assert_eq!(a, 100);
                assert_eq!(b, 100);
            }
            _ => panic!("wrong error"),
        }

        assert_eq!(pool.address_count(&sender), 1);
        assert_eq!(
            pool.pool_size,
            OrderedPoolOperation::new(Arc::new(po1), 0, true).mem_size(),
        );
    }

    #[test]
    fn replace_op() {
        let mut pool = pool();
        let sender = Address::random();
        let paymaster1 = Address::random();
        let mut po1 = create_op(sender, 0, 10);
        let uo1: &mut UserOperation = po1.uo.as_mut();
        uo1.max_priority_fee_per_gas = 10;
        uo1.paymaster_and_data = paymaster1.to_vec().into();
        po1.entity_infos.paymaster = Some(EntityInfo {
            entity: Entity::paymaster(paymaster1),
            is_staked: false,
        });
        let _ = pool.add_operation(po1, 0).unwrap();
        assert_eq!(pool.address_count(&paymaster1), 1);

        let paymaster2 = Address::random();
        let mut po2 = create_op(sender, 0, 11);
        let uo2: &mut UserOperation = po2.uo.as_mut();
        uo2.max_priority_fee_per_gas = 11;
        uo2.paymaster_and_data = paymaster2.to_vec().into();
        po2.entity_infos.paymaster = Some(EntityInfo {
            entity: Entity::paymaster(paymaster2),
            is_staked: false,
        });
        let _ = pool.add_operation(po2.clone(), 0).unwrap();

        assert_eq!(pool.address_count(&sender), 1);
        assert_eq!(pool.address_count(&paymaster1), 0);
        assert_eq!(pool.address_count(&paymaster2), 1);
        assert_eq!(
            pool.pool_size,
            OrderedPoolOperation::new(Arc::new(po2), 0, true).mem_size()
        );
    }

    #[test]
    fn test_already_known() {
        let mut pool = pool();
        let sender = Address::random();
        let mut po1 = create_op(sender, 0, 10);
        let uo1: &mut UserOperation = po1.uo.as_mut();
        uo1.max_priority_fee_per_gas = 10;
        let _ = pool.add_operation(po1.clone(), 0).unwrap();

        let res = pool.add_operation(po1, 0);
        assert!(res.is_err());
        match res.err().unwrap() {
            MempoolError::OperationAlreadyKnown => (),
            _ => panic!("wrong error"),
        }
    }

    #[test]
    fn test_expired() {
        let conf = conf();
        let mut pool = pool_with_conf(conf.clone());
        let sender = Address::random();
        let mut po1 = create_op(sender, 0, 10);
        po1.valid_time_range.valid_until = Timestamp::from(1);
        let hash = pool.add_operation(po1.clone(), 0).unwrap();

        pool.do_maintenance(0, Timestamp::from(2), None, FeeUpdate::default());
        assert_eq!(None, pool.get_operation_by_hash(hash));
    }

    #[test]
    fn test_multiple_expired() {
        let conf = conf();
        let mut pool = pool_with_conf(conf.clone());

        let mut po1 = create_op(Address::random(), 0, 10);
        po1.valid_time_range.valid_until = 5.into();
        let hash1 = pool.add_operation(po1.clone(), 0).unwrap();

        let mut po2 = create_op(Address::random(), 0, 10);
        po2.valid_time_range.valid_until = 10.into();
        let hash2 = pool.add_operation(po2.clone(), 0).unwrap();
        let mut po3 = create_op(Address::random(), 0, 10);
        po3.valid_time_range.valid_until = 9.into();
        let hash3 = pool.add_operation(po3.clone(), 0).unwrap();

        pool.do_maintenance(0, Timestamp::from(10), None, FeeUpdate::default());

        assert_eq!(None, pool.get_operation_by_hash(hash1));
        assert!(pool.get_operation_by_hash(hash2).is_some());
        assert_eq!(None, pool.get_operation_by_hash(hash3));
    }

    #[test]
    fn test_add_operation_ineligible_initially() {
        let mut conf = conf();
        conf.da_gas_tracking_enabled = true;
        let mut pool = pool_with_conf_oracle(conf.clone(), MockDAGasOracleSync::default());

        let po1 = create_op(Address::random(), 0, 10);

        let hash = pool.add_operation(po1, 50_001).unwrap();

        assert!(pool.get_operation_by_hash(hash).is_some());
        assert_eq!(pool.best_operations().collect::<Vec<_>>().len(), 0); // UO is ineligible due to pvg
    }

    #[test]
    fn test_add_operation_ineligible_then_eligible() {
        let mut conf = conf();
        conf.chain_spec.da_pre_verification_gas = true;
        conf.chain_spec.include_da_gas_in_gas_limit = true;
        conf.da_gas_tracking_enabled = true;

        let po1 = create_op(Address::random(), 0, 10);
        let pvg = po1.uo.pre_verification_gas();
        let da_pvg = po1
            .uo
            .pre_verification_da_gas_limit(&conf.chain_spec, Some(1));

        let mut oracle = MockDAGasOracleSync::default();
        oracle
            .expect_calc_da_gas_sync()
            .returning(move |_, _, _| da_pvg - 1);

        let mut pool = pool_with_conf_oracle(conf.clone(), oracle);

        let hash = pool.add_operation(po1, pvg + 1).unwrap();

        assert!(pool.get_operation_by_hash(hash).is_some());
        assert_eq!(pool.best_operations().collect::<Vec<_>>().len(), 0); // UO is ineligible due to pvg

        pool.do_maintenance(
            0,
            0.into(),
            Some(&DAGasBlockData::default()),
            FeeUpdate::default(),
        );

        assert_eq!(pool.best_operations().collect::<Vec<_>>().len(), 1); // UO is now eligible
    }

    #[test]
    fn test_add_operation_eligible_then_ineligible() {
        let mut conf = conf();
        conf.chain_spec.da_pre_verification_gas = true;
        conf.chain_spec.include_da_gas_in_gas_limit = true;
        conf.da_gas_tracking_enabled = true;

        let po1 = create_op(Address::random(), 0, 10);
        let pvg = po1.uo.pre_verification_gas();
        let da_pvg = po1
            .uo
            .pre_verification_da_gas_limit(&conf.chain_spec, Some(1));

        let mut oracle = MockDAGasOracleSync::default();
        oracle
            .expect_calc_da_gas_sync()
            .returning(move |_, _, _| da_pvg + 1);

        let mut pool = pool_with_conf_oracle(conf.clone(), oracle);

        let hash = pool.add_operation(po1, pvg).unwrap();

        assert!(pool.get_operation_by_hash(hash).is_some());
        assert_eq!(pool.best_operations().collect::<Vec<_>>().len(), 1);

        pool.do_maintenance(
            0,
            0.into(),
            Some(&DAGasBlockData::default()),
            FeeUpdate::default(),
        );

        assert_eq!(pool.best_operations().collect::<Vec<_>>().len(), 0);
    }

    #[test]
    fn test_add_operation_eligible_then_eligible() {
        let mut conf = conf();
        conf.chain_spec.da_pre_verification_gas = true;
        conf.chain_spec.include_da_gas_in_gas_limit = true;
        conf.da_gas_tracking_enabled = true;

        let po1 = create_op(Address::random(), 0, 10);
        let pvg = po1.uo.pre_verification_gas();
        let da_pvg = po1
            .uo
            .pre_verification_da_gas_limit(&conf.chain_spec, Some(1));

        let mut oracle = MockDAGasOracleSync::default();
        oracle
            .expect_calc_da_gas_sync()
            .returning(move |_, _, _| da_pvg);

        let mut pool = pool_with_conf_oracle(conf.clone(), oracle);

        let hash = pool.add_operation(po1, pvg).unwrap();

        assert!(pool.get_operation_by_hash(hash).is_some());
        assert_eq!(pool.best_operations().collect::<Vec<_>>().len(), 1);

        pool.do_maintenance(
            0,
            0.into(),
            Some(&DAGasBlockData::default()),
            FeeUpdate::default(),
        );

        assert_eq!(pool.best_operations().collect::<Vec<_>>().len(), 1);
    }

    #[test]
    fn test_add_operation_ineligible_then_ineligible() {
        let mut conf = conf();
        conf.chain_spec.da_pre_verification_gas = true;
        conf.chain_spec.include_da_gas_in_gas_limit = true;
        conf.da_gas_tracking_enabled = true;
        let base_fee = 0;

        let po1 = create_op(Address::random(), 0, 10);
        let po1_gas_price = po1.uo.gas_price(base_fee);
        let pvg = po1.uo.pre_verification_gas();
        let da_pvg = po1
            .uo
            .pre_verification_da_gas_limit(&conf.chain_spec, Some(1));

        let mut oracle = MockDAGasOracleSync::default();
        oracle.expect_calc_da_gas_sync().returning(move |_, _, gp| {
            assert_eq!(gp, po1_gas_price);
            da_pvg + 1
        });

        let mut pool = pool_with_conf_oracle(conf.clone(), oracle);

        let hash = pool.add_operation(po1, pvg + 1).unwrap();

        assert!(pool.get_operation_by_hash(hash).is_some());
        assert_eq!(pool.best_operations().collect::<Vec<_>>().len(), 0);

        pool.do_maintenance(
            0,
            0.into(),
            Some(&DAGasBlockData::default()),
            FeeUpdate::default(),
        );

        assert_eq!(pool.best_operations().collect::<Vec<_>>().len(), 0);
    }

    fn conf() -> PoolInnerConfig {
        PoolInnerConfig {
            chain_spec: ChainSpec::default(),
            entry_point: Address::random(),
            min_replacement_fee_increase_percentage: 10,
            max_size_of_pool_bytes: 20 * mem_size_of_ordered_pool_op(),
            throttled_entity_mempool_count: 4,
            throttled_entity_live_blocks: 10,
            da_gas_tracking_enabled: false,
        }
    }

    fn pool() -> PoolInner<Box<dyn DAGasOracleSync>> {
        PoolInner::new(conf(), None, broadcast::channel(100000).0)
    }

    fn pool_with_conf(conf: PoolInnerConfig) -> PoolInner<Box<dyn DAGasOracleSync>> {
        PoolInner::new(conf, None, broadcast::channel(100000).0)
    }

    fn pool_with_conf_oracle(
        conf: PoolInnerConfig,
        oracle: MockDAGasOracleSync,
    ) -> PoolInner<MockDAGasOracleSync> {
        PoolInner::new(conf, Some(oracle), broadcast::channel(100000).0)
    }

    fn mem_size_of_ordered_pool_op() -> usize {
        OrderedPoolOperation::new(Arc::new(create_op(Address::random(), 1, 1)), 1, true).mem_size()
    }

    fn create_op(sender: Address, nonce: usize, max_fee_per_gas: u128) -> PoolOperation {
        PoolOperation {
            uo: UserOperation {
                sender,
                nonce: U256::from(nonce),
                max_fee_per_gas,
                pre_verification_gas: 50_000,
                ..UserOperation::default()
            }
            .into(),
            entity_infos: EntityInfos {
                factory: None,
                sender: EntityInfo {
                    entity: Entity::account(sender),
                    is_staked: false,
                },
                paymaster: None,
                aggregator: None,
            },
            entry_point: Address::random(),
            valid_time_range: ValidTimeRange::default(),
            aggregator: None,
            expected_code_hash: B256::random(),
            sim_block_hash: B256::random(),
            sim_block_number: 0,
            account_is_staked: false,
            da_gas_data: Default::default(),
        }
    }

    fn check_map_entry(
        actual: Option<&Arc<OrderedPoolOperation>>,
        expected: Option<&PoolOperation>,
    ) {
        match (actual, expected) {
            (Some(actual), Some(expected)) => assert_eq!(*actual.po, *expected),
            (None, None) => (),
            _ => panic!("Expected {expected:?}, got {actual:?}"),
        }
    }
}
