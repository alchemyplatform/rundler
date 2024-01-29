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

use std::{collections::HashSet, sync::Arc};

use ethers::{
    types::{Address, H256, U256},
    utils::format_units,
};
use itertools::Itertools;
use parking_lot::RwLock;
use rundler_provider::{EntryPoint, PaymasterHelper, ProviderResult};
use rundler_sim::{Prechecker, Simulator};
use rundler_types::{Entity, EntityUpdate, EntityUpdateType, UserOperation};
use rundler_utils::emit::WithEntryPoint;
use tokio::sync::broadcast;
use tonic::async_trait;
use tracing::info;

use super::{
    error::{MempoolError, MempoolResult},
    pool::PoolInner,
    reputation::{Reputation, ReputationManager, ReputationStatus},
    Mempool, OperationOrigin, PaymasterMetadata, PoolConfig, PoolOperation, StakeInfo, StakeStatus,
};
use crate::{
    chain::{ChainUpdate, DepositInfo},
    emit::{EntityReputation, EntityStatus, EntitySummary, OpPoolEvent, OpRemovalReason},
};

/// User Operation Mempool
///
/// Wrapper around a pool object that implements thread-safety
/// via a RwLock. Safe to call from multiple threads. Methods
/// block on write locks.
pub(crate) struct UoPool<
    R: ReputationManager,
    P: Prechecker,
    S: Simulator,
    E: EntryPoint,
    PH: PaymasterHelper,
> {
    config: PoolConfig,
    reputation: Arc<R>,
    state: RwLock<UoPoolState>,
    event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
    prechecker: P,
    simulator: S,
    entry_point: E,
    paymaster_helper: PH,
}

struct UoPoolState {
    pool: PoolInner,
    throttled_ops: HashSet<H256>,
    block_number: u64,
}

impl<R, P, S, E, PH> UoPool<R, P, S, E, PH>
where
    R: ReputationManager,
    P: Prechecker,
    S: Simulator,
    E: EntryPoint,
    PH: PaymasterHelper,
{
    pub(crate) fn new(
        config: PoolConfig,
        reputation: Arc<R>,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        prechecker: P,
        simulator: S,
        entry_point: E,
        paymaster_helper: PH,
    ) -> Self {
        Self {
            config: config.clone(),
            reputation,
            state: RwLock::new(UoPoolState {
                pool: PoolInner::new(config.into()),
                throttled_ops: HashSet::new(),
                block_number: 0,
            }),
            event_sender,
            prechecker,
            simulator,
            entry_point,
            paymaster_helper,
        }
    }

    fn emit(&self, event: OpPoolEvent) {
        let _ = self.event_sender.send(WithEntryPoint {
            entry_point: self.config.entry_point,
            event,
        });
    }

    fn throttle_entity(&self, entity: Entity) {
        let mut state = self.state.write();
        let block_number = state.block_number;
        let removed_op_hashes = state.pool.throttle_entity(entity, block_number);

        let count = removed_op_hashes.len();
        self.emit(OpPoolEvent::RemovedEntity { entity });

        for op_hash in removed_op_hashes {
            self.emit(OpPoolEvent::RemovedOp {
                op_hash,
                reason: OpRemovalReason::EntityRemoved { entity },
            })
        }
        UoPoolMetrics::increment_removed_operations(count, self.config.entry_point);
        UoPoolMetrics::increment_removed_entities(self.config.entry_point);
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
        UoPoolMetrics::increment_removed_operations(count, self.config.entry_point);
        UoPoolMetrics::increment_removed_entities(self.config.entry_point);
    }
}

#[async_trait]
impl<R, P, S, E, PH> Mempool for UoPool<R, P, S, E, PH>
where
    R: ReputationManager,
    P: Prechecker,
    S: Simulator,
    E: EntryPoint,
    PH: PaymasterHelper,
{
    async fn on_chain_update(&self, update: &ChainUpdate) {
        {
            let deduped_ops = update.deduped_ops();
            let mined_ops = deduped_ops
                .mined_ops
                .iter()
                .filter(|op| op.entry_point == self.config.entry_point);

            let deposits: Vec<DepositInfo> = update
                .entity_deposits
                .iter()
                .filter(|d| d.entrypoint == self.config.entry_point)
                .cloned()
                .collect();

            let unmined_entity_deposits: Vec<DepositInfo> = update
                .unmined_entity_deposits
                .iter()
                .filter(|d| d.entrypoint == self.config.entry_point)
                .cloned()
                .collect();

            let unmined_ops = deduped_ops
                .unmined_ops
                .iter()
                .filter(|op| op.entry_point == self.config.entry_point);
            let mut mined_op_count = 0;
            let mut unmined_op_count = 0;

            if update.reorg_larger_than_history {
                let _ = self.reset_confirmed_paymaster_balances().await;
            }

            let mut state = self.state.write();
            state
                .pool
                .update_paymaster_balances_after_update(&deposits, &unmined_entity_deposits);

            for op in mined_ops {
                if op.entry_point != self.config.entry_point {
                    continue;
                }

                // Remove throttled ops that were included in the block
                state.throttled_ops.remove(&op.hash);

                if let Some(op) = state.pool.mine_operation(op, update.latest_block_number) {
                    // Only account for an entity once
                    for entity_addr in op.entities().map(|e| e.address).unique() {
                        self.reputation.add_included(entity_addr);
                    }
                    mined_op_count += 1;
                }
            }
            for op in unmined_ops {
                if op.entry_point != self.config.entry_point {
                    continue;
                }

                if let Some(op) = state.pool.unmine_operation(op) {
                    // Only account for an entity once
                    for entity_addr in op.entities().map(|e| e.address).unique() {
                        self.reputation.remove_included(entity_addr);
                    }
                    unmined_op_count += 1;
                }
            }
            if mined_op_count > 0 {
                info!(
                "{mined_op_count} op(s) mined on entry point {:?} when advancing to block with number {}, hash {:?}.",
                self.config.entry_point,
                update.latest_block_number,
                update.latest_block_hash,
            );
            }
            if unmined_op_count > 0 {
                info!(
                "{unmined_op_count} op(s) unmined in reorg on entry point {:?} when advancing to block with number {}, hash {:?}.",
                self.config.entry_point,
                update.latest_block_number,
                update.latest_block_hash,
            );
            }
            UoPoolMetrics::update_ops_seen(
                mined_op_count as isize - unmined_op_count as isize,
                self.config.entry_point,
            );
            UoPoolMetrics::increment_unmined_operations(unmined_op_count, self.config.entry_point);

            state
                .pool
                .forget_mined_operations_before_block(update.earliest_remembered_block_number);
            // Remove throttled ops that are too old
            let mut to_remove = HashSet::new();
            for hash in state.throttled_ops.iter() {
                let block_seen = state
                    .pool
                    .get_operation_by_hash(*hash)
                    .map(|po| po.sim_block_number);
                if let Some(block) = block_seen {
                    if update.latest_block_number - block > self.config.throttled_entity_live_blocks
                    {
                        to_remove.insert((*hash, block));
                    }
                }
            }
            for (hash, added_at_block) in to_remove {
                state.pool.remove_operation_by_hash(hash);
                state.throttled_ops.remove(&hash);
                self.emit(OpPoolEvent::RemovedOp {
                    op_hash: hash,
                    reason: OpRemovalReason::ThrottledAndOld {
                        added_at_block_number: added_at_block,
                        current_block_number: update.latest_block_number,
                    },
                })
            }

            // expire old UOs
            let expired = state.pool.remove_expired(update.latest_block_timestamp);
            for (hash, until) in expired {
                self.emit(OpPoolEvent::RemovedOp {
                    op_hash: hash,
                    reason: OpRemovalReason::Expired { valid_until: until },
                })
            }

            state.block_number = update.latest_block_number;
        }

        // update required bundle fees and update metrics
        if let Ok((bundle_fees, base_fee)) = self.prechecker.update_fees().await {
            let max_fee = match format_units(bundle_fees.max_fee_per_gas, "gwei") {
                Ok(s) => s.parse::<f64>().unwrap_or_default(),
                Err(_) => 0.0,
            };
            UoPoolMetrics::current_max_fee_gwei(max_fee);

            let max_priority_fee = match format_units(bundle_fees.max_priority_fee_per_gas, "gwei")
            {
                Ok(s) => s.parse::<f64>().unwrap_or_default(),
                Err(_) => 0.0,
            };
            UoPoolMetrics::current_max_priority_fee_gwei(max_priority_fee);

            let base_fee = match format_units(base_fee, "gwei") {
                Ok(s) => s.parse::<f64>().unwrap_or_default(),
                Err(_) => 0.0,
            };
            UoPoolMetrics::current_base_fee(base_fee);
        }
    }

    fn entry_point(&self) -> Address {
        self.config.entry_point
    }

    async fn reset_confirmed_paymaster_balances(&self) -> MempoolResult<()> {
        let paymaster_addresses = self.state.read().pool.paymaster_addresses();

        let balances = self
            .paymaster_helper
            .get_balances(paymaster_addresses.clone())
            .await?;

        self.state
            .write()
            .pool
            .set_confirmed_paymaster_balances(&paymaster_addresses, &balances);

        Ok(())
    }

    async fn add_operation(
        &self,
        origin: OperationOrigin,
        op: UserOperation,
    ) -> MempoolResult<H256> {
        // TODO(danc) aggregator reputation is not implemented
        // TODO(danc) catch ops with aggregators prior to simulation and reject

        // Check reputation of entities in involved in the operation
        // If throttled, entity can have THROTTLED_ENTITY_MEMPOOL_COUNT inflight operation at a time, else reject
        // If banned, reject
        let mut entity_summary = EntitySummary::default();
        let mut throttled = false;
        for entity in op.entities() {
            let address = entity.address;
            let reputation = match self.reputation.status(address) {
                ReputationStatus::Ok => EntityReputation::Ok,
                ReputationStatus::Throttled => {
                    if self.state.read().pool.address_count(&address)
                        >= self.config.throttled_entity_mempool_count as usize
                    {
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

        // Check if op is already known or replacing another, and if so, ensure its fees are high enough
        // do this before simulation to save resources
        self.state.read().pool.check_replacement(&op)?;
        // Check if op violates the STO-040 spec rule
        self.state.read().pool.check_multiple_roles_violation(&op)?;

        // check if paymaster is present and exists in pool
        // Note: this is super gross but due the fact that we do not want to make
        // http calls when we hold the readwrite lock its a work around
        let mut paymaster_metadata = None;
        if let Some(address) = op.paymaster() {
            let meta = self
                .paymaster_balance(address)
                .await
                .map_err(|e| MempoolError::Other(e.into()))?;

            paymaster_metadata = Some(meta);
        }

        // Prechecks
        self.prechecker.check(&op).await?;

        // Only let ops with successful simulations through
        let sim_result = self
            .simulator
            .simulate_validation(op.clone(), None, None)
            .await?;

        // No aggregators supported for now
        if let Some(agg) = &sim_result.aggregator {
            return Err(MempoolError::UnsupportedAggregator(agg.address));
        }

        // Check if op violates the STO-041 spec rule
        self.state
            .read()
            .pool
            .check_associated_storage(&sim_result.associated_addresses, &op)?;

        let valid_time_range = sim_result.valid_time_range;
        let pool_op = PoolOperation {
            uo: op,
            entry_point: self.config.entry_point,
            aggregator: None,
            valid_time_range,
            expected_code_hash: sim_result.code_hash,
            sim_block_hash: sim_result.block_hash,
            sim_block_number: sim_result.block_number.unwrap(), // simulation always returns a block number when called without a specified block_hash
            entities_needing_stake: sim_result.entities_needing_stake,
            account_is_staked: sim_result.account_is_staked,
            entity_infos: sim_result.entity_infos,
        };

        // Check sender count in mempool. If sender has too many operations, must be staked
        {
            let state = self.state.read();
            if !pool_op.account_is_staked
                && state.pool.address_count(&pool_op.uo.sender)
                    >= self.config.same_sender_mempool_count
            {
                return Err(MempoolError::MaxOperationsReached(
                    self.config.same_sender_mempool_count,
                    pool_op.uo.sender,
                ));
            }

            // Check unstaked non-sender entity counts in the mempool
            for entity in pool_op
                .unstaked_entities()
                .filter(|e| e.address != pool_op.entity_infos.sender.address)
            {
                let ops_allowed = self.reputation.get_ops_allowed(entity.address);
                if state.pool.address_count(&entity.address) >= ops_allowed as usize {
                    return Err(MempoolError::MaxOperationsReached(
                        ops_allowed as usize,
                        entity.address,
                    ));
                }
            }
        }

        // Add op to pool
        let hash = {
            let mut state = self.state.write();
            let hash = state
                .pool
                .add_operation(pool_op.clone(), paymaster_metadata)?;
            if throttled {
                state.throttled_ops.insert(hash);
            }
            hash
        };

        // Update reputation
        pool_op.entities().unique().for_each(|e| {
            self.reputation.add_seen(e.address);
            if self.reputation.status(e.address) == ReputationStatus::Throttled {
                self.throttle_entity(e);
            } else if self.reputation.status(e.address) == ReputationStatus::Banned {
                self.remove_entity(e);
            }
        });

        let op_hash = pool_op
            .uo
            .op_hash(self.config.entry_point, self.config.chain_id);
        let valid_after = pool_op.valid_time_range.valid_after;
        let valid_until = pool_op.valid_time_range.valid_until;
        self.emit(OpPoolEvent::ReceivedOp {
            op_hash,
            op: pool_op.uo,
            block_number: pool_op.sim_block_number,
            origin,
            valid_after,
            valid_until,
            entities: entity_summary,
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
        UoPoolMetrics::increment_removed_operations(count, self.config.entry_point);
    }

    fn update_entity(&self, update: EntityUpdate) {
        let entity = update.entity;
        match update.update_type {
            EntityUpdateType::UnstakedInvalidation => {
                self.reputation.handle_urep_030_penalty(entity.address);
            }
            EntityUpdateType::StakedInvalidation => {
                self.reputation.handle_srep_050_penalty(entity.address);
            }
        }

        if self.reputation.status(entity.address) == ReputationStatus::Banned {
            self.remove_entity(entity);
        }
    }

    async fn paymaster_balance(&self, paymaster: Address) -> ProviderResult<PaymasterMetadata> {
        if self.state.read().pool.paymaster_exists(paymaster) {
            let meta = self
                .state
                .read()
                .pool
                .paymaster_metadata(paymaster)
                .expect("Paymaster balance should not be empty if address exists in pool");
            return Ok(meta);
        }

        let balance = self.entry_point.balance_of(paymaster, None).await?;

        let paymaster_meta = PaymasterMetadata {
            address: paymaster,
            pending_balance: balance,
            confirmed_balance: balance,
        };

        Ok(paymaster_meta)
    }

    fn best_operations(
        &self,
        max: usize,
        shard_index: u64,
    ) -> MempoolResult<Vec<Arc<PoolOperation>>> {
        if shard_index >= self.config.num_shards {
            Err(anyhow::anyhow!("Invalid shard ID"))?;
        }

        // get the best operations from the pool
        let ordered_ops = self.state.read().pool.best_operations();
        // keep track of senders to avoid sending multiple ops from the same sender
        let mut senders = HashSet::<Address>::new();

        Ok(ordered_ops
            .into_iter()
            .filter(|op| {
                // short-circuit the mod if there is only 1 shard
                ((self.config.num_shards == 1) ||
                (U256::from_little_endian(op.uo.sender.as_bytes())
                        .div_mod(self.config.num_shards.into())
                        .1
                        == shard_index.into())) &&
                // filter out ops from senders we've already seen
                senders.insert(op.uo.sender)
            })
            .take(max)
            .collect())
    }

    fn all_operations(&self, max: usize) -> Vec<Arc<PoolOperation>> {
        self.state.read().pool.best_operations().take(max).collect()
    }

    fn get_user_operation_by_hash(&self, hash: H256) -> Option<Arc<PoolOperation>> {
        self.state.read().pool.get_operation_by_hash(hash)
    }

    fn clear_state(&self, clear_mempool: bool, clear_reputation: bool) {
        if clear_mempool {
            self.state.write().pool.clear()
        }
        if clear_reputation {
            self.reputation.clear()
        }
    }

    fn dump_reputation(&self) -> Vec<Reputation> {
        self.reputation.dump_reputation()
    }

    fn get_reputation_status(&self, address: Address) -> ReputationStatus {
        self.reputation.status(address)
    }

    async fn get_stake_status(&self, address: Address) -> MempoolResult<StakeStatus> {
        let deposit_info = self.paymaster_helper.get_deposit_info(address).await?;

        let is_staked = deposit_info
            .stake
            .ge(&self.config.sim_settings.min_stake_value)
            && deposit_info
                .unstake_delay_sec
                .ge(&self.config.sim_settings.min_unstake_delay);

        let stake_status = StakeStatus {
            stake_info: StakeInfo {
                stake: deposit_info.stake,
                unstake_delay_sec: deposit_info.unstake_delay_sec,
            },
            is_staked,
        };

        Ok(stake_status)
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

    fn current_max_fee_gwei(fee: f64) {
        metrics::gauge!("op_pool_current_max_fee_gwei", fee);
    }

    fn current_max_priority_fee_gwei(fee: f64) {
        metrics::gauge!("op_pool_current_max_priority_fee_gwei", fee);
    }

    fn current_base_fee(fee: f64) {
        metrics::gauge!("op_pool_current_base_fee", fee);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ethers::types::{Bytes, H160};
    use rundler_provider::{MockEntryPoint, MockPaymasterHelper};
    use rundler_sim::{
        EntityInfo, EntityInfos, MockPrechecker, MockSimulator, PrecheckError, PrecheckSettings,
        PrecheckViolation, SimulationError, SimulationResult, SimulationSettings,
        SimulationViolation, ViolationError,
    };
    use rundler_types::{DepositInfo, EntityType, GasFees, ValidTimeRange};

    use super::*;
    use crate::chain::MinedOp;

    const THROTTLE_SLACK: u64 = 5;
    const BAN_SLACK: u64 = 10;

    #[tokio::test]
    async fn add_single_op() {
        let op = create_op(Address::random(), 0, 0, None);
        let ops = vec![op.clone()];
        let uos = vec![op.op.clone()];
        let pool = create_pool(ops);

        let hash = pool
            .add_operation(OperationOrigin::Local, op.op)
            .await
            .unwrap();
        check_ops(pool.best_operations(1, 0).unwrap(), uos);
        pool.remove_operations(&[hash]);
        assert_eq!(pool.best_operations(1, 0).unwrap(), vec![]);
    }

    #[tokio::test]
    async fn add_multiple_ops() {
        let ops = vec![
            create_op(Address::random(), 0, 3, None),
            create_op(Address::random(), 0, 2, None),
            create_op(Address::random(), 0, 1, None),
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
        check_ops(pool.best_operations(3, 0).unwrap(), uos);
        pool.remove_operations(&hashes);
        assert_eq!(pool.best_operations(3, 0).unwrap(), vec![]);
    }

    #[tokio::test]
    async fn clear() {
        let ops = vec![
            create_op(Address::random(), 0, 3, None),
            create_op(Address::random(), 0, 2, None),
            create_op(Address::random(), 0, 1, None),
        ];
        let uos = ops.iter().map(|op| op.op.clone()).collect::<Vec<_>>();
        let pool = create_pool(ops);

        for op in &uos {
            let _ = pool
                .add_operation(OperationOrigin::Local, op.clone())
                .await
                .unwrap();
        }
        check_ops(pool.best_operations(3, 0).unwrap(), uos);
        pool.clear_state(true, true);
        assert_eq!(pool.best_operations(3, 0).unwrap(), vec![]);
    }

    #[tokio::test]
    async fn chain_update_mine() {
        let (pool, uos) = create_pool_insert_ops(vec![
            create_op(Address::random(), 0, 3, None),
            create_op(Address::random(), 0, 2, None),
            create_op(Address::random(), 0, 1, None),
        ])
        .await;
        check_ops(pool.best_operations(3, 0).unwrap(), uos.clone());

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: H256::random(),
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: pool.config.entry_point,
                hash: uos[0].op_hash(pool.config.entry_point, 1),
                sender: uos[0].sender,
                nonce: uos[0].nonce,
                actual_gas_cost: U256::zero(),
                paymaster: None,
            }],
            unmined_ops: vec![],
            entity_deposits: vec![],
            unmined_entity_deposits: vec![],
            reorg_larger_than_history: false,
        })
        .await;

        check_ops(pool.best_operations(3, 0).unwrap(), uos[1..].to_vec());
    }

    #[tokio::test]
    async fn chain_update_mine_unmine() {
        let paymaster = Address::random();

        let mut ops = vec![
            create_op(Address::random(), 0, 3, Some(paymaster)),
            create_op(Address::random(), 0, 2, Some(paymaster)),
            create_op(Address::random(), 0, 1, Some(paymaster)),
        ];

        // add pending max cost of 30 for each uo
        for op in &mut ops {
            op.op.call_gas_limit = 10.into();
            op.op.verification_gas_limit = 10.into();
            op.op.pre_verification_gas = 10.into();
            op.op.max_fee_per_gas = 1.into();
        }

        let (pool, uos) = create_pool_insert_ops(ops).await;
        let metadata = pool
            .state
            .read()
            .pool
            .paymaster_metadata(paymaster)
            .unwrap();

        assert_eq!(metadata.pending_balance, 850.into());
        check_ops(pool.best_operations(3, 0).unwrap(), uos.clone());

        // mine the first op with actual gas cost of 10
        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: H256::random(),
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: pool.config.entry_point,
                hash: uos[0].op_hash(pool.config.entry_point, 1),
                sender: uos[0].sender,
                nonce: uos[0].nonce,
                actual_gas_cost: 10.into(),
                paymaster: Some(paymaster),
            }],
            unmined_ops: vec![],
            entity_deposits: vec![],
            unmined_entity_deposits: vec![],
            reorg_larger_than_history: false,
        })
        .await;

        check_ops(
            pool.best_operations(3, 0).unwrap(),
            uos.clone()[1..].to_vec(),
        );

        let metadata = pool
            .state
            .read()
            .pool
            .paymaster_metadata(paymaster)
            .unwrap();
        assert_eq!(metadata.pending_balance, 890.into());

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: H256::random(),
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![],
            unmined_ops: vec![MinedOp {
                entry_point: pool.config.entry_point,
                hash: uos[0].op_hash(pool.config.entry_point, 1),
                sender: uos[0].sender,
                nonce: uos[0].nonce,
                actual_gas_cost: 10.into(),
                paymaster: None,
            }],
            entity_deposits: vec![],
            unmined_entity_deposits: vec![],
            reorg_larger_than_history: false,
        })
        .await;

        let metadata = pool
            .state
            .read()
            .pool
            .paymaster_metadata(paymaster)
            .unwrap();
        assert_eq!(metadata.pending_balance, 850.into());

        check_ops(pool.best_operations(3, 0).unwrap(), uos);
    }

    #[tokio::test]
    async fn chain_update_wrong_ep() {
        let (pool, uos) = create_pool_insert_ops(vec![
            create_op(Address::random(), 0, 3, None),
            create_op(Address::random(), 0, 2, None),
            create_op(Address::random(), 0, 1, None),
        ])
        .await;
        check_ops(pool.best_operations(3, 0).unwrap(), uos.clone());

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: H256::random(),
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: Address::random(),
                hash: uos[0].op_hash(pool.config.entry_point, 1),
                sender: uos[0].sender,
                nonce: uos[0].nonce,
                actual_gas_cost: U256::zero(),
                paymaster: None,
            }],
            unmined_ops: vec![],
            entity_deposits: vec![],
            unmined_entity_deposits: vec![],
            reorg_larger_than_history: false,
        })
        .await;

        check_ops(pool.best_operations(3, 0).unwrap(), uos);
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
        check_ops(pool.best_operations(3, 0).unwrap(), vec![uos[0].clone()]);

        let rep = pool.dump_reputation();
        assert_eq!(rep.len(), 1);
        assert_eq!(rep[0].address, address);
        assert_eq!(rep[0].ops_seen, 2); // 2 ops seen, 1 rejected at insert
        assert_eq!(rep[0].ops_included, 0); // No ops included yet

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: H256::random(),
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: pool.config.entry_point,
                hash: uos[0].op_hash(pool.config.entry_point, 1),
                sender: uos[0].sender,
                nonce: uos[0].nonce,
                actual_gas_cost: U256::zero(),
                paymaster: None,
            }],
            unmined_ops: vec![],
            entity_deposits: vec![],
            unmined_entity_deposits: vec![],
            reorg_larger_than_history: false,
        })
        .await;

        let rep = pool.dump_reputation();
        assert_eq!(rep.len(), 1);
        assert_eq!(rep[0].address, address);
        assert_eq!(rep[0].ops_seen, 2); // 2 ops seen, 1 rejected at insert
        assert_eq!(rep[0].ops_included, 1); // 1 op included
    }

    #[tokio::test]
    async fn test_throttled_account() {
        let address = Address::random();
        let mut ops = Vec::new();
        for i in 0..5 {
            ops.push(create_op_with_errors(address, i, 2, None, None, true));
        }
        let uos = ops.iter().map(|op| op.op.clone()).collect::<Vec<_>>();
        let pool = create_pool(ops);
        // Past throttle slack
        pool.set_reputation(address, 1 + THROTTLE_SLACK, 0);

        // Ops 0 through 3 should be included
        for uo in uos.iter().take(4) {
            pool.add_operation(OperationOrigin::Local, uo.clone())
                .await
                .unwrap();
        }

        check_ops(
            pool.all_operations(4),
            vec![
                uos[0].clone(),
                uos[1].clone(),
                uos[2].clone(),
                uos[3].clone(),
            ],
        );

        // Second op should be throttled
        let ret = pool
            .add_operation(OperationOrigin::Local, uos[4].clone())
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
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: pool.config.entry_point,
                hash: uos[0].op_hash(pool.config.entry_point, 1),
                sender: uos[0].sender,
                nonce: uos[0].nonce,
                actual_gas_cost: U256::zero(),
                paymaster: None,
            }],
            entity_deposits: vec![],
            unmined_ops: vec![],
            unmined_entity_deposits: vec![],
            reorg_larger_than_history: false,
        })
        .await;

        // Second op should be included
        pool.add_operation(OperationOrigin::Local, uos[4].clone())
            .await
            .unwrap();
        check_ops(
            pool.all_operations(4),
            vec![
                uos[1].clone(),
                uos[2].clone(),
                uos[3].clone(),
                uos[4].clone(),
            ],
        );
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
    async fn test_paymaster_balance_insufficient() {
        let paymaster = Address::random();
        let mut op = create_op(Address::random(), 0, 0, Some(paymaster));
        op.op.call_gas_limit = 1000.into();
        op.op.verification_gas_limit = 1000.into();
        op.op.pre_verification_gas = 1000.into();
        op.op.max_fee_per_gas = 1.into();

        let uo = op.op.clone();
        let pool = create_pool(vec![op]);

        let ret = pool
            .add_operation(OperationOrigin::Local, uo.clone())
            .await
            .unwrap_err();

        assert!(matches!(ret, MempoolError::PaymasterBalanceTooLow(_, _)));
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
        assert_eq!(pool.best_operations(1, 0).unwrap(), vec![]);
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
        assert_eq!(pool.best_operations(1, 0).unwrap(), vec![]);
    }

    #[tokio::test]
    async fn test_already_known() {
        let op = create_op(Address::random(), 0, 0, None);
        let pool = create_pool(vec![op.clone()]);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone())
            .await
            .unwrap();

        let err = pool
            .add_operation(OperationOrigin::Local, op.op.clone())
            .await
            .unwrap_err();
        assert!(matches!(err, MempoolError::OperationAlreadyKnown));

        check_ops(pool.best_operations(1, 0).unwrap(), vec![op.op]);
    }

    #[tokio::test]
    async fn test_replacement_underpriced() {
        let op = create_op(Address::random(), 0, 100, None);
        let pool = create_pool(vec![op.clone()]);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone())
            .await
            .unwrap();

        let mut replacement = op.op.clone();
        replacement.max_fee_per_gas = replacement.max_fee_per_gas + 1;

        let err = pool
            .add_operation(OperationOrigin::Local, replacement)
            .await
            .unwrap_err();

        assert!(matches!(err, MempoolError::ReplacementUnderpriced(_, _)));

        check_ops(pool.best_operations(1, 0).unwrap(), vec![op.op]);
    }

    #[tokio::test]
    async fn test_stake_status_staked() {
        let mut pool = create_pool(vec![]);

        pool.config.sim_settings.min_stake_value = 9999;
        pool.config.sim_settings.min_unstake_delay = 99;

        let status = pool.get_stake_status(Address::random()).await.unwrap();

        assert!(status.is_staked);
    }

    #[tokio::test]
    async fn test_stake_status_not_staked() {
        let mut pool = create_pool(vec![]);

        pool.config.sim_settings.min_stake_value = 10001;
        pool.config.sim_settings.min_unstake_delay = 101;

        let status = pool.get_stake_status(Address::random()).await.unwrap();

        assert!(!status.is_staked);
    }

    #[tokio::test]
    async fn test_replacement() {
        let paymaster = Address::random();

        let mut op = create_op(Address::random(), 0, 5, Some(paymaster));
        op.op.call_gas_limit = 10.into();
        op.op.verification_gas_limit = 10.into();
        op.op.pre_verification_gas = 10.into();
        op.op.max_fee_per_gas = 1.into();

        let pool = create_pool(vec![op.clone()]);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone())
            .await
            .unwrap();

        let mut replacement = op.op.clone();
        replacement.max_fee_per_gas = replacement.max_fee_per_gas + 1;

        let _ = pool
            .add_operation(OperationOrigin::Local, replacement.clone())
            .await
            .unwrap();

        check_ops(pool.best_operations(1, 0).unwrap(), vec![replacement]);

        let paymaster_balance = pool
            .state
            .read()
            .pool
            .paymaster_metadata(paymaster)
            .unwrap();
        assert_eq!(paymaster_balance.pending_balance, U256::from(900));
    }

    #[tokio::test]
    async fn test_expiry() {
        let mut op = create_op(Address::random(), 0, 0, None);
        op.valid_time_range = ValidTimeRange {
            valid_after: 0.into(),
            valid_until: 10.into(),
        };
        let pool = create_pool(vec![op.clone()]);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone())
            .await
            .unwrap();

        check_ops(pool.best_operations(1, 0).unwrap(), vec![op.op.clone()]);

        pool.on_chain_update(&ChainUpdate {
            latest_block_timestamp: 11.into(),
            ..ChainUpdate::default()
        })
        .await;

        check_ops(pool.best_operations(1, 0).unwrap(), vec![]);
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash() {
        let op = create_op(Address::random(), 0, 0, None);
        let pool = create_pool(vec![op.clone()]);

        let hash = pool
            .add_operation(OperationOrigin::Local, op.op.clone())
            .await
            .unwrap();

        let pool_op = pool.get_user_operation_by_hash(hash).unwrap();
        assert_eq!(pool_op.uo, op.op);
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_not_found() {
        let op = create_op(Address::random(), 0, 0, None);
        let pool = create_pool(vec![op.clone()]);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone())
            .await
            .unwrap();

        let pool_op = pool.get_user_operation_by_hash(H256::random());
        assert_eq!(pool_op, None);
    }

    #[tokio::test]
    async fn too_many_ops_for_unstaked_sender() {
        let mut ops = vec![];
        let addr = H160::random();
        for i in 0..5 {
            ops.push(create_op(addr, i, 1, None))
        }
        let pool = create_pool(ops.clone());

        for op in ops.iter().take(4) {
            pool.add_operation(OperationOrigin::Local, op.op.clone())
                .await
                .unwrap();
        }
        assert!(pool
            .add_operation(OperationOrigin::Local, ops[4].op.clone())
            .await
            .is_err());
    }

    #[derive(Clone, Debug)]
    struct OpWithErrors {
        op: UserOperation,
        valid_time_range: ValidTimeRange,
        precheck_error: Option<PrecheckViolation>,
        simulation_error: Option<SimulationViolation>,
        staked: bool,
    }

    fn create_pool(
        ops: Vec<OpWithErrors>,
    ) -> UoPool<
        impl ReputationManager,
        impl Prechecker,
        impl Simulator,
        impl EntryPoint,
        impl PaymasterHelper,
    > {
        let reputation = Arc::new(MockReputationManager::new(THROTTLE_SLACK, BAN_SLACK));
        let mut simulator = MockSimulator::new();
        let mut prechecker = MockPrechecker::new();
        let mut entrypoint = MockEntryPoint::new();
        let mut paymaster_helper = MockPaymasterHelper::new();
        prechecker.expect_update_fees().returning(|| {
            Ok((
                GasFees {
                    max_fee_per_gas: 0.into(),
                    max_priority_fee_per_gas: 0.into(),
                },
                0.into(),
            ))
        });

        paymaster_helper.expect_get_deposit_info().returning(|_| {
            Ok(DepositInfo {
                deposit: 1000,
                staked: true,
                stake: 10000,
                unstake_delay_sec: 100,
                withdraw_time: 10,
            })
        });

        entrypoint
            .expect_balance_of()
            .returning(|_, _| Ok(U256::from(1000)));

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
                        Err(SimulationError {
                            violation_error: ViolationError::Violations(vec![error.clone()]),
                            entity_infos: None,
                        })
                    } else {
                        Ok(SimulationResult {
                            account_is_staked: op.staked,
                            block_number: Some(0),
                            valid_time_range: op.valid_time_range,
                            entity_infos: EntityInfos {
                                sender: EntityInfo {
                                    address: op.op.sender,
                                    is_staked: false,
                                },
                                ..EntityInfos::default()
                            },
                            ..SimulationResult::default()
                        })
                    }
                });
        }

        let args = PoolConfig {
            entry_point: Address::random(),
            chain_id: 1,
            min_replacement_fee_increase_percentage: 10,
            max_size_of_pool_bytes: 10000,
            blocklist: None,
            allowlist: None,
            precheck_settings: PrecheckSettings::default(),
            sim_settings: SimulationSettings::default(),
            mempool_channel_configs: HashMap::new(),
            num_shards: 1,
            same_sender_mempool_count: 4,
            throttled_entity_mempool_count: 4,
            throttled_entity_live_blocks: 10,
        };
        let (event_sender, _) = broadcast::channel(4);

        UoPool::new(
            args,
            reputation,
            event_sender,
            prechecker,
            simulator,
            entrypoint,
            paymaster_helper,
        )
    }

    async fn create_pool_insert_ops(
        ops: Vec<OpWithErrors>,
    ) -> (
        UoPool<
            impl ReputationManager,
            impl Prechecker,
            impl Simulator,
            impl EntryPoint,
            impl PaymasterHelper,
        >,
        Vec<UserOperation>,
    ) {
        let uos = ops.iter().map(|op| op.op.clone()).collect::<Vec<_>>();
        let pool = create_pool(ops);
        for op in &uos {
            let _ = pool.add_operation(OperationOrigin::Local, op.clone()).await;
        }
        (pool, uos)
    }

    fn create_op(
        sender: Address,
        nonce: usize,
        max_fee_per_gas: usize,
        paymaster: Option<Address>,
    ) -> OpWithErrors {
        let mut paymaster_and_data = Bytes::new();

        if let Some(paymaster) = paymaster {
            paymaster_and_data = paymaster.to_fixed_bytes().into();
        }

        OpWithErrors {
            op: UserOperation {
                sender,
                nonce: nonce.into(),
                max_fee_per_gas: max_fee_per_gas.into(),
                paymaster_and_data,
                ..UserOperation::default()
            },
            valid_time_range: ValidTimeRange::default(),
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
            valid_time_range: ValidTimeRange::default(),
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
        bundle_invalidation_ops_seen_staked_penalty: u64,
        bundle_invalidation_ops_seen_unstaked_penalty: u64,
        same_unstaked_entity_mempool_count: u64,
        inclusion_rate_factor: u64,
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

        fn handle_srep_050_penalty(&self, address: Address) {
            *self.counts.write().seen.entry(address).or_default() =
                self.bundle_invalidation_ops_seen_staked_penalty;
        }

        fn handle_urep_030_penalty(&self, address: Address) {
            *self.counts.write().seen.entry(address).or_default() +=
                self.bundle_invalidation_ops_seen_unstaked_penalty;
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
                })
                .collect()
        }

        fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64) {
            let mut counts = self.counts.write();
            counts.seen.insert(address, ops_seen);
            counts.included.insert(address, ops_included);
        }

        fn get_ops_allowed(&self, address: Address) -> u64 {
            let counts = self.counts.read();
            let seen = *counts.seen.get(&address).unwrap_or(&0);
            let included = *counts.included.get(&address).unwrap_or(&0);
            let inclusion_based_count = if seen == 0 {
                // make sure we aren't dividing by 0
                0
            } else {
                included * self.inclusion_rate_factor / seen + std::cmp::min(included, 10_000)
            };

            // return ops allowed, as defined by UREP-020
            self.same_unstaked_entity_mempool_count + inclusion_based_count
        }

        fn clear(&self) {
            self.counts.write().seen.clear();
            self.counts.write().included.clear();
        }
    }
}
