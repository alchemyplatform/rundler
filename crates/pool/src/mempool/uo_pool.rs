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

use std::{collections::HashSet, sync::Arc, time::Instant};

use alloy_primitives::{utils::format_units, Address, Bytes, B256, U256};
use anyhow::Context;
use futures::TryFutureExt;
use itertools::Itertools;
use metrics::{Counter, Gauge, Histogram};
use metrics_derive::Metrics;
use parking_lot::RwLock;
use rundler_provider::{
    DAGasOracleSync, EvmProvider, ProvidersWithEntryPointT, SimulationProvider, StateOverride,
};
use rundler_sim::{FeeUpdate, MempoolConfig, Prechecker, Simulator};
use rundler_types::{
    pool::{
        MempoolError, PaymasterMetadata, PoolOperation, Reputation, ReputationStatus, StakeStatus,
    },
    Entity, EntityUpdate, EntityUpdateType, EntryPointVersion, UserOperation, UserOperationId,
    UserOperationPermissions, UserOperationVariant,
};
use rundler_utils::emit::WithEntryPoint;
use tokio::sync::broadcast;
use tonic::async_trait;
use tracing::{info, instrument};

use super::{
    paymaster::PaymasterTracker, pool::PoolInner, reputation::AddressReputation, Mempool,
    MempoolResult, OperationOrigin, PoolConfig,
};
use crate::{
    chain::ChainUpdate,
    emit::{EntityReputation, EntityStatus, EntitySummary, OpPoolEvent, OpRemovalReason},
};

/// User Operation Mempool
///
/// Wrapper around a pool object that implements thread-safety
/// via a RwLock. Safe to call from multiple threads. Methods
/// block on write locks.
pub(crate) struct UoPool<UP: UoPoolProvidersT, EP: ProvidersWithEntryPointT> {
    config: PoolConfig,
    ep_providers: EP,
    pool_providers: UP,
    state: RwLock<UoPoolState<EP::DAGasOracleSync>>,
    paymaster: PaymasterTracker<EP::EntryPoint>,
    reputation: Arc<AddressReputation>,
    event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
    ep_specific_metrics: UoPoolMetricsEPSpecific,
    metrics: UoPoolMetrics,
    mempool_config: MempoolConfig,
}

struct UoPoolState<D> {
    pool: PoolInner<D>,
    throttled_ops: HashSet<B256>,
    block_number: u64,
    block_hash: B256,
    gas_fees: FeeUpdate,
}

impl<UP, EP> UoPool<UP, EP>
where
    EP: ProvidersWithEntryPointT,
    UP: UoPoolProvidersT,
{
    pub(crate) fn new(
        config: PoolConfig,
        ep_providers: EP,
        pool_providers: UP,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        paymaster: PaymasterTracker<EP::EntryPoint>,
        reputation: Arc<AddressReputation>,
        mempool_config: MempoolConfig,
    ) -> Self {
        let ep = config.entry_point.to_string();
        Self {
            state: RwLock::new(UoPoolState {
                pool: PoolInner::new(
                    config.clone().into(),
                    ep_providers.da_gas_oracle_sync().clone(),
                    event_sender.clone(),
                ),
                throttled_ops: HashSet::new(),
                block_number: 0,
                block_hash: B256::ZERO,
                gas_fees: FeeUpdate::default(),
            }),
            reputation,
            paymaster,
            event_sender,
            config,
            ep_specific_metrics: UoPoolMetricsEPSpecific::new_with_labels(&[("entry_point", ep)]),
            metrics: UoPoolMetrics::default(),
            ep_providers,
            pool_providers,
            mempool_config,
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
        self.emit(OpPoolEvent::ThrottledEntity { entity });

        for op_hash in removed_op_hashes {
            self.emit(OpPoolEvent::RemovedOp {
                op_hash,
                reason: OpRemovalReason::EntityThrottled { entity },
            })
        }
        self.ep_specific_metrics
            .removed_operations
            .increment(count as u64);
        self.ep_specific_metrics.removed_entities.increment(1);
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
        self.ep_specific_metrics
            .removed_operations
            .increment(count as u64);
        self.ep_specific_metrics.removed_entities.increment(1);
    }

    async fn check_execution_gas_limit_efficiency(
        &self,
        op: UserOperationVariant,
        block_hash: B256,
    ) -> MempoolResult<()> {
        // Check call gas limit efficiency only if needed
        if self.config.gas_limit_efficiency_reject_threshold > 0.0 {
            // Node clients set base_fee to 0 during eth_call.
            // Geth: https://github.com/ethereum/go-ethereum/blob/a5fe7353cff959d6fcfcdd9593de19056edb9bdb/internal/ethapi/api.go#L1202
            // Reth: https://github.com/paradigmxyz/reth/blob/4d3b35dbd24c3a5c6b1a4f7bd86b1451e8efafcc/crates/rpc/rpc-eth-api/src/helpers/call.rs#L1098
            // Arb-geth: https://github.com/OffchainLabs/go-ethereum/blob/54adef6e3fbea263e770c578047fd38842b8e17f/internal/ethapi/api.go#L1126
            let gas_price = op.gas_price(0);

            if gas_price == 0 {
                // Can't calculate efficiency without gas price, fail open.
                return Ok(());
            }

            let execution_gas_limit = match &op {
                // For v0.6 only use the call gas limit as post op gas limit is always set to VGL*2
                // whether or not the UO is using a post op. Can cause the efficiency check to fail.
                UserOperationVariant::V0_6(op) => op.call_gas_limit(),
                UserOperationVariant::V0_7(op) => op.execution_gas_limit(),
            };
            if execution_gas_limit == 0 {
                return Ok(()); // No call gas limit, not useful, but not a failure here.
            }

            let sim_result = self
                .ep_providers
                .entry_point()
                .simulate_handle_op(
                    op.into(),
                    Address::ZERO,
                    Bytes::new(),
                    block_hash.into(),
                    StateOverride::default(),
                )
                .await;
            match sim_result {
                Err(e) => {
                    tracing::error!("Failed to simulate handle op for gas limit efficiency check, failing open: {:?}", e);
                }
                Ok(Err(e)) => {
                    tracing::debug!(
                        "Validation error during gas limit efficiency check, failing open: {:?}",
                        e
                    );
                }
                Ok(Ok(execution_res)) => {
                    let total_gas_used: u128 = (execution_res.paid / U256::from(gas_price))
                        .try_into()
                        .context("total gas used should fit in u128")?;

                    let execution_gas_used = total_gas_used - execution_res.pre_op_gas;

                    let execution_gas_efficiency =
                        execution_gas_used as f32 / execution_gas_limit as f32;
                    if execution_gas_efficiency < self.config.gas_limit_efficiency_reject_threshold
                    {
                        return Err(MempoolError::ExecutionGasLimitEfficiencyTooLow(
                            self.config.gas_limit_efficiency_reject_threshold,
                            execution_gas_efficiency,
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<UP, EP> Mempool for UoPool<UP, EP>
where
    EP: ProvidersWithEntryPointT,
    UP: UoPoolProvidersT,
{
    #[instrument(skip_all)]
    async fn on_chain_update(&self, update: &ChainUpdate) {
        let deduped_ops = update.deduped_ops();
        let mined_ops = deduped_ops
            .mined_ops
            .iter()
            .filter(|op| op.entry_point == self.config.entry_point);

        let entity_balance_updates = update.entity_balance_updates.iter().filter_map(|u| {
            if u.entrypoint == self.config.entry_point {
                Some(u.address)
            } else {
                None
            }
        });

        let unmined_entity_balance_updates = update
            .unmined_entity_balance_updates
            .iter()
            .filter_map(|u| {
                if u.entrypoint == self.config.entry_point {
                    Some(u.address)
                } else {
                    None
                }
            });

        let unmined_ops = deduped_ops
            .unmined_ops
            .iter()
            .filter(|op| op.entry_point == self.config.entry_point);
        let mut mined_op_count = 0;
        let mut unmined_op_count = 0;

        for op in mined_ops {
            if op.entry_point != self.config.entry_point {
                continue;
            }
            self.paymaster.update_paymaster_balance_from_mined_op(op);

            // Remove throttled ops that were included in the block
            self.state.write().throttled_ops.remove(&op.hash);

            if let Some(pool_op) = self
                .state
                .write()
                .pool
                .mine_operation(op, update.latest_block_number)
            {
                // Only account for an entity once
                for entity_addr in pool_op.entities().map(|e| e.address).unique() {
                    self.reputation.add_included(entity_addr);
                }
                mined_op_count += 1;
            }
        }

        for op in unmined_ops {
            if op.entry_point != self.config.entry_point {
                continue;
            }

            if let Some(paymaster) = op.paymaster {
                self.paymaster
                    .unmine_actual_cost(&paymaster, op.actual_gas_cost);
            }

            let pool_op = self.state.write().pool.unmine_operation(op);

            if let Some(po) = pool_op {
                for entity_addr in po.entities().map(|e| e.address).unique() {
                    self.reputation.dec_included(entity_addr);
                }

                unmined_op_count += 1;
                let _ = self.paymaster.add_or_update_balance(&po).await;
            }
        }

        // Update paymaster balances AFTER updating the pool to reset confirmed balances if needed.
        if update.reorg_larger_than_history {
            if let Err(e) = self.reset_confirmed_paymaster_balances().await {
                tracing::error!("Failed to reset confirmed paymaster balances: {:?}", e);
            }
        } else {
            let addresses = entity_balance_updates
                .chain(unmined_entity_balance_updates)
                .unique()
                .collect::<Vec<_>>();
            if !addresses.is_empty() {
                if let Err(e) = self
                    .paymaster
                    .reset_confirmed_balances_for(&addresses)
                    .await
                {
                    tracing::error!("Failed to reset confirmed paymaster balances: {:?}", e);
                }
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
        let ops_seen: f64 = (mined_op_count as isize - unmined_op_count as isize) as f64;
        self.ep_specific_metrics.ops_seen.increment(ops_seen);
        self.ep_specific_metrics
            .unmined_operations
            .increment(unmined_op_count);

        // update required bundle fees and update metrics
        match self.pool_providers.prechecker().update_fees().await {
            Ok(fees) => {
                let max_fee = match format_units(fees.bundle_fees.max_fee_per_gas, "gwei") {
                    Ok(s) => s.parse::<f64>().unwrap_or_default(),
                    Err(_) => 0.0,
                };
                self.metrics.current_max_fee_gwei.set(max_fee);

                let max_priority_fee =
                    match format_units(fees.bundle_fees.max_priority_fee_per_gas, "gwei") {
                        Ok(s) => s.parse::<f64>().unwrap_or_default(),
                        Err(_) => 0.0,
                    };
                self.metrics
                    .current_max_priority_fee_gwei
                    .set(max_priority_fee);

                let base_fee_f64 = match format_units(fees.base_fee, "gwei") {
                    Ok(s) => s.parse::<f64>().unwrap_or_default(),
                    Err(_) => 0.0,
                };
                self.metrics.current_base_fee.set(base_fee_f64);

                // cache for the next update
                {
                    let mut state = self.state.write();
                    state.block_number = update.latest_block_number;
                    state.block_hash = update.latest_block_hash;
                    state.gas_fees = fees;
                }
            }
            Err(e) => {
                tracing::error!("Failed to update fees: {:?}", e);
                {
                    let mut state = self.state.write();
                    state.block_number = update.latest_block_number;
                }
            }
        }

        let da_block_data = if self.config.da_gas_tracking_enabled
            && self.ep_providers.da_gas_oracle_sync().is_some()
        {
            let da_gas_oracle = self.ep_providers.da_gas_oracle_sync().as_ref().unwrap();
            match da_gas_oracle
                .da_block_data(update.latest_block_hash.into())
                .await
            {
                Ok(da_block_data) => Some(da_block_data),
                Err(e) => {
                    tracing::error!("Failed to get da block data, skipping da tracking: {:?}", e);
                    None
                }
            }
        } else {
            None
        };

        let start = Instant::now();
        {
            let mut state = self.state.write();
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

            // pool maintenance
            let gas_fees = state.gas_fees;
            state.pool.do_maintenance(
                update.latest_block_number,
                update.latest_block_timestamp,
                da_block_data.as_ref(),
                gas_fees,
            );
        }
        let maintenance_time = start.elapsed();
        tracing::debug!(
            "Pool maintenance took {:?} µs",
            maintenance_time.as_micros()
        );
        self.ep_specific_metrics
            .maintenance_time
            .record(maintenance_time.as_micros() as f64);
    }

    fn entry_point_version(&self) -> EntryPointVersion {
        self.config.entry_point_version
    }

    #[instrument(skip_all)]
    async fn add_operation(
        &self,
        origin: OperationOrigin,
        mut op: UserOperationVariant,
        perms: UserOperationPermissions,
    ) -> MempoolResult<B256> {
        // Initial state checks
        let to_replace = {
            let state = self.state.read();

            // Check if op violates the STO-040 spec rule
            state.pool.check_multiple_roles_violation(&op)?;

            // Check if op use 7702
            state.pool.check_eip7702(&op)?;

            // Check if op is already known or replacing another, and if so, ensure its fees are high enough
            state
                .pool
                .check_replacement(&op)?
                .and_then(|r| self.state.read().pool.get_operation_by_hash(r))
        };

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

        // NOTE: We get the latest block from the provider here to avoid a race condition
        // where the pool is still processing the previous block, but the user may have been
        // notified of a new block.
        //
        // This doesn't clear all race conditions, as the pool may need to update its state before
        // a UO can be valid, i.e. for replacement.
        let (block_hash, block_number) = self
            .ep_providers
            .evm()
            .get_latest_block_hash_and_number()
            .await
            .map_err(anyhow::Error::from)?;

        // check if paymaster is present and exists in pool
        // this is optimistic and could potentially lead to
        // multiple user operations call this before they are
        // added to the pool and can lead to an overdraft
        self.paymaster.check_operation_cost(&op).await?;

        // If using an aggregator, transform with calculated signature
        if let Some(aggregator) = op.aggregator() {
            let Some(agg) = self.config.chain_spec.get_signature_aggregator(&aggregator) else {
                return Err(MempoolError::AggregatorError(format!(
                    "Unsupported aggregator {:?}",
                    aggregator
                )));
            };

            let signature = match agg.validate_user_op_signature(&op).await {
                Ok(sig) => sig,
                Err(e) => {
                    return Err(MempoolError::AggregatorError(format!(
                        "Error validating signature: {:?}",
                        e
                    )));
                }
            };

            op = op.transform_for_aggregator(
                &self.config.chain_spec,
                aggregator,
                agg.costs().clone(),
                signature,
            );
        }

        let versioned_op: UP::UO = op.clone().into();

        // Prechecks
        let precheck_ret = self
            .pool_providers
            .prechecker()
            .check(&versioned_op, &perms, block_hash.into())
            .await?;

        // Only let ops with successful simulations through
        // Run simulation and call gas limit efficiency check in parallel
        let sim_fut = self
            .pool_providers
            .simulator()
            .simulate_validation(versioned_op, perms.trusted, block_hash, None)
            .map_err(Into::into);
        let execution_gas_check_future =
            self.check_execution_gas_limit_efficiency(op.clone(), block_hash);
        let (sim_result, _) = tokio::try_join!(sim_fut, execution_gas_check_future)?;

        // Check if op has more than the maximum allowed expected storage slots
        let expected_slots = sim_result.expected_storage.num_slots();
        if expected_slots > self.config.max_expected_storage_slots {
            return Err(MempoolError::TooManyExpectedStorageSlots(
                self.config.max_expected_storage_slots,
                expected_slots,
            ));
        }

        // Check if op violates the STO-041 spec rule
        self.state
            .read()
            .pool
            .check_associated_storage(&sim_result.associated_addresses, &op)?;

        // Check pre op gas limit efficiency
        let pre_op_gas_efficiency = sim_result.pre_op_gas as f32 / op.pre_op_gas_limit() as f32;
        if pre_op_gas_efficiency < self.config.gas_limit_efficiency_reject_threshold {
            return Err(MempoolError::PreOpGasLimitEfficiencyTooLow(
                self.config.gas_limit_efficiency_reject_threshold,
                pre_op_gas_efficiency,
            ));
        }

        let filter_id = self.mempool_config.match_filter(&op);
        let valid_time_range = sim_result.valid_time_range;
        let pool_op = PoolOperation {
            uo: op,
            entry_point: self.config.entry_point,
            aggregator: None,
            valid_time_range,
            expected_code_hash: sim_result.code_hash,
            sim_block_hash: block_hash,
            sim_block_number: block_number,
            account_is_staked: sim_result.account_is_staked,
            entity_infos: sim_result.entity_infos,
            da_gas_data: precheck_ret.da_gas_data,
            filter_id,
            perms,
        };

        // Check sender count in mempool. If sender has too many operations, must be staked
        {
            let sender_allowed_count = pool_op
                .perms
                .max_allowed_in_pool_for_sender
                .unwrap_or(self.config.same_sender_mempool_count);

            let state = self.state.read();
            if !pool_op.account_is_staked
                && to_replace.is_none()
                && state.pool.address_count(&pool_op.uo.sender()) >= sender_allowed_count
            {
                return Err(MempoolError::MaxOperationsReached(
                    sender_allowed_count,
                    Entity::account(pool_op.uo.sender()),
                ));
            }

            // Check unstaked non-sender entity counts in the mempool
            for entity in pool_op
                .unstaked_entities()
                .unique()
                .filter(|e| e.address != pool_op.entity_infos.sender.address())
            {
                let mut ops_allowed = self.reputation.get_ops_allowed(entity.address);
                if let Some(to_replace) = &to_replace {
                    if to_replace.entities().contains(&entity) {
                        ops_allowed += 1;
                    }
                }

                if state.pool.address_count(&entity.address) >= ops_allowed as usize {
                    return Err(MempoolError::MaxOperationsReached(
                        ops_allowed as usize,
                        entity,
                    ));
                }
            }
        }

        // Add op to pool
        let hash = {
            let mut state = self.state.write();
            let base_fee = state.gas_fees.base_fee;
            let hash = state.pool.add_operation(
                pool_op.clone(),
                base_fee,
                precheck_ret.required_pre_verification_gas,
            )?;

            if throttled {
                state.throttled_ops.insert(hash);
            }
            hash
        };

        // Add op cost to pending paymaster balance
        // once the operation has been added to the pool
        self.paymaster.add_or_update_balance(&pool_op).await?;

        // Update reputation, handling replacement if needed
        if let Some(to_replace) = to_replace {
            to_replace.entities().unique().for_each(|e| {
                self.reputation.dec_seen(e.address);
            });
        }
        pool_op.entities().unique().for_each(|e| {
            self.reputation.add_seen(e.address);
            if self.reputation.status(e.address) == ReputationStatus::Throttled {
                self.throttle_entity(e);
            } else if self.reputation.status(e.address) == ReputationStatus::Banned {
                self.remove_entity(e);
            }
        });

        // Emit event
        let op_hash = pool_op.uo.hash();
        self.emit(OpPoolEvent::ReceivedOp {
            op_hash,
            op: pool_op.uo,
            block_number: pool_op.sim_block_number,
            origin,
            valid_after: pool_op.valid_time_range.valid_after,
            valid_until: pool_op.valid_time_range.valid_until,
            entities: entity_summary,
        });

        Ok(hash)
    }

    fn remove_operations(&self, hashes: &[B256]) {
        let mut count: u64 = 0;
        let mut removed_hashes = vec![];
        {
            let mut state = self.state.write();
            for hash in hashes {
                if let Some(op) = state.pool.remove_operation_by_hash(*hash) {
                    self.paymaster.remove_operation(&op.uo.id());
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
        self.ep_specific_metrics.removed_operations.increment(count);
    }

    fn remove_op_by_id(&self, id: &UserOperationId) -> MempoolResult<Option<B256>> {
        // Check for the operation in the pool and its age
        let po = {
            let state = self.state.read();
            match state.pool.get_operation_by_id(id) {
                Some(po) => {
                    if po.sim_block_number + self.config.drop_min_num_blocks > state.block_number {
                        return Err(MempoolError::OperationDropTooSoon(
                            po.sim_block_number,
                            state.block_number,
                            self.config.drop_min_num_blocks,
                        ));
                    }
                    po
                }
                None => return Ok(None),
            }
        };

        let hash = po.uo.hash();

        // This can return none if the operation was removed by another thread
        if self
            .state
            .write()
            .pool
            .remove_operation_by_hash(hash)
            .is_none()
        {
            return Ok(None);
        }

        self.emit(OpPoolEvent::RemovedOp {
            op_hash: hash,
            reason: OpRemovalReason::Requested,
        });
        Ok(Some(hash))
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
            EntityUpdateType::PaymasterOpsSeenDecrement => {
                assert!(
                    entity.is_paymaster(),
                    "Attempted to add EREP-015 paymaster amendment for non-paymaster entity"
                );
                self.reputation.handle_erep_015_amendment(
                    entity.address,
                    update
                        .value
                        .expect("PaymasterOpsSeenDecrement must carry an explicit decrement value"),
                );
            }
        }

        if self.reputation.status(entity.address) == ReputationStatus::Banned {
            self.remove_entity(entity);
        } else if self.reputation.status(entity.address) == ReputationStatus::Throttled {
            self.throttle_entity(entity);
        }
    }

    fn best_operations(
        &self,
        max: usize,
        filter_id: Option<String>,
    ) -> MempoolResult<Vec<Arc<PoolOperation>>> {
        // get the best operations from the pool
        let state = self.state.read();
        let ordered_ops = state.pool.best_operations();

        Ok(ordered_ops
            .into_iter()
            .filter(|op| filter_id == op.filter_id)
            .take(max)
            .collect())
    }

    fn all_operations(&self, max: usize) -> Vec<Arc<PoolOperation>> {
        self.state.read().pool.all_operations().take(max).collect()
    }

    fn get_user_operation_by_hash(&self, hash: B256) -> Option<Arc<PoolOperation>> {
        self.state.read().pool.get_operation_by_hash(hash)
    }

    // DEBUG METHODS

    fn clear_state(&self, clear_mempool: bool, clear_paymaster: bool, clear_reputation: bool) {
        if clear_mempool {
            self.state.write().pool.clear();
        }

        if clear_paymaster {
            self.paymaster.clear();
        }

        if clear_reputation {
            self.reputation.clear()
        }
    }

    fn dump_reputation(&self) -> Vec<Reputation> {
        self.reputation.dump_reputation()
    }

    fn dump_paymaster_balances(&self) -> Vec<PaymasterMetadata> {
        self.paymaster.dump_paymaster_metadata()
    }

    fn get_reputation_status(&self, address: Address) -> ReputationStatus {
        self.reputation.status(address)
    }

    fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64) {
        self.reputation
            .set_reputation(address, ops_seen, ops_included)
    }

    #[instrument(skip_all)]
    async fn get_stake_status(&self, address: Address) -> MempoolResult<StakeStatus> {
        self.paymaster.get_stake_status(address).await
    }

    #[instrument(skip_all)]
    async fn reset_confirmed_paymaster_balances(&self) -> MempoolResult<()> {
        self.paymaster.reset_confirmed_balances().await
    }

    fn set_tracking(&self, paymaster: bool, reputation: bool) {
        self.paymaster.set_tracking(paymaster);
        self.reputation.set_tracking(reputation);
    }
}

// Type erasure for UoPool providers
pub(crate) trait UoPoolProvidersT: Send + Sync {
    type UO: UserOperation + From<UserOperationVariant>;
    type Prechecker: Prechecker<UO = Self::UO>;
    type Simulator: Simulator<UO = Self::UO>;

    fn prechecker(&self) -> &Self::Prechecker;

    fn simulator(&self) -> &Self::Simulator;
}

pub(crate) struct UoPoolProviders<S, P> {
    simulator: S,
    prechecker: P,
}

impl<S, P> UoPoolProviders<S, P> {
    pub(crate) fn new(simulator: S, prechecker: P) -> Self {
        Self {
            simulator,
            prechecker,
        }
    }
}

impl<S, P> UoPoolProvidersT for UoPoolProviders<S, P>
where
    S: Simulator,
    S::UO: UserOperation + From<UserOperationVariant>,
    P: Prechecker<UO = S::UO>,
{
    type UO = S::UO;
    type Prechecker = P;
    type Simulator = S;

    fn prechecker(&self) -> &Self::Prechecker {
        &self.prechecker
    }

    fn simulator(&self) -> &Self::Simulator {
        &self.simulator
    }
}

#[derive(Metrics)]
#[metrics(scope = "op_pool")]
struct UoPoolMetricsEPSpecific {
    #[metric(describe = "the number of ops seen.")]
    ops_seen: Gauge,
    #[metric(describe = "the count of unmined ops.")]
    unmined_operations: Counter,
    #[metric(describe = "the count of removed ops.")]
    removed_operations: Counter,
    #[metric(describe = "the count of removed entities.")]
    removed_entities: Counter,
    #[metric(describe = "time to run pool maintenance in µs.")]
    maintenance_time: Histogram,
}

#[derive(Metrics)]
#[metrics(scope = "op_pool")]
struct UoPoolMetrics {
    #[metric(describe = "the maximum fee in Gwei.")]
    current_max_fee_gwei: Gauge,
    #[metric(describe = "the maximum priority fee in Gwei.")]
    current_max_priority_fee_gwei: Gauge,
    #[metric(describe = "the base fee of current block.")]
    current_base_fee: Gauge,
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr, vec};

    use alloy_primitives::{address, bytes, uint, Bytes};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use mockall::Sequence;
    use rundler_provider::{
        DepositInfo, ExecutionResult, MockDAGasOracleSync, MockEntryPointV0_6, MockEvmProvider,
        ProvidersWithEntryPoint,
    };
    use rundler_sim::{
        MockPrechecker, MockSimulator, PrecheckError, PrecheckReturn, PrecheckSettings,
        SimulationError, SimulationResult, SimulationSettings, ViolationError,
    };
    use rundler_types::{
        aggregator::{
            AggregatorCosts, MockSignatureAggregator, SignatureAggregator, SignatureAggregatorError,
        },
        authorization::Eip7702Auth,
        chain::{ChainSpec, ContractRegistry},
        da::DAGasData,
        pool::{PrecheckViolation, SimulationViolation},
        v0_6::{UserOperationBuilder, UserOperationRequiredFields},
        EntityInfo, EntityInfos, EntityType, EntryPointVersion,
        UserOperation as UserOperationTrait, ValidTimeRange,
    };

    use super::*;
    use crate::{
        chain::{BalanceUpdate, MinedOp},
        mempool::{PaymasterConfig, ReputationParams},
    };
    const THROTTLE_SLACK: u64 = 5;
    const BAN_SLACK: u64 = 10;

    #[tokio::test]
    async fn add_single_op() {
        let op = create_op(Address::random(), 0, 0, None);
        let ops = vec![op.clone()];
        let uos = vec![op.op.clone()];
        let pool = create_pool(ops);

        let hash = pool
            .add_operation(OperationOrigin::Local, op.op, default_perms())
            .await
            .unwrap();
        check_ops(pool.best_operations(1, None).unwrap(), uos);
        pool.remove_operations(&[hash]);
        assert_eq!(pool.best_operations(1, None).unwrap(), vec![]);
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
                .add_operation(OperationOrigin::Local, op.clone(), default_perms())
                .await
                .unwrap();
            hashes.push(hash);
        }
        check_ops(pool.best_operations(3, None).unwrap(), uos);
        pool.remove_operations(&hashes);
        assert_eq!(pool.best_operations(3, None).unwrap(), vec![]);
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
                .add_operation(OperationOrigin::Local, op.clone(), default_perms())
                .await
                .unwrap();
        }
        check_ops(pool.best_operations(3, None).unwrap(), uos);
        pool.clear_state(true, true, true);
        assert_eq!(pool.best_operations(3, None).unwrap(), vec![]);
    }

    #[tokio::test]
    async fn all_operations() {
        let ops = vec![
            create_op(Address::random(), 0, 3, None),
            create_op(Address::random(), 0, 2, None),
            create_op(Address::random(), 0, 1, None),
        ];
        let uos = ops.iter().map(|op| op.op.clone()).collect::<Vec<_>>();
        let pool = create_pool(ops);

        for op in &uos {
            let _ = pool
                .add_operation(OperationOrigin::Local, op.clone(), default_perms())
                .await
                .unwrap();
        }
        check_ops_unordered(&pool.all_operations(16), &uos);
    }

    #[tokio::test]
    async fn chain_update_mine() {
        let paymaster = Address::random();

        let mut entrypoint = MockEntryPointV0_6::new();
        // initial balance
        entrypoint
            .expect_balance_of()
            .returning(|_, _| Ok(U256::from(1000)));
        // after updates
        entrypoint
            .expect_get_balances()
            .returning(|_| Ok(vec![U256::from(1110)]));

        let (pool, uos) = create_pool_with_entrypoint_insert_ops(
            vec![
                create_op(Address::random(), 0, 3, None),
                create_op(Address::random(), 0, 2, None),
                create_op(Address::random(), 0, 1, Some(paymaster)),
            ],
            entrypoint,
        )
        .await;
        check_ops(pool.best_operations(3, None).unwrap(), uos.clone());

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: B256::random(),
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: pool.config.entry_point,
                hash: uos[0].hash(),
                sender: uos[0].sender(),
                nonce: uos[0].nonce(),
                actual_gas_cost: U256::ZERO,
                paymaster: None,
            }],
            unmined_ops: vec![],
            entity_balance_updates: vec![BalanceUpdate {
                address: paymaster,
                amount: U256::from(100),
                entrypoint: pool.config.entry_point,
                is_addition: true,
            }],
            unmined_entity_balance_updates: vec![BalanceUpdate {
                address: paymaster,
                amount: U256::from(10),
                entrypoint: pool.config.entry_point,
                is_addition: false,
            }],
            address_updates: vec![],
            reorg_larger_than_history: false,
        })
        .await;

        check_ops(pool.best_operations(3, None).unwrap(), uos[1..].to_vec());

        let paymaster_balance = pool.paymaster.paymaster_balance(paymaster).await.unwrap();
        assert_eq!(paymaster_balance.confirmed_balance, U256::from(1110));
    }

    #[tokio::test]
    async fn chain_update_mine_unmine() {
        let paymaster = Address::random();
        let paymaster_and_data = paymaster.to_vec().into();

        let base_required = UserOperationRequiredFields {
            max_fee_per_gas: 1,
            call_gas_limit: 10,
            verification_gas_limit: 10,
            pre_verification_gas: 10,
            paymaster_and_data,
            ..Default::default()
        };

        let ops = vec![
            create_op_from_required(UserOperationRequiredFields {
                sender: Address::random(),
                nonce: U256::from(3),
                ..base_required.clone()
            }),
            create_op_from_required(UserOperationRequiredFields {
                sender: Address::random(),
                nonce: U256::from(2),
                ..base_required.clone()
            }),
            create_op_from_required(UserOperationRequiredFields {
                sender: Address::random(),
                nonce: U256::from(1),
                ..base_required.clone()
            }),
        ];

        let mut entrypoint = MockEntryPointV0_6::new();
        // initial balance, pending = 850
        entrypoint
            .expect_balance_of()
            .returning(|_, _| Ok(U256::from(1000)));
        // after updates
        let mut seq = Sequence::new();
        // one UO mined with actual cost of 10, unmine deposit of 10, mine deposit 100
        // confirmed = 1000 - 10 - 10 + 100 = 1080. Pending = 1080 - 50*2 = 980
        entrypoint
            .expect_get_balances()
            .once()
            .in_sequence(&mut seq)
            .returning(|_| Ok(vec![U256::from(1080)]));
        // Unmine UO of 10, unmine deposit of 100
        // confirmed = 1080 + 10 - 100 = 990. Pending = 990 - 50*3 = 840
        entrypoint
            .expect_get_balances()
            .once()
            .in_sequence(&mut seq)
            .returning(|_| Ok(vec![U256::from(990)]));

        let (pool, uos) = create_pool_with_entrypoint_insert_ops(ops, entrypoint).await;
        let metadata = pool.paymaster.paymaster_balance(paymaster).await.unwrap();

        assert_eq!(metadata.pending_balance, U256::from(850));
        check_ops(pool.best_operations(3, None).unwrap(), uos.clone());

        // mine the first op with actual gas cost of 10
        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: B256::random(),
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: pool.config.entry_point,
                hash: uos[0].hash(),
                sender: uos[0].sender(),
                nonce: uos[0].nonce(),
                actual_gas_cost: U256::from(10),
                paymaster: Some(paymaster),
            }],
            unmined_ops: vec![],
            entity_balance_updates: vec![BalanceUpdate {
                address: paymaster,
                amount: U256::from(100),
                entrypoint: pool.config.entry_point,
                is_addition: true,
            }],
            unmined_entity_balance_updates: vec![BalanceUpdate {
                address: paymaster,
                amount: U256::from(10),
                entrypoint: pool.config.entry_point,
                is_addition: false,
            }],
            address_updates: vec![],
            reorg_larger_than_history: false,
        })
        .await;

        check_ops(
            pool.best_operations(3, None).unwrap(),
            uos.clone()[1..].to_vec(),
        );

        let metadata = pool.paymaster.paymaster_balance(paymaster).await.unwrap();
        assert_eq!(metadata.pending_balance, U256::from(980));

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: B256::random(),
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![],
            unmined_ops: vec![MinedOp {
                entry_point: pool.config.entry_point,
                hash: uos[0].hash(),
                sender: uos[0].sender(),
                nonce: uos[0].nonce(),
                actual_gas_cost: U256::from(10),
                paymaster: None,
            }],
            entity_balance_updates: vec![],
            unmined_entity_balance_updates: vec![BalanceUpdate {
                address: paymaster,
                amount: U256::from(100),
                entrypoint: pool.config.entry_point,
                is_addition: true,
            }],
            address_updates: vec![],
            reorg_larger_than_history: false,
        })
        .await;

        check_ops(pool.best_operations(3, None).unwrap(), uos);

        let metadata = pool.paymaster.paymaster_balance(paymaster).await.unwrap();
        assert_eq!(metadata.pending_balance, U256::from(840));
    }

    #[tokio::test]
    async fn chain_update_wrong_ep() {
        let (pool, uos) = create_pool_insert_ops(vec![
            create_op(Address::random(), 0, 3, None),
            create_op(Address::random(), 0, 2, None),
            create_op(Address::random(), 0, 1, None),
        ])
        .await;
        check_ops(pool.best_operations(3, None).unwrap(), uos.clone());

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: B256::random(),
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: Address::random(),
                hash: uos[0].hash(),
                sender: uos[0].sender(),
                nonce: uos[0].nonce(),
                actual_gas_cost: U256::ZERO,
                paymaster: None,
            }],
            unmined_ops: vec![],
            entity_balance_updates: vec![],
            unmined_entity_balance_updates: vec![],
            address_updates: vec![],
            reorg_larger_than_history: false,
        })
        .await;

        check_ops(pool.best_operations(3, None).unwrap(), uos);
    }

    #[tokio::test]
    async fn test_account_reputation() {
        let address = Address::random();
        let (pool, uos) = create_pool_insert_ops(vec![
            create_op_with_errors(address, 0, 2, None, None, true), // accept
            create_op_with_errors(address, 1, 2, None, None, true), // accept
            create_op_with_errors(address, 1, 2, None, None, true), // reject
        ])
        .await;
        // staked, so include all ops
        check_ops(pool.best_operations(3, None).unwrap(), uos[0..2].to_vec());

        let rep = pool.dump_reputation();
        assert_eq!(rep.len(), 1);
        assert_eq!(rep[0].address, address);
        assert_eq!(rep[0].ops_seen, 2); // 2 ops seen, 1 rejected at insert
        assert_eq!(rep[0].ops_included, 0); // No ops included yet

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 1,
            latest_block_hash: B256::random(),
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: pool.config.entry_point,
                hash: uos[0].hash(),
                sender: uos[0].sender(),
                nonce: uos[0].nonce(),
                actual_gas_cost: U256::ZERO,
                paymaster: None,
            }],
            unmined_ops: vec![],
            entity_balance_updates: vec![],
            unmined_entity_balance_updates: vec![],
            address_updates: vec![],
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

        let ops_seen = 100;
        let ops_included = ops_seen / 10 - THROTTLE_SLACK - 1;

        // Past throttle slack
        pool.set_reputation(address, ops_seen, ops_included);

        // Ops 0 through 3 should be included
        for uo in uos.iter().take(4) {
            pool.add_operation(OperationOrigin::Local, uo.clone(), default_perms())
                .await
                .unwrap();
        }

        check_ops(
            pool.best_operations(4, None).unwrap(),
            vec![
                uos[0].clone(),
                uos[1].clone(),
                uos[2].clone(),
                uos[3].clone(),
            ],
        );

        // Second op should be throttled
        let ret = pool
            .add_operation(OperationOrigin::Local, uos[4].clone(), default_perms())
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
            latest_block_hash: B256::random(),
            latest_block_timestamp: 0.into(),
            earliest_remembered_block_number: 0,
            reorg_depth: 0,
            mined_ops: vec![MinedOp {
                entry_point: pool.config.entry_point,
                hash: uos[0].hash(),
                sender: uos[0].sender(),
                nonce: uos[0].nonce(),
                actual_gas_cost: U256::ZERO,
                paymaster: None,
            }],
            entity_balance_updates: vec![],
            unmined_entity_balance_updates: vec![],
            unmined_ops: vec![],
            address_updates: vec![],
            reorg_larger_than_history: false,
        })
        .await;

        // Second op should be included
        pool.add_operation(OperationOrigin::Local, uos[4].clone(), default_perms())
            .await
            .unwrap();
        check_ops(
            pool.best_operations(4, None).unwrap(),
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

        let ops_seen = 1000;
        let ops_included = ops_seen / 10 - BAN_SLACK - 1;
        pool.set_reputation(address, ops_seen, ops_included);

        // First op should be banned
        let ret = pool
            .add_operation(OperationOrigin::Local, uo.clone(), default_perms())
            .await;
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
        let op = create_op_from_required(UserOperationRequiredFields {
            sender: Address::random(),
            nonce: U256::from(0),
            max_fee_per_gas: 1,
            call_gas_limit: 1000,
            verification_gas_limit: 1000,
            pre_verification_gas: 1000,
            paymaster_and_data: paymaster.to_vec().into(),
            ..Default::default()
        });

        let mut entrypoint = MockEntryPointV0_6::new();
        entrypoint
            .expect_balance_of()
            .returning(|_, _| Ok(U256::from(1000)));

        let uo = op.op.clone();
        let pool = create_pool_with_entry_point(vec![op], entrypoint);

        let ret = pool
            .add_operation(OperationOrigin::Local, uo.clone(), default_perms())
            .await
            .unwrap_err();

        assert!(matches!(ret, MempoolError::PaymasterBalanceTooLow(_, _)));
    }

    #[tokio::test]
    async fn precheck_error() {
        let sender = Address::random();
        let op = create_op_with_errors(
            sender,
            0,
            0,
            Some(PrecheckViolation::SenderIsNotContractAndNoInitCode(sender)),
            None,
            false,
        );
        let ops = vec![op.clone()];
        let pool = create_pool(ops);

        match pool
            .add_operation(OperationOrigin::Local, op.op, default_perms())
            .await
        {
            Err(MempoolError::PrecheckViolation(
                PrecheckViolation::SenderIsNotContractAndNoInitCode(_),
            )) => {}
            _ => panic!("Expected InitCodeTooShort error"),
        }
        assert_eq!(pool.best_operations(1, None).unwrap(), vec![]);
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

        match pool
            .add_operation(OperationOrigin::Local, op.op, default_perms())
            .await
        {
            Err(MempoolError::SimulationViolation(SimulationViolation::DidNotRevert)) => {}
            _ => panic!("Expected DidNotRevert error"),
        }
        assert_eq!(pool.best_operations(1, None).unwrap(), vec![]);
    }

    #[tokio::test]
    async fn test_already_known() {
        let op = create_op(Address::random(), 0, 0, None);
        let pool = create_pool(vec![op.clone()]);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
            .await
            .unwrap();

        let err = pool
            .add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
            .await
            .unwrap_err();
        assert!(matches!(err, MempoolError::OperationAlreadyKnown));

        check_ops(pool.best_operations(1, None).unwrap(), vec![op.op]);
    }

    #[tokio::test]
    async fn test_replacement_underpriced() {
        let op = create_op(Address::random(), 0, 100, None);
        let pool = create_pool(vec![op.clone()]);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
            .await
            .unwrap();

        let new_max_fee = op.op.max_fee_per_gas() + 1;
        let uo = UserOperationBuilder::from_uo(op.op.clone().into(), &ChainSpec::default())
            .max_fee_per_gas(new_max_fee)
            .build();

        let err = pool
            .add_operation(OperationOrigin::Local, uo.into(), default_perms())
            .await
            .unwrap_err();

        assert!(matches!(err, MempoolError::ReplacementUnderpriced(_, _)));

        check_ops(pool.best_operations(1, None).unwrap(), vec![op.op]);
    }

    #[tokio::test]
    async fn test_stake_status_not_staked() {
        let mut entrypoint = MockEntryPointV0_6::new();
        entrypoint.expect_get_deposit_info().returning(|_| {
            Ok(DepositInfo {
                deposit: U256::from(1000),
                staked: true,
                stake: U256::from(10000),
                unstake_delay_sec: 100,
                withdraw_time: 10,
            })
        });
        let mut pool = create_pool_with_entry_point(vec![], entrypoint);

        pool.config.sim_settings.min_stake_value = U256::from(10001);
        pool.config.sim_settings.min_unstake_delay = 101;

        let status = pool.get_stake_status(Address::random()).await.unwrap();

        assert!(!status.is_staked);
    }

    #[tokio::test]
    async fn test_replacement() {
        let paymaster = Address::random();

        let mut op = create_op(Address::random(), 0, 5, Some(paymaster));
        let uo = UserOperationBuilder::from_uo(op.op.clone().into(), &ChainSpec::default())
            .call_gas_limit(10)
            .verification_gas_limit(10)
            .pre_verification_gas(10)
            .max_fee_per_gas(1)
            .build();
        op.op = uo.into();

        let mut entrypoint = MockEntryPointV0_6::new();
        entrypoint
            .expect_balance_of()
            .returning(|_, _| Ok(U256::from(1000)));
        let pool = create_pool_with_entry_point(vec![op.clone()], entrypoint);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
            .await
            .unwrap();

        let new_max_fee = op.op.max_fee_per_gas() + 1;
        let replacement: UserOperationVariant =
            UserOperationBuilder::from_uo(op.op.clone().into(), &ChainSpec::default())
                .max_fee_per_gas(new_max_fee)
                .build()
                .into();

        let _ = pool
            .add_operation(OperationOrigin::Local, replacement.clone(), default_perms())
            .await
            .unwrap();

        check_ops(pool.best_operations(1, None).unwrap(), vec![replacement]);

        let paymaster_balance = pool.paymaster.paymaster_balance(paymaster).await.unwrap();
        assert_eq!(paymaster_balance.pending_balance, U256::from(900));
        let rep = pool.dump_reputation();
        assert_eq!(rep.len(), 1);
        assert_eq!(rep[0].address, op.op.sender());
        assert_eq!(rep[0].ops_seen, 1);
        assert_eq!(rep[0].ops_included, 0);
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
            .add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
            .await
            .unwrap();

        check_ops(pool.best_operations(1, None).unwrap(), vec![op.op.clone()]);

        pool.on_chain_update(&ChainUpdate {
            latest_block_timestamp: 11.into(),
            ..ChainUpdate::default()
        })
        .await;

        check_ops(pool.best_operations(1, None).unwrap(), vec![]);
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash() {
        let op = create_op(Address::random(), 0, 0, None);
        let pool = create_pool(vec![op.clone()]);

        let hash = pool
            .add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
            .await
            .unwrap();

        let pool_op = pool.get_user_operation_by_hash(hash).unwrap();
        assert_eq!(pool_op.uo, op.op);
    }

    #[tokio::test]
    async fn test_remove_by_id_too_soon() {
        let op = create_op(Address::random(), 0, 0, None);
        let pool = create_pool(vec![op.clone()]);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
            .await
            .unwrap();

        assert!(matches!(
            pool.remove_op_by_id(&op.op.id()),
            Err(MempoolError::OperationDropTooSoon(_, _, _))
        ));
        check_ops(pool.best_operations(1, None).unwrap(), vec![op.op]);
    }

    #[tokio::test]
    async fn test_remove_by_id_not_found() {
        let op = create_op(Address::random(), 0, 0, None);
        let pool = create_pool(vec![op.clone()]);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
            .await
            .unwrap();

        assert!(matches!(
            pool.remove_op_by_id(&UserOperationId {
                sender: Address::random(),
                nonce: U256::ZERO
            }),
            Ok(None)
        ));
        check_ops(pool.best_operations(1, None).unwrap(), vec![op.op]);
    }

    #[tokio::test]
    async fn test_remove_by_id() {
        let op = create_op(Address::random(), 0, 0, None);
        let pool = create_pool(vec![op.clone()]);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
            .await
            .unwrap();
        let hash = op.op.hash();

        pool.on_chain_update(&ChainUpdate {
            latest_block_number: 11,
            ..Default::default()
        })
        .await;

        assert_eq!(pool.remove_op_by_id(&op.op.id()).unwrap().unwrap(), hash);
        check_ops(pool.best_operations(1, None).unwrap(), vec![]);
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_not_found() {
        let op = create_op(Address::random(), 0, 0, None);
        let pool = create_pool(vec![op.clone()]);

        let _ = pool
            .add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
            .await
            .unwrap();

        let pool_op = pool.get_user_operation_by_hash(B256::random());
        assert_eq!(pool_op, None);
    }

    #[tokio::test]
    async fn too_many_ops_for_unstaked_sender() {
        let mut ops = vec![];
        let addr = Address::random();
        for i in 0..5 {
            ops.push(create_op(addr, i, 1, None))
        }
        let pool = create_pool(ops.clone());

        for op in ops.iter().take(4) {
            pool.add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
                .await
                .unwrap();
        }
        assert!(pool
            .add_operation(OperationOrigin::Local, ops[4].op.clone(), default_perms())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_replacement_max_ops_for_unstaked_sender() {
        let mut ops = vec![];
        let addr = Address::random();
        for i in 0..4 {
            ops.push(create_op(addr, i, 1, None))
        }
        // replacement op for first op
        ops.push(create_op(addr, 0, 2, None));

        let pool = create_pool(ops.clone());

        for op in ops.iter().take(4) {
            pool.add_operation(OperationOrigin::Local, op.op.clone(), default_perms())
                .await
                .unwrap();
        }

        pool.add_operation(OperationOrigin::Local, ops[4].op.clone(), default_perms())
            .await
            .unwrap();

        let uos = ops.into_iter().skip(1).map(|op| op.op).collect::<Vec<_>>();

        check_ops_unordered(&pool.all_operations(16), &uos);
    }

    #[tokio::test]
    async fn test_best_staked() {
        let address = Address::random();
        let (pool, uos) = create_pool_insert_ops(vec![
            create_op_with_errors(address, 0, 2, None, None, true),
            create_op_with_errors(address, 1, 2, None, None, true),
            create_op_with_errors(address, 2, 2, None, None, true),
        ])
        .await;
        // staked, so include all ops
        check_ops(pool.best_operations(3, None).unwrap(), uos);
    }

    #[tokio::test]
    async fn test_pre_op_gas_limit_reject() {
        let mut config = default_config();
        config.gas_limit_efficiency_reject_threshold = 0.25;

        let op = create_op_from_op_v0_6(UserOperationRequiredFields {
            call_gas_limit: 10_000,
            verification_gas_limit: 500_000, // used 100K of 550K
            pre_verification_gas: 50_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            ..Default::default()
        });

        let mut ep = MockEntryPointV0_6::new();
        ep.expect_simulate_handle_op().returning(|_, _, _, _, _| {
            Ok(Ok(ExecutionResult {
                pre_op_gas: 100_000,
                paid: uint!(110_000_U256),
                target_success: true,
                ..Default::default()
            }))
        });

        let pool = create_pool_with_entry_point_config(
            config,
            vec![op.clone()],
            ep,
            MempoolConfig::default(),
        );
        let ret = pool
            .add_operation(OperationOrigin::Local, op.op, default_perms())
            .await;
        let actual_eff = 100_000_f32 / 550_000_f32;

        match ret.err().unwrap() {
            MempoolError::PreOpGasLimitEfficiencyTooLow(eff, actual) => {
                assert_eq!(eff, 0.25);
                assert_eq!(actual, actual_eff);
            }
            _ => panic!("Expected PreOpGasLimitEfficiencyTooLow error"),
        }
    }

    #[tokio::test]
    async fn test_call_gas_limit_reject() {
        let mut config = default_config();
        config.gas_limit_efficiency_reject_threshold = 0.25;

        let op = create_op_from_op_v0_6(UserOperationRequiredFields {
            call_gas_limit: 50_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            ..Default::default()
        });

        let mut ep = MockEntryPointV0_6::new();
        ep.expect_simulate_handle_op().returning(|_, _, _, _, _| {
            Ok(Ok(ExecutionResult {
                pre_op_gas: 50_000,
                paid: uint!(60_000_U256), // call gas used is 10K
                target_success: true,
                ..Default::default()
            }))
        });

        let pool = create_pool_with_entry_point_config(
            config,
            vec![op.clone()],
            ep,
            MempoolConfig::default(),
        );
        let ret = pool
            .add_operation(OperationOrigin::Local, op.op, default_perms())
            .await;
        let actual_eff = 10_000_f32 / 50_000_f32;

        match ret.err().unwrap() {
            MempoolError::ExecutionGasLimitEfficiencyTooLow(eff, actual) => {
                assert_eq!(eff, 0.25);
                assert_eq!(actual, actual_eff);
            }
            _ => panic!("Expected ExecutionGasLimitEfficiencyTooLow error"),
        }
    }

    #[tokio::test]
    async fn test_gas_price_zero_fail_open() {
        let mut config = default_config();
        config.gas_limit_efficiency_reject_threshold = 0.25;

        let op = create_op_from_op_v0_6(UserOperationRequiredFields {
            call_gas_limit: 50_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            ..Default::default()
        });

        let pool = create_pool_with_config(config, vec![op.clone()]);
        pool.add_operation(OperationOrigin::Local, op.op, default_perms())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_auth_support() {
        let mut config = default_config();
        let op = create_op_with_auth(
            UserOperationRequiredFields {
                call_gas_limit: 50_000,
                max_fee_per_gas: 0,
                max_priority_fee_per_gas: 0,
                ..Default::default()
            },
            Eip7702Auth::default(),
        );
        {
            let pool = create_pool_with_config(config.clone(), vec![op.clone()]);
            assert!(pool
                .add_operation(OperationOrigin::Local, op.clone().op, default_perms())
                .await
                .is_err());
        }
        {
            config.support_7702 = true;
            let pool = create_pool_with_config(config.clone(), vec![op.clone()]);
            assert!(pool
                .add_operation(OperationOrigin::Local, op.clone().op, default_perms())
                .await
                .is_err());
        }
        {
            config.support_7702 = true;
            let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
            let signer: PrivateKeySigner = PrivateKeySigner::from_str(private_key).unwrap();
            let authorization = alloy_eips::eip7702::Authorization {
                chain_id: 11011,
                address: Address::from_str("0x1234123412341234123412341234123412341234").unwrap(),
                nonce: 1,
            };
            let signature = signer
                .sign_hash_sync(&authorization.signature_hash())
                .unwrap();
            let signed_authorization = authorization.into_signed(signature);
            let signed_op = create_op_with_auth(
                UserOperationRequiredFields {
                    sender: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
                        .unwrap(),
                    call_gas_limit: 50_000,
                    max_fee_per_gas: 0,
                    max_priority_fee_per_gas: 0,
                    ..Default::default()
                },
                Eip7702Auth {
                    address: signed_authorization.address,
                    chain_id: signed_authorization.chain_id,
                    nonce: signed_authorization.nonce,
                    y_parity: signed_authorization.y_parity(),
                    r: signed_authorization.r(),
                    s: signed_authorization.s(),
                },
            );

            let pool = create_pool_with_config(config.clone(), vec![signed_op.clone()]);
            assert!(pool
                .add_operation(
                    OperationOrigin::Local,
                    signed_op.clone().op,
                    default_perms()
                )
                .await
                .is_ok());
        }
    }

    #[tokio::test]
    async fn test_da_gas_ineligible() {
        let mut config = default_config();
        config.da_gas_tracking_enabled = true;

        let op = create_op_from_op_v0_6(UserOperationRequiredFields {
            call_gas_limit: 50_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            pre_verification_gas: 50_000, // below 100K
            ..Default::default()
        });

        let pool = create_pool_with_config(config, vec![op.clone()]);
        pool.add_operation(OperationOrigin::Local, op.op, default_perms())
            .await
            .unwrap();

        let best = pool.best_operations(10000, None).unwrap();
        assert_eq!(best.len(), 0);
    }

    #[tokio::test]
    async fn test_unsupported_aggregator() {
        let unsupported = Address::random();
        let op = create_op_with_aggregator(UserOperationRequiredFields::default(), unsupported);

        let ops = vec![op.clone()];
        let pool = create_pool(ops);
        let err = pool
            .add_operation(OperationOrigin::Local, op.op, default_perms())
            .await
            .err()
            .unwrap();

        assert!(matches!(err, MempoolError::AggregatorError(_)));
    }

    #[tokio::test]
    async fn test_aggregator_transform() {
        let mut config = default_config();
        let agg_address = Address::random();
        let agg_sig = bytes!("deadbeef");
        let org_sig = bytes!("012345");

        let mut agg = MockSignatureAggregator::default();
        let agg_sig_clone = agg_sig.clone();
        agg.expect_address().return_const(agg_address);
        agg.expect_costs().return_const(AggregatorCosts::default());
        agg.expect_validate_user_op_signature()
            .returning(move |_| Ok(agg_sig_clone.clone()));

        let mut registry = ContractRegistry::<Arc<dyn SignatureAggregator>>::default();
        registry.register(agg_address, Arc::new(agg));

        config
            .chain_spec
            .set_signature_aggregators(Arc::new(registry));

        let op = create_op_with_aggregator(
            UserOperationRequiredFields {
                signature: org_sig.clone(),
                ..Default::default()
            },
            agg_address,
        );

        let ops = vec![op.clone()];
        let pool = create_pool_with_config(config, ops);
        let hash = pool
            .add_operation(OperationOrigin::Local, op.op, default_perms())
            .await
            .unwrap();

        let pool_op = pool.get_user_operation_by_hash(hash).unwrap();

        if let UserOperationVariant::V0_6(uo) = &pool_op.uo {
            assert_eq!(*uo.signature(), agg_sig);
            assert_eq!(*uo.original_signature(), org_sig);
        } else {
            panic!("Expected V0_6 variant");
        }
    }

    #[tokio::test]
    async fn test_aggregator_fail() {
        let mut config = default_config();
        let agg_address = Address::random();

        let mut agg = MockSignatureAggregator::default();
        agg.expect_address().return_const(agg_address);
        agg.expect_costs().return_const(AggregatorCosts::default());
        agg.expect_validate_user_op_signature()
            .returning(move |_| Err(SignatureAggregatorError::ValidationReverted(Bytes::new())));

        let mut registry = ContractRegistry::<Arc<dyn SignatureAggregator>>::default();
        registry.register(agg_address, Arc::new(agg));

        config
            .chain_spec
            .set_signature_aggregators(Arc::new(registry));

        let op = create_op_with_aggregator(UserOperationRequiredFields::default(), agg_address);

        let ops = vec![op.clone()];
        let pool = create_pool_with_config(config, ops);
        let err = pool
            .add_operation(OperationOrigin::Local, op.op, default_perms())
            .await
            .err()
            .unwrap();

        assert!(matches!(err, MempoolError::AggregatorError(_)));
    }

    #[tokio::test]
    async fn test_filter_id_miss() {
        let mut config = default_config();
        let agg_address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");

        let mut agg = MockSignatureAggregator::default();
        agg.expect_address().return_const(agg_address);
        agg.expect_costs().return_const(AggregatorCosts::default());
        agg.expect_validate_user_op_signature()
            .returning(move |_| Ok(bytes!("deadbeef")));

        let mut registry = ContractRegistry::<Arc<dyn SignatureAggregator>>::default();
        registry.register(agg_address, Arc::new(agg));

        config
            .chain_spec
            .set_signature_aggregators(Arc::new(registry));

        let mempool_config = r#"{
            "entryPoint": "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
            "filters": [
                {
                    "id": "1",
                    "filter": {
                        "aggregator": "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
                    }
                }
            ]
        }"#;

        let mempool_config = serde_json::from_str::<MempoolConfig>(mempool_config).unwrap();

        let op = create_op_with_aggregator(UserOperationRequiredFields::default(), agg_address);

        let pool = create_pool_with_mempool_config(config, vec![op.clone()], mempool_config);
        pool.add_operation(OperationOrigin::Local, op.op, default_perms())
            .await
            .unwrap();

        let best = pool.best_operations(10000, None).unwrap();
        assert_eq!(best.len(), 0);
    }

    #[tokio::test]
    async fn test_filter_id_match() {
        let mut config = default_config();
        let agg_address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");
        let filter_id = "1".to_string();

        let mut agg = MockSignatureAggregator::default();
        agg.expect_address().return_const(agg_address);
        agg.expect_costs().return_const(AggregatorCosts::default());
        agg.expect_validate_user_op_signature()
            .returning(move |_| Ok(bytes!("deadbeef")));

        let mut registry = ContractRegistry::<Arc<dyn SignatureAggregator>>::default();
        registry.register(agg_address, Arc::new(agg));

        config
            .chain_spec
            .set_signature_aggregators(Arc::new(registry));

        let mempool_config = r#"{
            "entryPoint": "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
            "filters": [
                {
                    "id": "1",
                    "filter": {
                        "aggregator": "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
                    }
                }
            ]
        }"#;

        let mempool_config = serde_json::from_str::<MempoolConfig>(mempool_config).unwrap();

        let op = create_op_with_aggregator(UserOperationRequiredFields::default(), agg_address);

        let pool = create_pool_with_mempool_config(config, vec![op.clone()], mempool_config);
        pool.add_operation(OperationOrigin::Local, op.op, default_perms())
            .await
            .unwrap();

        let best = pool.best_operations(10000, Some(filter_id)).unwrap();
        assert_eq!(best.len(), 1);
    }

    #[tokio::test]
    async fn test_trusted_uo() {
        let config = default_config();
        let perms = UserOperationPermissions {
            trusted: true,
            ..Default::default()
        };

        let op = create_trusted_op(Address::random(), 0, 0);
        let pool = create_pool_with_config(config, vec![op.clone()]);
        pool.add_operation(OperationOrigin::Local, op.op, perms)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_max_allowed_in_pool_for_sender() {
        let config = default_config();
        let perms = UserOperationPermissions {
            max_allowed_in_pool_for_sender: Some(2),
            ..Default::default()
        };
        let sender = Address::random();

        let op1 = create_op(sender, 1, 100, None);
        let op2 = create_op(sender, 2, 100, None);
        let op3 = create_op(sender, 3, 100, None);

        let pool = create_pool_with_config(config, vec![op1.clone(), op2.clone(), op3.clone()]);
        pool.add_operation(OperationOrigin::Local, op1.op, perms.clone())
            .await
            .unwrap();
        pool.add_operation(OperationOrigin::Local, op2.op, perms.clone())
            .await
            .unwrap();
        let err = pool
            .add_operation(OperationOrigin::Local, op3.op, perms)
            .await
            .err()
            .unwrap();

        assert!(matches!(err, MempoolError::MaxOperationsReached(2, _)));
    }

    #[derive(Clone, Debug)]
    struct OpWithErrors {
        op: UserOperationVariant,
        valid_time_range: ValidTimeRange,
        precheck_error: Option<PrecheckViolation>,
        simulation_error: Option<SimulationViolation>,
        staked: bool,
        trusted: bool,
    }

    fn default_config() -> PoolConfig {
        PoolConfig {
            chain_spec: ChainSpec::default(),
            entry_point: Address::random(),
            entry_point_version: EntryPointVersion::V0_6,
            min_replacement_fee_increase_percentage: 10,
            max_size_of_pool_bytes: 10000,
            blocklist: None,
            allowlist: None,
            precheck_settings: PrecheckSettings::default(),
            sim_settings: SimulationSettings::default(),
            mempool_channel_configs: HashMap::new(),
            same_sender_mempool_count: 4,
            throttled_entity_mempool_count: 4,
            throttled_entity_live_blocks: 10,
            paymaster_tracking_enabled: true,
            da_gas_tracking_enabled: false,
            paymaster_cache_length: 100,
            reputation_tracking_enabled: true,
            drop_min_num_blocks: 10,
            gas_limit_efficiency_reject_threshold: 0.0,
            max_time_in_pool: None,
            max_expected_storage_slots: usize::MAX,
            support_7702: false,
        }
    }

    fn create_pool(
        ops: Vec<OpWithErrors>,
    ) -> UoPool<impl UoPoolProvidersT, impl ProvidersWithEntryPointT> {
        create_pool_with_entry_point(ops, MockEntryPointV0_6::new())
    }

    fn create_pool_with_config(
        args: PoolConfig,
        ops: Vec<OpWithErrors>,
    ) -> UoPool<impl UoPoolProvidersT, impl ProvidersWithEntryPointT> {
        create_pool_with_entry_point_config(
            args,
            ops,
            MockEntryPointV0_6::new(),
            MempoolConfig::default(),
        )
    }

    fn create_pool_with_entry_point(
        ops: Vec<OpWithErrors>,
        entrypoint: MockEntryPointV0_6,
    ) -> UoPool<impl UoPoolProvidersT, impl ProvidersWithEntryPointT> {
        let config = default_config();
        create_pool_with_entry_point_config(config, ops, entrypoint, MempoolConfig::default())
    }

    fn create_pool_with_mempool_config(
        args: PoolConfig,
        ops: Vec<OpWithErrors>,
        mempool_config: MempoolConfig,
    ) -> UoPool<impl UoPoolProvidersT, impl ProvidersWithEntryPointT> {
        create_pool_with_entry_point_config(args, ops, MockEntryPointV0_6::new(), mempool_config)
    }

    fn create_pool_with_entry_point_config(
        args: PoolConfig,
        ops: Vec<OpWithErrors>,
        entrypoint: MockEntryPointV0_6,
        mempool_config: MempoolConfig,
    ) -> UoPool<impl UoPoolProvidersT, impl ProvidersWithEntryPointT> {
        let entrypoint = Arc::new(entrypoint);

        let mut evm = MockEvmProvider::new();
        evm.expect_get_latest_block_hash_and_number()
            .returning(|| Ok((B256::ZERO, 0)));

        let mut simulator = MockSimulator::new();
        let mut prechecker = MockPrechecker::new();
        let entry_point = Arc::new(entrypoint);

        let paymaster = PaymasterTracker::new(
            entry_point.clone(),
            PaymasterConfig::new(
                args.sim_settings.min_stake_value,
                args.sim_settings.min_unstake_delay,
                args.paymaster_tracking_enabled,
                args.paymaster_cache_length,
            ),
        );

        let reputation = Arc::new(AddressReputation::new(
            ReputationParams::test_parameters(BAN_SLACK, THROTTLE_SLACK),
            args.blocklist.clone().unwrap_or_default(),
            args.allowlist.clone().unwrap_or_default(),
        ));

        prechecker
            .expect_update_fees()
            .returning(|| Ok(FeeUpdate::default()));

        for op in ops {
            prechecker.expect_check().returning(move |_, _, _| {
                if let Some(error) = &op.precheck_error {
                    Err(PrecheckError::Violations(vec![error.clone()]))
                } else {
                    Ok(PrecheckReturn {
                        da_gas_data: DAGasData::Empty,
                        required_pre_verification_gas: 100_000,
                    })
                }
            });
            let is_trusted = op.trusted;
            simulator
                .expect_simulate_validation()
                .withf(move |_, &trusted, _, _| is_trusted == trusted)
                .returning(move |_, _, _, _| {
                    if let Some(error) = &op.simulation_error {
                        Err(SimulationError {
                            violation_error: ViolationError::Violations(vec![error.clone()]),
                            entity_infos: None,
                        })
                    } else {
                        Ok(SimulationResult {
                            account_is_staked: op.staked,
                            valid_time_range: op.valid_time_range,
                            entity_infos: EntityInfos {
                                sender: EntityInfo {
                                    entity: Entity::account(op.op.sender()),
                                    is_staked: false,
                                },
                                ..EntityInfos::default()
                            },
                            pre_op_gas: 100_000,
                            ..SimulationResult::default()
                        })
                    }
                });
        }

        let (event_sender, _) = broadcast::channel(4);
        let da_oracle = Arc::new(MockDAGasOracleSync::new());

        UoPool::new(
            args,
            ProvidersWithEntryPoint::new(Arc::new(evm), entry_point, Some(da_oracle)),
            UoPoolProviders::new(simulator, prechecker),
            event_sender,
            paymaster,
            reputation,
            mempool_config,
        )
    }

    async fn create_pool_with_entrypoint_insert_ops(
        ops: Vec<OpWithErrors>,
        entrypoint: MockEntryPointV0_6,
    ) -> (
        UoPool<impl UoPoolProvidersT, impl ProvidersWithEntryPointT>,
        Vec<UserOperationVariant>,
    ) {
        let uos = ops.iter().map(|op| op.op.clone()).collect::<Vec<_>>();
        let pool = create_pool_with_entry_point(ops, entrypoint);
        for op in &uos {
            let _ = pool
                .add_operation(OperationOrigin::Local, op.clone(), default_perms())
                .await;
        }
        (pool, uos)
    }

    async fn create_pool_insert_ops(
        ops: Vec<OpWithErrors>,
    ) -> (
        UoPool<impl UoPoolProvidersT, impl ProvidersWithEntryPointT>,
        Vec<UserOperationVariant>,
    ) {
        let uos = ops.iter().map(|op| op.op.clone()).collect::<Vec<_>>();
        let pool = create_pool(ops);
        for op in &uos {
            let _ = pool
                .add_operation(OperationOrigin::Local, op.clone(), default_perms())
                .await;
        }
        (pool, uos)
    }

    fn create_op(
        sender: Address,
        nonce: usize,
        max_fee_per_gas: u128,
        paymaster: Option<Address>,
    ) -> OpWithErrors {
        let mut paymaster_and_data = Bytes::new();

        if let Some(paymaster) = paymaster {
            paymaster_and_data = paymaster.to_vec().into();
        }

        let required = UserOperationRequiredFields {
            sender,
            nonce: U256::from(nonce),
            max_fee_per_gas,
            paymaster_and_data,
            ..Default::default()
        };

        create_op_from_required(required)
    }

    fn create_op_from_required(required: UserOperationRequiredFields) -> OpWithErrors {
        OpWithErrors {
            op: UserOperationBuilder::new(&ChainSpec::default(), required)
                .build()
                .into(),
            valid_time_range: ValidTimeRange::default(),
            precheck_error: None,
            simulation_error: None,
            staked: false,
            trusted: false,
        }
    }

    fn create_op_with_errors(
        sender: Address,
        nonce: usize,
        max_fee_per_gas: u128,
        precheck_error: Option<PrecheckViolation>,
        simulation_error: Option<SimulationViolation>,
        staked: bool,
    ) -> OpWithErrors {
        OpWithErrors {
            op: UserOperationBuilder::new(
                &ChainSpec::default(),
                UserOperationRequiredFields {
                    sender,
                    nonce: U256::from(nonce),
                    max_fee_per_gas,
                    ..Default::default()
                },
            )
            .build()
            .into(),
            valid_time_range: ValidTimeRange::default(),
            precheck_error,
            simulation_error,
            staked,
            trusted: false,
        }
    }

    fn create_op_with_auth(op: UserOperationRequiredFields, auth: Eip7702Auth) -> OpWithErrors {
        let op = UserOperationBuilder::new(&ChainSpec::default(), op)
            .authorization_tuple(auth)
            .build()
            .into();
        OpWithErrors {
            op,
            valid_time_range: ValidTimeRange::default(),
            precheck_error: None,
            simulation_error: None,
            staked: false,
            trusted: false,
        }
    }

    fn create_op_with_aggregator(
        op: UserOperationRequiredFields,
        aggregator: Address,
    ) -> OpWithErrors {
        let op = UserOperationBuilder::new(&ChainSpec::default(), op)
            .aggregator(aggregator)
            .build()
            .into();
        OpWithErrors {
            op,
            valid_time_range: ValidTimeRange::default(),
            precheck_error: None,
            simulation_error: None,
            staked: false,
            trusted: false,
        }
    }

    fn create_op_from_op_v0_6(op: UserOperationRequiredFields) -> OpWithErrors {
        OpWithErrors {
            op: UserOperationBuilder::new(&ChainSpec::default(), op)
                .build()
                .into(),
            valid_time_range: ValidTimeRange::default(),
            precheck_error: None,
            simulation_error: None,
            staked: false,
            trusted: false,
        }
    }

    fn create_trusted_op(sender: Address, nonce: usize, max_fee_per_gas: u128) -> OpWithErrors {
        let mut op = create_op_with_errors(sender, nonce, max_fee_per_gas, None, None, false);
        op.trusted = true;
        op
    }

    fn check_ops(ops: Vec<Arc<PoolOperation>>, expected: Vec<UserOperationVariant>) {
        assert_eq!(ops.len(), expected.len());
        for (actual, expected) in ops.into_iter().zip(expected) {
            assert_eq!(actual.uo, expected);
        }
    }

    fn check_ops_unordered(actual: &[Arc<PoolOperation>], expected: &[UserOperationVariant]) {
        let actual_hashes = actual.iter().map(|op| op.uo.hash()).collect::<HashSet<_>>();
        let expected_hashes = expected.iter().map(|op| op.hash()).collect::<HashSet<_>>();
        assert_eq!(actual_hashes, expected_hashes);
    }

    fn default_perms() -> UserOperationPermissions {
        UserOperationPermissions::default()
    }
}
