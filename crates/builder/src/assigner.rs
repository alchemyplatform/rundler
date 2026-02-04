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
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use alloy_primitives::Address;
use metrics::Gauge;
use metrics_derive::Metrics;
use rundler_types::{
    GasFees,
    pool::{Pool, PoolOperation, PoolOperationSummary},
};

/// Information about a configured entrypoint (or virtual entrypoint with filter)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EntrypointInfo {
    /// Entrypoint contract address
    pub address: Address,
    /// Optional filter ID for pool filtering (creates "virtual" entrypoints)
    pub filter_id: Option<String>,
}

/// Result of assigning work to a worker
#[derive(Debug)]
pub(crate) struct WorkAssignment {
    /// The selected entrypoint address
    pub entry_point: Address,
    /// The filter ID used (needed to lookup the correct registry entry)
    pub filter_id: Option<String>,
    /// The assigned operations
    pub operations: Vec<PoolOperation>,
}

// The Assigner is responsible for assigning operations to builder addresses.
//
// It handles both entrypoint selection (with starvation prevention) and operation
// assignment to ensure no two builders attempt to include operations from the same
// sender in bundles simultaneously.
//
// Entrypoint Selection Strategy:
// - Primary: Select the entrypoint with the most eligible ops (throughput-optimized)
// - Starvation prevention: If any entrypoint hasn't been selected in (num_signers/2) cycles,
//   force-select the most starved one. This ensures all entrypoints get attention.
pub(crate) struct Assigner {
    pool: Box<dyn Pool>,
    entrypoints: Vec<EntrypointInfo>,
    num_signers: usize,
    state: Mutex<State>,
    max_pool_ops_per_request: u64,
    max_bundle_size: u64,
    metrics: GlobalMetrics,
}

/// Registry key type for entrypoint tracking: (address, filter_id)
type RegistryKey = (Address, Option<String>);

#[derive(Default)]
struct State {
    uo_sender_to_builder_state: HashMap<Address, (Address, LockState)>,
    builder_to_uo_senders: HashMap<Address, HashSet<Address>>,
    /// Global cycle counter incremented on each assign_work call
    global_cycle: u64,
    /// Tracks when each entrypoint was last selected (by cycle number)
    entrypoint_last_selected: HashMap<RegistryKey, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockState {
    // The sender is assigned to the builder, but has not yet been confirmed.
    // The builder has yet to include the sender in a bundle.
    Assigned,
    // The sender is confirmed to the builder. The builder has included the sender in a bundle.
    Confirmed,
}

impl Assigner {
    pub(crate) fn new(
        pool: Box<dyn Pool>,
        entrypoints: Vec<EntrypointInfo>,
        num_signers: usize,
        max_pool_ops_per_request: u64,
        max_bundle_size: u64,
    ) -> Self {
        Self {
            pool,
            entrypoints,
            num_signers,
            state: Mutex::new(State::default()),
            max_pool_ops_per_request,
            max_bundle_size,
            metrics: GlobalMetrics::default(),
        }
    }

    /// Assigns work to a worker using priority-based entrypoint selection with starvation prevention.
    ///
    /// 1. Queries all entrypoints for pending operations
    /// 2. Filters to only eligible ops (not assigned to other builders, simulated before max_sim_block_number)
    /// 3. Selects an entrypoint using starvation-aware priority:
    ///    - If any entrypoint hasn't been selected in (num_signers/2) cycles, force-select the most starved
    ///    - Otherwise, select the entrypoint with the most eligible ops
    /// 4. Assigns operations from that entrypoint to the worker
    /// 5. Returns None if no work is available
    pub(crate) async fn assign_work(
        &self,
        builder_address: Address,
        max_sim_block_number: u64,
        _base_fee: u128,
        _required_fees: GasFees,
    ) -> anyhow::Result<Option<WorkAssignment>> {
        // Query each entrypoint for pending ops and count eligible ones
        let mut candidates = Vec::new();
        for ep in &self.entrypoints {
            let ops = self
                .pool
                .get_ops_summaries(
                    ep.address,
                    self.max_pool_ops_per_request,
                    ep.filter_id.clone(),
                )
                .await?;

            // Count eligible ops (not assigned to other builders, simulated before max_sim_block_number)
            let eligible_count =
                self.count_eligible_ops(&ops, builder_address, max_sim_block_number);
            if eligible_count > 0 {
                candidates.push((ep.clone(), ops, eligible_count));
            }
        }

        if candidates.is_empty() {
            return Ok(None);
        }

        // Starvation threshold: each entrypoint should be selected at least once per half-cycle through signers
        let starvation_threshold = (self.num_signers / 2).max(1) as u64;

        // Select entrypoint with starvation prevention
        let (selected_ep, ops) = {
            let mut state = self.state.lock().unwrap();
            state.global_cycle += 1;
            let current_cycle = state.global_cycle;

            // Find the most starved entrypoint (if any are past threshold)
            let starved = candidates
                .iter()
                .filter_map(|(ep, ops, _)| {
                    let key: RegistryKey = (ep.address, ep.filter_id.clone());
                    let last = state
                        .entrypoint_last_selected
                        .get(&key)
                        .copied()
                        .unwrap_or(0);
                    let gap = current_cycle.saturating_sub(last);
                    if gap > starvation_threshold {
                        Some((ep, ops, gap))
                    } else {
                        None
                    }
                })
                .max_by_key(|(_, _, gap)| *gap);

            let (selected_ep, ops) = if let Some((ep, ops, gap)) = starved {
                tracing::debug!(
                    "Force-selecting starved entrypoint {:?} (filter: {:?}) - gap: {} cycles",
                    ep.address,
                    ep.filter_id,
                    gap
                );
                (ep.clone(), ops.clone())
            } else {
                // Normal: pick highest eligible count
                candidates.sort_by(|a, b| b.2.cmp(&a.2));
                let (ep, ops, _) = candidates.into_iter().next().unwrap();
                (ep, ops)
            };

            // Record that we selected this entrypoint
            let key: RegistryKey = (selected_ep.address, selected_ep.filter_id.clone());
            state.entrypoint_last_selected.insert(key, current_cycle);

            (selected_ep, ops)
        };

        // Assign operations from selected entrypoint
        let assigned_ops = self
            .assign_ops_internal(
                builder_address,
                selected_ep.address,
                ops,
                max_sim_block_number,
            )
            .await?;

        if assigned_ops.is_empty() {
            return Ok(None);
        }

        Ok(Some(WorkAssignment {
            entry_point: selected_ep.address,
            filter_id: selected_ep.filter_id,
            operations: assigned_ops,
        }))
    }

    /// Count ops that are eligible for assignment:
    /// - Not assigned to another builder
    /// - Simulated before max_sim_block_number
    fn count_eligible_ops(
        &self,
        ops: &[PoolOperationSummary],
        builder_address: Address,
        max_sim_block_number: u64,
    ) -> usize {
        let state = self.state.lock().unwrap();
        ops.iter()
            .filter(|op| op.sim_block_number <= max_sim_block_number)
            .filter(|op| {
                // Check if sender is unassigned or assigned to this builder
                match state.uo_sender_to_builder_state.get(&op.sender) {
                    None => true,
                    Some((locked_builder, _)) => *locked_builder == builder_address,
                }
            })
            .count()
    }

    /// Internal method to assign operations from a specific entrypoint
    async fn assign_ops_internal(
        &self,
        builder_address: Address,
        entry_point: Address,
        ops: Vec<PoolOperationSummary>,
        max_sim_block_number: u64,
    ) -> anyhow::Result<Vec<PoolOperation>> {
        let per_builder_metrics =
            PerBuilderMetrics::new_with_labels(&[("builder_address", builder_address.to_string())]);
        let mut return_ops_summaries = Vec::new();

        {
            let mut state = self.state.lock().unwrap();
            for op in ops
                .iter()
                .filter(|op| op.sim_block_number <= max_sim_block_number)
            {
                let (locked_builder_address, _) = state
                    .uo_sender_to_builder_state
                    .entry(op.sender)
                    .or_insert_with(|| {
                        tracing::debug!(
                            "op {:?} sender {:?} assigned to builder {:?}",
                            op.hash,
                            op.sender,
                            builder_address
                        );
                        per_builder_metrics.senders_assigned.increment(1);
                        (builder_address, LockState::Assigned)
                    });

                if *locked_builder_address != builder_address {
                    tracing::debug!(
                        "op {:?} sender {:?} already assigned to another builder {:?}, skipping",
                        op.hash,
                        op.sender,
                        locked_builder_address
                    );
                    continue;
                }

                state
                    .builder_to_uo_senders
                    .entry(builder_address)
                    .or_insert_with(|| {
                        self.metrics.active_builders.increment(1);
                        HashSet::new()
                    })
                    .insert(op.sender);

                return_ops_summaries.push(op.clone());
                if return_ops_summaries.len() >= self.max_bundle_size as usize {
                    break;
                }
            }
        }

        if return_ops_summaries.is_empty() {
            return Ok(vec![]);
        }

        let return_ops = self
            .pool
            .get_ops_by_hashes(
                entry_point,
                return_ops_summaries.iter().map(|op| op.hash).collect(),
            )
            .await?;

        Ok(return_ops)
    }

    // This method confirms the locks for the `confirmed_senders` and drops the locks for the senders that are not confirmed.
    //
    //  - If a sender is assigned to the builder (is in the "assigned" state), it will be dropped if it is not in the `confirmed_senders` list.
    //  - If a sender was previously confirmed to the builder (is in the "confirmed" state), it will be kept regardless of whether it is in the `confirmed_senders` list or not.
    //
    // This method is typically called when the builder is done forming and sending a bundle. Confirmed senders are the senders that were included in the bundle.
    //
    // PANICS:
    // - If the confirmed_sender is not found in the state, the builder must have been assigned this sender via the assign_work method.
    // - If the confirmed_sender is assigned to another builder, the builder must have been assigned this sender via the assign_work method.
    // - If the builder_address is not found in the state, the builder must have been assigned via the assign_work method.
    // - If the builder is assigned a sender that is not found in the uo_sender_to_builder_state map, this is an internal error.
    pub(crate) fn confirm_senders_drop_unused<'a>(
        &self,
        builder_address: Address,
        confirmed_senders: impl IntoIterator<Item = &'a Address>,
    ) {
        let mut state = self.state.lock().unwrap();
        let per_builder_metrics =
            PerBuilderMetrics::new_with_labels(&[("builder_address", builder_address.to_string())]);

        // Confirm all of the senders in state
        for confirmed_sender in confirmed_senders.into_iter() {
            let (locked_builder_address, lock_state) = state
                .uo_sender_to_builder_state
                .get_mut(confirmed_sender)
                .expect("BUG: confirmed_sender not found in state, lock contract broken");

            if *locked_builder_address != builder_address {
                panic!(
                    "BUG: confirmed_sender {:?} is assigned to another builder expected: {:?} found: {:?}, lock contract broken",
                    confirmed_sender, builder_address, locked_builder_address
                );
            }

            // Confirm the sender to the builder
            if *lock_state == LockState::Assigned {
                tracing::debug!(
                    "confirmed_sender {:?} confirmed to builder {:?}",
                    confirmed_sender,
                    builder_address
                );
                per_builder_metrics.senders_confirmed.increment(1);
                per_builder_metrics.senders_assigned.decrement(1);
                *lock_state = LockState::Confirmed;
            }
        }

        // Drop locks for all senders that are still in the assigned state
        let builder_senders = state
            .builder_to_uo_senders
            .get(&builder_address)
            .expect("BUG: builder_address not found in state, lock contract broken");

        let mut to_remove = Vec::new();

        for sender in builder_senders.iter() {
            let entry = state
                .uo_sender_to_builder_state
                .get(sender)
                .expect("BUG: sender not found in state, lock contract broken");
            if entry.1 != LockState::Confirmed {
                to_remove.push(*sender);
            }
        }

        for sender in to_remove {
            state.uo_sender_to_builder_state.remove(&sender);
            let builder_senders = state
                .builder_to_uo_senders
                .get_mut(&builder_address)
                .unwrap();
            builder_senders.remove(&sender);
            tracing::debug!(
                "sender {:?} removed from builder {:?}",
                sender,
                builder_address
            );
            per_builder_metrics.senders_assigned.decrement(1);

            if builder_senders.is_empty() {
                self.metrics.active_builders.decrement(1);
                state.builder_to_uo_senders.remove(&builder_address);
            }
        }
    }

    // This method releases all of the senders assigned to the builder.
    // This is typically done when the builder is done forming a bundle and is ready to start forming the next bundle.
    pub(crate) fn release_all(&self, builder_address: Address) {
        let mut state = self.state.lock().unwrap();
        let Some(builder_senders) = state.builder_to_uo_senders.remove(&builder_address) else {
            return;
        };
        let per_builder_metrics =
            PerBuilderMetrics::new_with_labels(&[("builder_address", builder_address.to_string())]);

        for sender in builder_senders {
            if let Some((_, state)) = state.uo_sender_to_builder_state.remove(&sender) {
                tracing::debug!(
                    "sender {:?} removed from builder {:?}",
                    sender,
                    builder_address
                );
                match state {
                    LockState::Assigned => {
                        per_builder_metrics.senders_assigned.decrement(1);
                    }
                    LockState::Confirmed => {
                        per_builder_metrics.senders_confirmed.decrement(1);
                    }
                }
            }
        }

        self.metrics.active_builders.decrement(1);
    }
}

#[derive(Metrics, Clone)]
#[metrics(scope = "builder_assigner")]
struct GlobalMetrics {
    #[metric(describe = "the number of active builders.")]
    active_builders: Gauge,
}

#[derive(Metrics)]
#[metrics(scope = "builder_assigner")]
struct PerBuilderMetrics {
    #[metric(describe = "the count of senders assigned to a builder.")]
    senders_assigned: Gauge,
    #[metric(describe = "the count of senders confirmed to a builder.")]
    senders_confirmed: Gauge,
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use rundler_types::{
        EntityInfos, UserOperation, UserOperationPermissions, ValidTimeRange,
        chain::ChainSpec,
        pool::MockPool,
        v0_6::{UserOperationBuilder, UserOperationRequiredFields},
    };

    use super::*;

    const TEST_ENTRY_POINT: Address = Address::ZERO;

    fn create_test_ops(senders: &[Address]) -> Vec<PoolOperation> {
        senders
            .iter()
            .map(|sender| {
                let uo = UserOperationBuilder::new(
                    &ChainSpec::default(),
                    UserOperationRequiredFields {
                        sender: *sender,
                        ..Default::default()
                    },
                )
                .build()
                .into();
                PoolOperation {
                    uo,
                    expected_code_hash: B256::ZERO,
                    entry_point: TEST_ENTRY_POINT,
                    sim_block_hash: B256::ZERO,
                    sim_block_number: 0,
                    account_is_staked: false,
                    valid_time_range: ValidTimeRange::default(),
                    entity_infos: EntityInfos::default(),
                    aggregator: None,
                    da_gas_data: Default::default(),
                    filter_id: None,
                    perms: UserOperationPermissions::default(),
                    sender_is_7702: false,
                }
            })
            .collect()
    }

    fn mock_pool_get_ops(mock_pool: &mut MockPool, ops: Vec<PoolOperation>) {
        let ops_cloned = ops.clone();
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |_, _, _| {
                Ok(ops_cloned.iter().map(|op| op.into()).collect::<Vec<_>>())
            });
        mock_pool
            .expect_get_ops_by_hashes()
            .returning(move |_, hashes| {
                Ok(ops
                    .iter()
                    .filter(|op| hashes.contains(&op.uo.hash()))
                    .cloned()
                    .collect::<Vec<_>>())
            });
    }

    fn test_entrypoints() -> Vec<EntrypointInfo> {
        vec![EntrypointInfo {
            address: TEST_ENTRY_POINT,
            filter_id: None,
        }]
    }

    #[tokio::test]
    async fn test_no_operations() {
        let mut mock_pool = MockPool::new();
        mock_pool_get_ops(&mut mock_pool, vec![]);
        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10);

        let result = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_assign_work() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10);
        let assignment = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap()
            .expect("should have work");
        assert_eq!(assignment.operations.len(), 2);
        assert_eq!(assignment.operations[0].uo.sender(), address(1));
        assert_eq!(assignment.operations[1].uo.sender(), address(2));
        assert_eq!(assignment.entry_point, TEST_ENTRY_POINT);
    }

    #[tokio::test]
    async fn test_assign_twice() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10);
        let _ = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap();

        // Same builder address should assign again
        let assignment = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap()
            .expect("should have work");
        assert_eq!(assignment.operations.len(), 2);

        // Different builder address should not assign (ops locked to builder 0)
        let result = assigner
            .assign_work(address(1), u64::MAX, 0, GasFees::default())
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_assign_after_drop() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10);
        let _ = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap();

        // Confirm sender 1, drop sender 2
        assigner.confirm_senders_drop_unused(address(0), &[address(1)]);

        // Different builder should be able to receive address(2)
        let assignment = assigner
            .assign_work(address(1), u64::MAX, 0, GasFees::default())
            .await
            .unwrap()
            .expect("should have work");
        assert_eq!(assignment.operations.len(), 1);
        assert_eq!(assignment.operations[0].uo.sender(), address(2));
    }

    #[tokio::test]
    async fn test_assign_after_release() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10);
        let _ = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap();

        // Release all locks
        assigner.release_all(address(0));

        // Different builder should get all ops
        let assignment = assigner
            .assign_work(address(1), u64::MAX, 0, GasFees::default())
            .await
            .unwrap()
            .expect("should have work");
        assert_eq!(assignment.operations.len(), 2);
        assert_eq!(assignment.operations[0].uo.sender(), address(1));
        assert_eq!(assignment.operations[1].uo.sender(), address(2));
    }

    #[tokio::test]
    async fn test_cannot_drop_confirmed_senders() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10);
        let _ = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap();

        // confirm address(1)
        assigner.confirm_senders_drop_unused(address(0), &[address(1)]);
        // this should not drop lock on address(1)
        assigner.confirm_senders_drop_unused(address(0), &[]);

        // Different builder should only get address(2)
        let assignment = assigner
            .assign_work(address(1), u64::MAX, 0, GasFees::default())
            .await
            .unwrap()
            .expect("should have work");
        assert_eq!(assignment.operations.len(), 1);
        assert_eq!(assignment.operations[0].uo.sender(), address(2));
    }

    #[tokio::test]
    #[should_panic]
    async fn test_try_confirm_unknown_sender() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10);
        assigner.confirm_senders_drop_unused(address(0), &[address(3)]);
    }

    #[tokio::test]
    #[should_panic]
    async fn test_try_confirm_sender_not_assigned() {
        let mock_pool = MockPool::new();
        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10);
        assigner.confirm_senders_drop_unused(address(1), &[address(1)]);
    }

    #[tokio::test]
    #[should_panic]
    async fn test_try_confirm_sender_assigned_to_other_builder() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10);
        let _ = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap();

        assigner.confirm_senders_drop_unused(address(1), &[address(1)]);
    }

    fn address(i: u64) -> Address {
        Address::from([i as u8; 20])
    }

    const TEST_ENTRY_POINT_2: Address = Address::new([0x01; 20]);

    fn two_entrypoints() -> Vec<EntrypointInfo> {
        vec![
            EntrypointInfo {
                address: TEST_ENTRY_POINT,
                filter_id: None,
            },
            EntrypointInfo {
                address: TEST_ENTRY_POINT_2,
                filter_id: None,
            },
        ]
    }

    /// Create test ops for a specific entrypoint
    fn create_test_ops_for_entrypoint(
        senders: &[Address],
        entry_point: Address,
    ) -> Vec<PoolOperation> {
        senders
            .iter()
            .map(|sender| {
                let uo = UserOperationBuilder::new(
                    &ChainSpec::default(),
                    UserOperationRequiredFields {
                        sender: *sender,
                        ..Default::default()
                    },
                )
                .build()
                .into();
                PoolOperation {
                    uo,
                    expected_code_hash: B256::ZERO,
                    entry_point,
                    sim_block_hash: B256::ZERO,
                    sim_block_number: 0,
                    account_is_staked: false,
                    valid_time_range: ValidTimeRange::default(),
                    entity_infos: EntityInfos::default(),
                    aggregator: None,
                    da_gas_data: Default::default(),
                    filter_id: None,
                    perms: UserOperationPermissions::default(),
                    sender_is_7702: false,
                }
            })
            .collect()
    }

    #[tokio::test]
    async fn test_starvation_prevention() {
        // EP1 always has 10 ops, EP2 always has 2 ops
        // With num_signers=4, threshold = 4/2 = 2 cycles
        // EP1 should be selected first (more ops), but after 2 cycles EP2 should be force-selected

        let ep1_ops = create_test_ops_for_entrypoint(
            &[
                address(10),
                address(11),
                address(12),
                address(13),
                address(14),
                address(15),
                address(16),
                address(17),
                address(18),
                address(19),
            ],
            TEST_ENTRY_POINT,
        );
        let ep2_ops =
            create_test_ops_for_entrypoint(&[address(20), address(21)], TEST_ENTRY_POINT_2);

        let mut mock_pool = MockPool::new();
        let ep1_ops_clone = ep1_ops.clone();
        let ep2_ops_clone = ep2_ops.clone();

        mock_pool
            .expect_get_ops_summaries()
            .returning(move |ep, _, _| {
                if ep == TEST_ENTRY_POINT {
                    Ok(ep1_ops_clone.iter().map(|op| op.into()).collect())
                } else {
                    Ok(ep2_ops_clone.iter().map(|op| op.into()).collect())
                }
            });

        let ep1_ops_for_hashes = ep1_ops.clone();
        let ep2_ops_for_hashes = ep2_ops.clone();
        mock_pool
            .expect_get_ops_by_hashes()
            .returning(move |ep, hashes| {
                let ops = if ep == TEST_ENTRY_POINT {
                    &ep1_ops_for_hashes
                } else {
                    &ep2_ops_for_hashes
                };
                Ok(ops
                    .iter()
                    .filter(|op| hashes.contains(&op.uo.hash()))
                    .cloned()
                    .collect())
            });

        // 4 signers = threshold of 2 cycles
        let assigner = Assigner::new(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024);

        // Cycle 1: EP1 should be selected (more ops)
        let result = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap()
            .expect("should have work");
        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT,
            "Cycle 1: EP1 expected"
        );
        assigner.release_all(address(0));

        // Cycle 2: EP1 still has more ops, should still be selected
        let result = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap()
            .expect("should have work");
        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT,
            "Cycle 2: EP1 expected"
        );
        assigner.release_all(address(0));

        // Cycle 3: EP2 hasn't been selected in 2 cycles (threshold), should be force-selected
        let result = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap()
            .expect("should have work");
        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT_2,
            "Cycle 3: EP2 expected (starvation prevention)"
        );
        assigner.release_all(address(0));

        // Cycle 4: EP2 was just selected, back to normal - EP1 has more ops
        let result = assigner
            .assign_work(address(0), u64::MAX, 0, GasFees::default())
            .await
            .unwrap()
            .expect("should have work");
        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT,
            "Cycle 4: EP1 expected"
        );
    }
}
