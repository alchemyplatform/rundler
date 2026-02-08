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

use alloy_primitives::{Address, U256};
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

/// Detailed result of attempting to assign work.
#[derive(Debug)]
pub(crate) enum AssignmentResult {
    /// Work was assigned successfully.
    Assigned(WorkAssignment),
    /// No assignable operations were available.
    NoOperations,
    /// Assignable operations existed, but all failed fee requirements.
    NoOperationsAfterFeeFilter,
}

// The Assigner is responsible for assigning operations to builder addresses.
//
// It handles both entrypoint selection (with starvation prevention) and operation
// assignment to ensure no two builders attempt to include operations from the same
// sender in bundles simultaneously.
//
// Entrypoint Selection Strategy:
// - Primary: Select the entrypoint with the most eligible ops (throughput-optimized)
// - Starvation prevention: If any entrypoint hasn't been selected in (num_signers * starvation_ratio) cycles,
//   force-select the most starved one. This ensures all entrypoints get attention.
pub(crate) struct Assigner {
    pool: Box<dyn Pool>,
    entrypoints: Vec<EntrypointInfo>,
    num_signers: usize,
    starvation_ratio: f64,
    state: Mutex<State>,
    max_pool_ops_per_request: u64,
    max_bundle_size: u64,
    metrics: GlobalMetrics,
}

use crate::ProposerKey;

#[derive(Default)]
struct State {
    uo_sender_to_builder_state: HashMap<Address, (Address, LockState)>,
    builder_to_uo_senders: HashMap<Address, HashSet<Address>>,
    /// Global cycle counter incremented on each assign_work call
    global_cycle: u64,
    /// Tracks when each entrypoint was last selected (by cycle number)
    entrypoint_last_selected: HashMap<ProposerKey, u64>,
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
        starvation_ratio: f64,
    ) -> Self {
        Self {
            pool,
            entrypoints,
            num_signers,
            starvation_ratio,
            state: Mutex::new(State::default()),
            max_pool_ops_per_request,
            max_bundle_size,
            metrics: GlobalMetrics::default(),
        }
    }

    /// Assigns work to a worker using priority-based entrypoint selection with starvation prevention.
    ///
    /// 1. Queries all entrypoints for pending operations
    /// 2. Filters to only eligible ops (not assigned to other builders, simulated before max_sim_block_number, meets fee requirements)
    /// 3. Selects an entrypoint using starvation-aware priority:
    ///    - If any entrypoint hasn't been selected in (num_signers * starvation_ratio) cycles, force-select the most starved
    ///    - Otherwise, select the entrypoint with the most eligible ops
    /// 4. Attempts assignment from selected entrypoints in priority order until one succeeds
    /// 5. Returns no-work only if all candidates fail assignment
    pub(crate) async fn assign_work(
        &self,
        builder_address: Address,
        max_sim_block_number: u64,
        required_fees: GasFees,
    ) -> anyhow::Result<AssignmentResult> {
        // Query all entrypoints in parallel for pending ops, then count eligible ones.
        //
        // NOTE: There is a deliberate TOCTOU gap between counting eligible ops here
        // and the actual assignment in assign_ops_internal. Between these two steps,
        // another concurrent worker could assign some of the same senders. This is
        // acceptable: assign_ops_internal re-checks sender locks under the state mutex,
        // so correctness is preserved. The worst case is suboptimal entrypoint selection
        // (picking an entrypoint that appeared to have more ops but some were claimed).
        let query_futures: Vec<_> = self
            .entrypoints
            .iter()
            .map(|ep| {
                self.pool.get_ops_summaries(
                    ep.address,
                    self.max_pool_ops_per_request,
                    ep.filter_id.clone(),
                )
            })
            .collect();
        let query_results = futures_util::future::join_all(query_futures).await;

        let mut candidates = Vec::new();
        let mut fee_filtered_candidate_exists = false;
        for (entrypoint_idx, (ep, result)) in self
            .entrypoints
            .iter()
            .zip(query_results.into_iter())
            .enumerate()
        {
            let ops = result?;
            let assignable_count =
                self.count_assignable_ops(&ops, builder_address, max_sim_block_number);
            let eligible_count = self.count_eligible_ops(
                &ops,
                builder_address,
                max_sim_block_number,
                &required_fees,
            );
            if eligible_count > 0 {
                candidates.push((entrypoint_idx, ep.clone(), ops, eligible_count));
            } else if assignable_count > 0 {
                fee_filtered_candidate_exists = true;
            }
        }

        if candidates.is_empty() {
            return Ok(if fee_filtered_candidate_exists {
                AssignmentResult::NoOperationsAfterFeeFilter
            } else {
                tracing::debug!(
                    "Builder Assigner: no eligible ops for builder {:?}",
                    builder_address
                );
                AssignmentResult::NoOperations
            });
        }

        // Starvation threshold: each entrypoint should be selected at least once per starvation_ratio cycle through signers
        let starvation_threshold =
            ((self.num_signers as f64 * self.starvation_ratio) as usize).max(1) as u64;

        // Build candidate order with starvation prevention
        let (current_cycle, ordered_candidates) = {
            let mut state = self.state.lock().unwrap();
            state.global_cycle += 1;
            let current_cycle = state.global_cycle;

            // Find the most starved entrypoint (if any are past threshold)
            let starved = candidates
                .iter()
                .filter_map(|(entrypoint_idx, ep, ops, _)| {
                    let key: ProposerKey = (ep.address, ep.filter_id.clone());
                    let last = state
                        .entrypoint_last_selected
                        .get(&key)
                        .copied()
                        .unwrap_or(0);
                    let gap = current_cycle.saturating_sub(last);
                    if gap > starvation_threshold {
                        Some((entrypoint_idx, ep, ops, gap))
                    } else {
                        None
                    }
                })
                // Tiebreak: prefer lower config index (b.0.cmp(a.0) in max_by
                // is equivalent to a.0.cmp(b.0) in sort_by — both prefer lower index)
                .max_by(|a, b| a.3.cmp(&b.3).then_with(|| b.0.cmp(a.0)));

            if let Some((starved_idx, ep, _, gap)) = starved {
                tracing::info!(
                    "Builder Assigner: Force-selecting starved entrypoint {:?} (filter: {:?}) - gap: {} cycles",
                    ep.address,
                    ep.filter_id,
                    gap
                );
                let starved_idx = *starved_idx;
                if let Some(pos) = candidates
                    .iter()
                    .position(|(idx, _, _, _)| *idx == starved_idx)
                {
                    let starved_candidate = candidates.remove(pos);
                    candidates.insert(0, starved_candidate);
                }
            } else {
                // Normal: pick highest eligible count, break ties by least recently selected
                candidates.sort_by(|a, b| {
                    b.3.cmp(&a.3).then_with(|| {
                        let key_a: ProposerKey = (a.1.address, a.1.filter_id.clone());
                        let key_b: ProposerKey = (b.1.address, b.1.filter_id.clone());
                        let last_a = state
                            .entrypoint_last_selected
                            .get(&key_a)
                            .copied()
                            .unwrap_or(0);
                        let last_b = state
                            .entrypoint_last_selected
                            .get(&key_b)
                            .copied()
                            .unwrap_or(0);
                        last_a.cmp(&last_b).then_with(|| a.0.cmp(&b.0))
                    })
                });
            }

            let ordered_candidates = candidates
                .into_iter()
                .map(|(_, ep, ops, _)| (ep, ops))
                .collect::<Vec<_>>();

            (current_cycle, ordered_candidates)
        };

        let total_candidates = ordered_candidates.len();
        for (candidate_idx, (selected_ep, ops)) in ordered_candidates.into_iter().enumerate() {
            // Record the attempted entrypoint for starvation and tie-break tracking.
            {
                let mut state = self.state.lock().unwrap();
                let key: ProposerKey = (selected_ep.address, selected_ep.filter_id.clone());
                state.entrypoint_last_selected.insert(key, current_cycle);
            }

            tracing::info!(
                "Builder Assigner: selected_ep: {:?} (filter: {:?}) for builder {:?}, candidate {}/{}, num pool summaries: {:?}",
                selected_ep.address,
                selected_ep.filter_id,
                builder_address,
                candidate_idx + 1,
                total_candidates,
                ops.len()
            );

            // Assign operations from selected entrypoint
            let assigned_ops = self
                .assign_ops_internal(
                    builder_address,
                    selected_ep.address,
                    ops,
                    max_sim_block_number,
                    &required_fees,
                )
                .await?;

            if assigned_ops.is_empty() {
                tracing::info!(
                    "Builder Assigner: no assigned ops for ep {:?} (filter: {:?}) after selection",
                    selected_ep.address,
                    selected_ep.filter_id
                );
                continue;
            }

            return Ok(AssignmentResult::Assigned(WorkAssignment {
                entry_point: selected_ep.address,
                filter_id: selected_ep.filter_id,
                operations: assigned_ops,
            }));
        }

        Ok(AssignmentResult::NoOperations)
    }

    /// Assigns work for a specific entrypoint configuration.
    ///
    /// This is used for replacement attempts to ensure the entrypoint does not change.
    pub(crate) async fn assign_work_for_entrypoint(
        &self,
        builder_address: Address,
        max_sim_block_number: u64,
        required_fees: GasFees,
        entry_point: Address,
        filter_id: Option<String>,
    ) -> anyhow::Result<AssignmentResult> {
        let ops = self
            .pool
            .get_ops_summaries(
                entry_point,
                self.max_pool_ops_per_request,
                filter_id.clone(),
            )
            .await?;

        let assignable_count =
            self.count_assignable_ops(&ops, builder_address, max_sim_block_number);
        let eligible_count =
            self.count_eligible_ops(&ops, builder_address, max_sim_block_number, &required_fees);

        // Always update starvation tracking, even with no eligible ops.
        // This intentionally inflates the starvation counter for this entrypoint during
        // replacement attempts, which is acceptable: the entrypoint is actively being
        // worked on (fee escalation), so it shouldn't trigger starvation prevention.
        {
            let mut state = self.state.lock().unwrap();
            state.global_cycle += 1;
            let global_cycle = state.global_cycle;
            let key: ProposerKey = (entry_point, filter_id.clone());
            state.entrypoint_last_selected.insert(key, global_cycle);
        }

        if assignable_count == 0 {
            return Ok(AssignmentResult::NoOperations);
        }

        if eligible_count == 0 {
            return Ok(AssignmentResult::NoOperationsAfterFeeFilter);
        }

        let assigned_ops = self
            .assign_ops_internal(
                builder_address,
                entry_point,
                ops,
                max_sim_block_number,
                &required_fees,
            )
            .await?;

        if assigned_ops.is_empty() {
            return Ok(AssignmentResult::NoOperations);
        }

        Ok(AssignmentResult::Assigned(WorkAssignment {
            entry_point,
            filter_id,
            operations: assigned_ops,
        }))
    }

    /// Count ops that are assignable before fee filtering:
    /// - Not assigned to another builder
    /// - Simulated before max_sim_block_number
    fn count_assignable_ops(
        &self,
        ops: &[PoolOperationSummary],
        builder_address: Address,
        max_sim_block_number: u64,
    ) -> usize {
        let state = self.state.lock().unwrap();
        ops.iter()
            .filter(|op| op.sim_block_number <= max_sim_block_number)
            .filter(
                |op| match state.uo_sender_to_builder_state.get(&op.sender) {
                    None => true,
                    Some((locked_builder, _)) => *locked_builder == builder_address,
                },
            )
            .count()
    }

    /// Count ops that are eligible for assignment:
    /// - Not assigned to another builder
    /// - Simulated before max_sim_block_number
    /// - Meets fee requirements
    fn count_eligible_ops(
        &self,
        ops: &[PoolOperationSummary],
        builder_address: Address,
        max_sim_block_number: u64,
        required_fees: &GasFees,
    ) -> usize {
        let state = self.state.lock().unwrap();
        ops.iter()
            .filter(|op| op.sim_block_number <= max_sim_block_number)
            .filter(|op| self.op_meets_fee_requirements(op, required_fees, false))
            .filter(|op| {
                // Check if sender is unassigned or assigned to this builder
                match state.uo_sender_to_builder_state.get(&op.sender) {
                    None => true,
                    Some((locked_builder, _)) => *locked_builder == builder_address,
                }
            })
            .count()
    }

    /// Check if an operation meets the fee requirements for bundling.
    ///
    /// NOTE: For bundler-sponsored ops, this is an approximate check using the summary's
    /// gas_limit which does not account for dynamic pre-verification gas (PVG) calculated
    /// later by the proposer. Some sponsored ops may pass this check but be rejected
    /// during bundle proposal when exact gas costs are known.
    ///
    /// When `log` is true, logs the reason for rejection (used during assignment).
    /// Set `log` to false for counting paths to avoid duplicate log noise.
    fn op_meets_fee_requirements(
        &self,
        op: &PoolOperationSummary,
        required_fees: &GasFees,
        log: bool,
    ) -> bool {
        if let Some(max_cost) = op.bundler_sponsorship_max_cost {
            // Bundler-sponsored: check that required fees fit within the sponsorship budget
            let total_cost = U256::from(op.gas_limit) * U256::from(required_fees.max_fee_per_gas);
            if total_cost > max_cost {
                if log {
                    tracing::info!(
                        "Builder Assigner: op {:?} doesn't meet bundler sponsorship requirements: total_cost: {:?}, max_cost: {:?}",
                        op.hash,
                        total_cost,
                        max_cost
                    );
                }
                return false;
            }
            return true;
        }
        // Non-sponsored: op fees must meet required fees
        if op.max_priority_fee_per_gas < required_fees.max_priority_fee_per_gas
            || op.max_fee_per_gas < required_fees.max_fee_per_gas
        {
            if log {
                tracing::info!(
                    "Builder Assigner: op {:?} doesn't meet fee requirements: max_priority_fee_per_gas: {:?}, max_fee_per_gas: {:?}, required_fees: {:?}",
                    op.hash,
                    op.max_priority_fee_per_gas,
                    op.max_fee_per_gas,
                    required_fees
                );
            }
            return false;
        }
        true
    }

    /// Internal method to assign operations from a specific entrypoint
    async fn assign_ops_internal(
        &self,
        builder_address: Address,
        entry_point: Address,
        ops: Vec<PoolOperationSummary>,
        max_sim_block_number: u64,
        required_fees: &GasFees,
    ) -> anyhow::Result<Vec<PoolOperation>> {
        let per_builder_metrics =
            PerBuilderMetrics::new_with_labels(&[("builder_address", builder_address.to_string())]);
        let mut return_ops_summaries = Vec::new();

        {
            let mut state = self.state.lock().unwrap();
            for op in ops
                .iter()
                .filter(|op| op.sim_block_number <= max_sim_block_number)
                .filter(|op| self.op_meets_fee_requirements(op, required_fees, true))
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
        let Some(builder_senders) = state.builder_to_uo_senders.get(&builder_address) else {
            return;
        };

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
        create_test_ops_for_entrypoint(senders, TEST_ENTRY_POINT)
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

    fn expect_assigned(result: AssignmentResult) -> WorkAssignment {
        match result {
            AssignmentResult::Assigned(assignment) => assignment,
            other => panic!("should have work, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_operations() {
        let mut mock_pool = MockPool::new();
        mock_pool_get_ops(&mut mock_pool, vec![]);
        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        let result = assigner
            .assign_work(address(0), u64::MAX, GasFees::default())
            .await
            .unwrap();
        assert!(matches!(result, AssignmentResult::NoOperations));
    }

    #[tokio::test]
    async fn test_assign_work() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let assignment = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
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

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let _ = assigner
            .assign_work(address(0), u64::MAX, GasFees::default())
            .await
            .unwrap();

        // Same builder address should assign again
        let assignment = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        assert_eq!(assignment.operations.len(), 2);

        // Different builder address should not assign (ops locked to builder 0)
        let result = assigner
            .assign_work(address(1), u64::MAX, GasFees::default())
            .await
            .unwrap();
        assert!(matches!(result, AssignmentResult::NoOperations));
    }

    #[tokio::test]
    async fn test_assign_after_drop() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let _ = assigner
            .assign_work(address(0), u64::MAX, GasFees::default())
            .await
            .unwrap();

        // Confirm sender 1, drop sender 2
        assigner.confirm_senders_drop_unused(address(0), &[address(1)]);

        // Different builder should be able to receive address(2)
        let assignment = expect_assigned(
            assigner
                .assign_work(address(1), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        assert_eq!(assignment.operations.len(), 1);
        assert_eq!(assignment.operations[0].uo.sender(), address(2));
    }

    #[tokio::test]
    async fn test_assign_after_release() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let _ = assigner
            .assign_work(address(0), u64::MAX, GasFees::default())
            .await
            .unwrap();

        // Release all locks
        assigner.release_all(address(0));

        // Different builder should get all ops
        let assignment = expect_assigned(
            assigner
                .assign_work(address(1), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        assert_eq!(assignment.operations.len(), 2);
        assert_eq!(assignment.operations[0].uo.sender(), address(1));
        assert_eq!(assignment.operations[1].uo.sender(), address(2));
    }

    #[tokio::test]
    async fn test_cannot_drop_confirmed_senders() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let _ = assigner
            .assign_work(address(0), u64::MAX, GasFees::default())
            .await
            .unwrap();

        // confirm address(1)
        assigner.confirm_senders_drop_unused(address(0), &[address(1)]);
        // this should not drop lock on address(1)
        assigner.confirm_senders_drop_unused(address(0), &[]);

        // Different builder should only get address(2)
        let assignment = expect_assigned(
            assigner
                .assign_work(address(1), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        assert_eq!(assignment.operations.len(), 1);
        assert_eq!(assignment.operations[0].uo.sender(), address(2));
    }

    #[tokio::test]
    #[should_panic]
    async fn test_try_confirm_unknown_sender() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        assigner.confirm_senders_drop_unused(address(0), &[address(3)]);
    }

    #[tokio::test]
    #[should_panic]
    async fn test_try_confirm_sender_not_assigned() {
        let mock_pool = MockPool::new();
        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        assigner.confirm_senders_drop_unused(address(1), &[address(1)]);
    }

    #[tokio::test]
    #[should_panic]
    async fn test_try_confirm_sender_assigned_to_other_builder() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let _ = assigner
            .assign_work(address(0), u64::MAX, GasFees::default())
            .await
            .unwrap();

        assigner.confirm_senders_drop_unused(address(1), &[address(1)]);
    }

    fn address(i: u64) -> Address {
        Address::from([i as u8; 20])
    }

    const TEST_ENTRY_POINT_2: Address = Address::new([0xBB; 20]);

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
    async fn test_tiebreak_by_last_selected() {
        // EP1 and EP2 both have 3 ops (equal eligible count).
        // Tie should be broken by least-recently-selected, producing round-robin.
        let ep1_ops = create_test_ops_for_entrypoint(
            &[address(10), address(11), address(12)],
            TEST_ENTRY_POINT,
        );
        let ep2_ops = create_test_ops_for_entrypoint(
            &[address(20), address(21), address(22)],
            TEST_ENTRY_POINT_2,
        );

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

        // High starvation ratio so starvation prevention doesn't interfere
        let assigner = Assigner::new(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

        // Cycle 1: Both unseen (last_selected=0). Tertiary tiebreak by config order keeps EP1 first.
        let r1 = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        let first = r1.entry_point;
        assigner.release_all(address(0));

        // Cycle 2: The other EP should win the tiebreak (least recently selected).
        let r2 = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        assert_ne!(
            r2.entry_point, first,
            "Cycle 2: should pick the other EP via tiebreak"
        );
        assigner.release_all(address(0));

        // Cycle 3: Should alternate back to the first EP.
        let r3 = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        assert_eq!(
            r3.entry_point, first,
            "Cycle 3: should alternate back to first EP"
        );
        assigner.release_all(address(0));

        // Cycle 4: Should alternate again.
        let r4 = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        assert_ne!(
            r4.entry_point, first,
            "Cycle 4: should alternate to other EP"
        );
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
        let assigner = Assigner::new(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 0.50);

        // Cycle 1: EP1 should be selected (more ops)
        let result = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT,
            "Cycle 1: EP1 expected"
        );
        assigner.release_all(address(0));

        // Cycle 2: EP1 still has more ops, should still be selected
        let result = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT,
            "Cycle 2: EP1 expected"
        );
        assigner.release_all(address(0));

        // Cycle 3: EP2 hasn't been selected in 2 cycles (threshold), should be force-selected
        let result = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT_2,
            "Cycle 3: EP2 expected (starvation prevention)"
        );
        assigner.release_all(address(0));

        // Cycle 4: EP2 was just selected, back to normal - EP1 has more ops
        let result = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );
        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT,
            "Cycle 4: EP1 expected"
        );
    }

    #[tokio::test]
    async fn test_assign_work_falls_back_to_next_candidate() {
        let ep1_ops = create_test_ops_for_entrypoint(&[address(10), address(11)], TEST_ENTRY_POINT);
        let ep2_ops = create_test_ops_for_entrypoint(&[address(20)], TEST_ENTRY_POINT_2);

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

        // Simulate first candidate returning no concrete ops after selection; assigner should
        // continue to the next candidate in the same call.
        let ep2_ops_for_hashes = ep2_ops.clone();
        mock_pool
            .expect_get_ops_by_hashes()
            .returning(move |ep, hashes| {
                if ep == TEST_ENTRY_POINT {
                    Ok(Vec::new())
                } else {
                    Ok(ep2_ops_for_hashes
                        .iter()
                        .filter(|op| hashes.contains(&op.uo.hash()))
                        .cloned()
                        .collect())
                }
            });

        let assigner = Assigner::new(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

        let result = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, GasFees::default())
                .await
                .unwrap(),
        );

        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT_2,
            "assignment should fall back to next candidate in same call"
        );
        assert_eq!(result.operations.len(), 1);
        assert_eq!(result.operations[0].uo.sender(), address(20));
    }

    /// Create test ops with specific fees
    fn create_test_ops_with_fees(
        senders: &[Address],
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> Vec<PoolOperation> {
        senders
            .iter()
            .map(|sender| {
                let uo = UserOperationBuilder::new(
                    &ChainSpec::default(),
                    UserOperationRequiredFields {
                        sender: *sender,
                        max_fee_per_gas,
                        max_priority_fee_per_gas,
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

    #[tokio::test]
    async fn test_fee_filtering() {
        // Create ops with different fees:
        // - Op 1 & 2: high fees (100, 10) - should be included
        // - Op 3 & 4: low fees (5, 1) - should be filtered out
        let high_fee_ops = create_test_ops_with_fees(&[address(1), address(2)], 100, 10);
        let low_fee_ops = create_test_ops_with_fees(&[address(3), address(4)], 5, 1);

        let mut all_ops = high_fee_ops.clone();
        all_ops.extend(low_fee_ops.clone());

        let mut mock_pool = MockPool::new();
        let all_ops_for_summaries = all_ops.clone();
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |_, _, _| {
                Ok(all_ops_for_summaries
                    .iter()
                    .map(|op| op.into())
                    .collect::<Vec<_>>())
            });

        // Only high fee ops should be fetched by hash
        mock_pool
            .expect_get_ops_by_hashes()
            .returning(move |_, hashes| {
                Ok(all_ops
                    .iter()
                    .filter(|op| hashes.contains(&op.uo.hash()))
                    .cloned()
                    .collect::<Vec<_>>())
            });

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        // Request with required_fees=(50, 5)
        // Only ops with max_fee >= 50 and priority_fee >= 5 should be eligible
        let required_fees = GasFees {
            max_fee_per_gas: 50,
            max_priority_fee_per_gas: 5,
        };

        let assignment = expect_assigned(
            assigner
                .assign_work(address(0), u64::MAX, required_fees)
                .await
                .unwrap(),
        );

        // Should only get the high fee ops (address(1) and address(2))
        assert_eq!(assignment.operations.len(), 2);
        let senders: Vec<_> = assignment
            .operations
            .iter()
            .map(|op| op.uo.sender())
            .collect();
        assert!(senders.contains(&address(1)));
        assert!(senders.contains(&address(2)));
        // Low fee ops should NOT be included
        assert!(!senders.contains(&address(3)));
        assert!(!senders.contains(&address(4)));
    }

    #[tokio::test]
    async fn test_assign_work_for_entrypoint_returns_ops_for_pinned_ep() {
        // assign_work_for_entrypoint should return ops only from the specified entrypoint,
        // update starvation tracking, and support the replacement (fee escalation) flow.
        let ep1_ops = create_test_ops_for_entrypoint(&[address(10), address(11)], TEST_ENTRY_POINT);
        let ep2_ops = create_test_ops_for_entrypoint(
            &[address(20), address(21), address(22)],
            TEST_ENTRY_POINT_2,
        );

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

        let assigner = Assigner::new(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

        // Pin to EP2 (as if doing a replacement for an existing bundle on EP2)
        let result = assigner
            .assign_work_for_entrypoint(
                address(0),
                u64::MAX,
                GasFees::default(),
                TEST_ENTRY_POINT_2,
                None,
            )
            .await
            .unwrap();

        let assignment = expect_assigned(result);
        assert_eq!(assignment.entry_point, TEST_ENTRY_POINT_2);
        assert_eq!(assignment.operations.len(), 3);
    }

    #[tokio::test]
    async fn test_assign_work_for_entrypoint_no_ops_returns_no_operations() {
        let mut mock_pool = MockPool::new();
        mock_pool
            .expect_get_ops_summaries()
            .returning(|_, _, _| Ok(vec![]));

        let assigner = Assigner::new(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

        let result = assigner
            .assign_work_for_entrypoint(
                address(0),
                u64::MAX,
                GasFees::default(),
                TEST_ENTRY_POINT_2,
                None,
            )
            .await
            .unwrap();

        assert!(matches!(result, AssignmentResult::NoOperations));
    }

    #[tokio::test]
    async fn test_fee_filtering_no_eligible_ops() {
        // All ops have fees too low
        let low_fee_ops = create_test_ops_with_fees(&[address(1), address(2)], 10, 2);

        let mut mock_pool = MockPool::new();
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |_, _, _| {
                Ok(low_fee_ops.iter().map(|op| op.into()).collect::<Vec<_>>())
            });

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        // Request with high fee requirements - no ops should be eligible
        let required_fees = GasFees {
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 50,
        };

        let result = assigner
            .assign_work(address(0), u64::MAX, required_fees)
            .await
            .unwrap();

        assert!(matches!(
            result,
            AssignmentResult::NoOperationsAfterFeeFilter
        ));
    }
}
