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
use anyhow::bail;
use metrics::{Counter, Gauge};
use metrics_derive::Metrics;
use rundler_types::{
    GasFees,
    pool::{Pool, PoolOperation, PoolOperationSummary},
};

use crate::ProposerKey;

/// Information about a configured entrypoint (or virtual entrypoint with filter)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EntrypointInfo {
    /// Entrypoint contract address
    pub address: Address,
    /// Optional filter ID for pool filtering (creates "virtual" entrypoints)
    pub filter_id: Option<String>,
}

impl EntrypointInfo {
    /// Returns the proposer key for this entrypoint.
    pub(crate) fn key(&self) -> ProposerKey {
        (self.address, self.filter_id.clone())
    }
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

#[derive(Default)]
struct State {
    uo_sender_to_builder_state: HashMap<Address, (Address, LockState)>,
    builder_to_uo_senders: HashMap<Address, HashSet<Address>>,
    /// Global cycle counter incremented on each assign_work call
    global_cycle: u64,
    /// Tracks when each entrypoint was last selected (by cycle number)
    entrypoint_last_selected: HashMap<ProposerKey, u64>,
    /// Tracks which entrypoint a builder is pinned to for replacement attempts
    builder_to_pinned_proposer: HashMap<Address, ProposerKey>,
}

/// A candidate entrypoint for assignment, used during priority-based selection.
struct Candidate {
    /// Index in the entrypoints config vec (for stable tiebreaking).
    config_index: usize,
    /// The entrypoint info.
    ep: EntrypointInfo,
    /// The pool operation summaries for this entrypoint.
    ops: Vec<PoolOperationSummary>,
    /// Number of eligible ops (after fee filtering).
    eligible_count: usize,
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
        // If builder has confirmed locks, stay pinned to the same entrypoint.
        // This skips the all-entrypoint pool queries and candidate sorting.
        let pinned_target = {
            let state = self.state.lock().unwrap();
            state
                .builder_to_pinned_proposer
                .get(&builder_address)
                .cloned()
                .filter(|_| {
                    state
                        .builder_to_uo_senders
                        .get(&builder_address)
                        .is_some_and(|senders| {
                            senders.iter().any(|s| {
                                state
                                    .uo_sender_to_builder_state
                                    .get(s)
                                    .is_some_and(|(_, ls)| *ls == LockState::Confirmed)
                            })
                        })
                })
        };
        if let Some(pinned_proposer) = pinned_target {
            return self
                .assign_work_for_entrypoint(
                    builder_address,
                    max_sim_block_number,
                    required_fees,
                    pinned_proposer.0,
                    pinned_proposer.1,
                )
                .await;
        }

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
            let (assignable_count, eligible_count) =
                self.count_ops(&ops, builder_address, max_sim_block_number, &required_fees);
            let ep_metrics = ep_metrics_for(ep);
            ep_metrics.ep_eligible_ops.set(eligible_count as f64);
            if eligible_count > 0 {
                candidates.push(Candidate {
                    config_index: entrypoint_idx,
                    ep: ep.clone(),
                    ops,
                    eligible_count,
                });
            } else if assignable_count > 0 {
                fee_filtered_candidate_exists = true;
            }
        }

        if candidates.is_empty() {
            return Ok(if fee_filtered_candidate_exists {
                AssignmentResult::NoOperationsAfterFeeFilter
            } else {
                tracing::debug!(
                    "Builder Assigner: no eligible ops for builder {builder_address:?}"
                );
                AssignmentResult::NoOperations
            });
        }

        // Starvation threshold: each entrypoint should be selected at least once per starvation_ratio cycle through signers
        let starvation_threshold =
            ((self.num_signers as f64 * self.starvation_ratio) as usize).max(1) as u64;

        // Build candidate order with starvation prevention
        let (current_cycle, candidates) = {
            let mut state = self.state.lock().unwrap();
            state.global_cycle += 1;
            let current_cycle = state.global_cycle;

            // Find the most starved entrypoint (if any are past threshold)
            let starved = candidates
                .iter()
                .enumerate()
                .filter_map(|(pos, c)| {
                    let last = state
                        .entrypoint_last_selected
                        .get(&c.ep.key())
                        .copied()
                        .unwrap_or(0);
                    let gap = current_cycle.saturating_sub(last);
                    if gap > starvation_threshold {
                        Some((pos, c, gap))
                    } else {
                        None
                    }
                })
                // Tiebreak: prefer lower config index (b.config_index.cmp(a.config_index) in max_by
                // is equivalent to a.config_index.cmp(b.config_index) in sort_by — both prefer lower index)
                .max_by(|a, b| {
                    a.2.cmp(&b.2)
                        .then_with(|| b.1.config_index.cmp(&a.1.config_index))
                });

            if let Some((pos, c, gap)) = starved {
                let ep_address = c.ep.address;
                let ep_filter = &c.ep.filter_id;
                tracing::info!(
                    "Builder Assigner: Force-selecting starved entrypoint {ep_address:?} (filter: {ep_filter:?}) - gap: {gap} cycles"
                );
                ep_metrics_for(&c.ep).ep_starvation_wakeups.increment(1);
                let starved_candidate = candidates.remove(pos);
                candidates.insert(0, starved_candidate);
            } else {
                // Normal: pick highest eligible count, break ties by least recently selected
                candidates.sort_by(|a, b| {
                    b.eligible_count.cmp(&a.eligible_count).then_with(|| {
                        let last_a = state
                            .entrypoint_last_selected
                            .get(&a.ep.key())
                            .copied()
                            .unwrap_or(0);
                        let last_b = state
                            .entrypoint_last_selected
                            .get(&b.ep.key())
                            .copied()
                            .unwrap_or(0);
                        last_a
                            .cmp(&last_b)
                            .then_with(|| a.config_index.cmp(&b.config_index))
                    })
                });
            }

            (current_cycle, candidates)
        };

        let total_candidates = candidates.len();
        for (candidate_idx, candidate) in candidates.into_iter().enumerate() {
            let ep_address = candidate.ep.address;
            let ep_filter = &candidate.ep.filter_id;
            let candidate_num = candidate_idx + 1;
            let num_summaries = candidate.ops.len();
            tracing::info!(
                "Builder Assigner: selected_ep: {ep_address:?} (filter: {ep_filter:?}) for builder {builder_address:?}, candidate {candidate_num}/{total_candidates}, num pool summaries: {num_summaries}"
            );

            // Assign operations from selected entrypoint
            let assigned_ops = self
                .assign_ops_internal(
                    builder_address,
                    &candidate.ep,
                    candidate.ops,
                    max_sim_block_number,
                    &required_fees,
                )
                .await?;

            if assigned_ops.is_empty() {
                tracing::info!(
                    "Builder Assigner: no assigned ops for ep {ep_address:?} (filter: {ep_filter:?}) after selection"
                );
                continue;
            }

            // Record the selected entrypoint for starvation and tie-break tracking.
            // Only updated on successful assignment to avoid refreshing the counter
            // for entrypoints that had no concrete ops assigned.
            {
                let mut state = self.state.lock().unwrap();
                state
                    .entrypoint_last_selected
                    .insert(candidate.ep.key(), current_cycle);
                // Pin builder to this entrypoint for replacement attempts
                state
                    .builder_to_pinned_proposer
                    .insert(builder_address, candidate.ep.key());
            }
            ep_metrics_for(&candidate.ep).ep_assignments.increment(1);

            return Ok(AssignmentResult::Assigned(WorkAssignment {
                entry_point: candidate.ep.address,
                filter_id: candidate.ep.filter_id,
                operations: assigned_ops,
            }));
        }

        Ok(AssignmentResult::NoOperations)
    }

    /// Assigns work for a specific entrypoint configuration.
    ///
    /// This is used internally for replacement attempts to ensure the entrypoint does not change.
    async fn assign_work_for_entrypoint(
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

        let (assignable_count, eligible_count) =
            self.count_ops(&ops, builder_address, max_sim_block_number, &required_fees);

        let ep_info = EntrypointInfo {
            address: entry_point,
            filter_id: filter_id.clone(),
        };
        let ep_metrics = ep_metrics_for(&ep_info);
        ep_metrics.ep_eligible_ops.set(eligible_count as f64);

        // Always update starvation tracking, even with no eligible ops.
        // This intentionally inflates the starvation counter for this entrypoint during
        // replacement attempts, which is acceptable: the entrypoint is actively being
        // worked on (fee escalation), so it shouldn't trigger starvation prevention.
        {
            let mut state = self.state.lock().unwrap();
            state.global_cycle += 1;
            let global_cycle = state.global_cycle;
            state
                .entrypoint_last_selected
                .insert(ep_info.key(), global_cycle);
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
                &ep_info,
                ops,
                max_sim_block_number,
                &required_fees,
            )
            .await?;

        if assigned_ops.is_empty() {
            return Ok(AssignmentResult::NoOperations);
        }

        // Pin builder to this entrypoint (may already be pinned)
        {
            let mut state = self.state.lock().unwrap();
            state
                .builder_to_pinned_proposer
                .insert(builder_address, (entry_point, filter_id.clone()));
        }
        ep_metrics.ep_assignments.increment(1);

        Ok(AssignmentResult::Assigned(WorkAssignment {
            entry_point,
            filter_id,
            operations: assigned_ops,
        }))
    }

    /// Count ops in a single pass under one lock acquisition.
    /// Returns (assignable_count, eligible_count) where:
    /// - assignable: not assigned to another builder, simulated before max_sim_block_number
    /// - eligible: assignable AND meets fee requirements
    fn count_ops(
        &self,
        ops: &[PoolOperationSummary],
        builder_address: Address,
        max_sim_block_number: u64,
        required_fees: &GasFees,
    ) -> (usize, usize) {
        let state = self.state.lock().unwrap();
        let mut assignable = 0;
        let mut eligible = 0;
        for op in ops.iter() {
            if op.sim_block_number > max_sim_block_number {
                continue;
            }
            let is_assignable = match state.uo_sender_to_builder_state.get(&op.sender) {
                None => true,
                Some((locked_builder, _)) => *locked_builder == builder_address,
            };
            if !is_assignable {
                continue;
            }
            assignable += 1;
            if self.op_meets_fee_requirements(op, required_fees, false) {
                eligible += 1;
            }
        }
        (assignable, eligible)
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
                    let hash = op.hash;
                    tracing::info!(
                        "Builder Assigner: op {hash:?} doesn't meet bundler sponsorship requirements: total_cost: {total_cost:?}, max_cost: {max_cost:?}"
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
                let hash = op.hash;
                let max_priority = op.max_priority_fee_per_gas;
                let max_fee = op.max_fee_per_gas;
                tracing::info!(
                    "Builder Assigner: op {hash:?} doesn't meet fee requirements: max_priority_fee_per_gas: {max_priority:?}, max_fee_per_gas: {max_fee:?}, required_fees: {required_fees:?}"
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
        ep: &EntrypointInfo,
        ops: Vec<PoolOperationSummary>,
        max_sim_block_number: u64,
        required_fees: &GasFees,
    ) -> anyhow::Result<Vec<PoolOperation>> {
        let per_builder_metrics =
            PerBuilderMetrics::new_with_labels(&[("builder_address", builder_address.to_string())]);
        let per_ep_metrics = ep_metrics_for(ep);
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
                        let hash = op.hash;
                        let sender = op.sender;
                        tracing::debug!(
                            "op {hash:?} sender {sender:?} assigned to builder {builder_address:?}"
                        );
                        per_builder_metrics.senders_assigned.increment(1);
                        per_ep_metrics.ep_senders_assigned.increment(1);
                        (builder_address, LockState::Assigned)
                    });

                if *locked_builder_address != builder_address {
                    let hash = op.hash;
                    let sender = op.sender;
                    tracing::debug!(
                        "op {hash:?} sender {sender:?} already assigned to another builder {locked_builder_address:?}, skipping"
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
                ep.address,
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
    // Returns an error if a confirmed sender is not found in the state or is assigned to a
    // different builder — both indicate a broken lock contract.
    //
    // If builder_address has no entry in builder_to_uo_senders (e.g. called with an
    // unknown builder or after all senders were already released), this is a no-op.
    pub(crate) fn confirm_senders_drop_unused<'a>(
        &self,
        builder_address: Address,
        confirmed_senders: impl IntoIterator<Item = &'a Address>,
    ) -> anyhow::Result<()> {
        let mut state = self.state.lock().unwrap();
        let per_builder_metrics =
            PerBuilderMetrics::new_with_labels(&[("builder_address", builder_address.to_string())]);
        let per_ep_metrics = state
            .builder_to_pinned_proposer
            .get(&builder_address)
            .map(ep_metrics_for_key);

        // Confirm all of the senders in state
        for confirmed_sender in confirmed_senders.into_iter() {
            let Some((locked_builder_address, lock_state)) =
                state.uo_sender_to_builder_state.get_mut(confirmed_sender)
            else {
                bail!(
                    "confirmed_sender {confirmed_sender:?} not found in state, lock contract broken"
                );
            };

            if *locked_builder_address != builder_address {
                bail!(
                    "confirmed_sender {confirmed_sender:?} is assigned to builder {locked_builder_address:?}, expected {builder_address:?}, lock contract broken"
                );
            }

            // Confirm the sender to the builder
            if *lock_state == LockState::Assigned {
                tracing::debug!(
                    "confirmed_sender {confirmed_sender:?} confirmed to builder {builder_address:?}"
                );
                per_builder_metrics.senders_confirmed.increment(1);
                per_builder_metrics.senders_assigned.decrement(1);
                if let Some(ref ep_m) = per_ep_metrics {
                    ep_m.ep_senders_confirmed.increment(1);
                    ep_m.ep_senders_assigned.decrement(1);
                }
                *lock_state = LockState::Confirmed;
            }
        }

        // Drop locks for all senders that are still in the assigned state
        let Some(builder_senders) = state.builder_to_uo_senders.get(&builder_address) else {
            return Ok(());
        };

        let mut to_remove = Vec::new();

        for sender in builder_senders.iter() {
            let Some(entry) = state.uo_sender_to_builder_state.get(sender) else {
                bail!(
                    "sender {sender:?} in builder_to_uo_senders but not in uo_sender_to_builder_state, lock contract broken"
                );
            };
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
            tracing::debug!("sender {sender:?} removed from builder {builder_address:?}");
            per_builder_metrics.senders_assigned.decrement(1);
            if let Some(ref ep_m) = per_ep_metrics {
                ep_m.ep_senders_assigned.decrement(1);
            }

            if builder_senders.is_empty() {
                self.metrics.active_builders.decrement(1);
                state.builder_to_uo_senders.remove(&builder_address);
                state.builder_to_pinned_proposer.remove(&builder_address);
            }
        }

        Ok(())
    }

    /// Returns the proposer key that the builder is currently pinned to, if any.
    pub(crate) fn pinned_proposer(&self, builder_address: Address) -> Option<ProposerKey> {
        self.state
            .lock()
            .unwrap()
            .builder_to_pinned_proposer
            .get(&builder_address)
            .cloned()
    }

    // This method releases all of the senders assigned to the builder.
    // This is typically done when the builder is done forming a bundle and is ready to start forming the next bundle.
    pub(crate) fn release_all(&self, builder_address: Address) {
        let mut state = self.state.lock().unwrap();
        let per_ep_metrics = state
            .builder_to_pinned_proposer
            .get(&builder_address)
            .map(ep_metrics_for_key);
        state.builder_to_pinned_proposer.remove(&builder_address);
        let Some(builder_senders) = state.builder_to_uo_senders.remove(&builder_address) else {
            return;
        };
        let per_builder_metrics =
            PerBuilderMetrics::new_with_labels(&[("builder_address", builder_address.to_string())]);

        for sender in builder_senders {
            if let Some((_, lock_state)) = state.uo_sender_to_builder_state.remove(&sender) {
                tracing::debug!("sender {sender:?} removed from builder {builder_address:?}");
                match lock_state {
                    LockState::Assigned => {
                        per_builder_metrics.senders_assigned.decrement(1);
                        if let Some(ref ep_m) = per_ep_metrics {
                            ep_m.ep_senders_assigned.decrement(1);
                        }
                    }
                    LockState::Confirmed => {
                        per_builder_metrics.senders_confirmed.decrement(1);
                        if let Some(ref ep_m) = per_ep_metrics {
                            ep_m.ep_senders_confirmed.decrement(1);
                        }
                    }
                }
            }
        }

        self.metrics.active_builders.decrement(1);
    }
}

#[cfg(test)]
impl Assigner {
    /// Test helper: establish confirmed sender locks and pin a builder to a proposer key.
    /// This simulates the state after a successful bundle send.
    pub(crate) fn test_establish_pin(
        &self,
        builder_address: Address,
        senders: &[Address],
        proposer_key: ProposerKey,
    ) {
        let mut state = self.state.lock().unwrap();
        for sender in senders {
            state
                .uo_sender_to_builder_state
                .insert(*sender, (builder_address, LockState::Confirmed));
            state
                .builder_to_uo_senders
                .entry(builder_address)
                .or_default()
                .insert(*sender);
        }
        state
            .builder_to_pinned_proposer
            .insert(builder_address, proposer_key);
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

#[derive(Metrics)]
#[metrics(scope = "builder_assigner")]
struct PerEntrypointMetrics {
    #[metric(describe = "the count of senders assigned to builders for this entrypoint.")]
    ep_senders_assigned: Gauge,
    #[metric(describe = "the count of senders confirmed to builders for this entrypoint.")]
    ep_senders_confirmed: Gauge,
    #[metric(describe = "the total number of successful assignments from this entrypoint.")]
    ep_assignments: Counter,
    #[metric(
        describe = "the number of times this entrypoint was force-selected due to starvation."
    )]
    ep_starvation_wakeups: Counter,
    #[metric(describe = "the last-seen eligible op count for this entrypoint.")]
    ep_eligible_ops: Gauge,
}

fn ep_metrics_for(ep: &EntrypointInfo) -> PerEntrypointMetrics {
    ep_metrics_for_key(&ep.key())
}

fn ep_metrics_for_key(key: &ProposerKey) -> PerEntrypointMetrics {
    let label = match &key.1 {
        Some(filter_id) => {
            let ep = key.0;
            format!("{ep}:{filter_id}")
        }
        None => key.0.to_string(),
    };
    PerEntrypointMetrics::new_with_labels(&[("entry_point", label)])
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

    fn mock_pool_two_eps(ep1_ops: Vec<PoolOperation>, ep2_ops: Vec<PoolOperation>) -> MockPool {
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

        mock_pool
            .expect_get_ops_by_hashes()
            .returning(move |ep, hashes| {
                let ops = if ep == TEST_ENTRY_POINT {
                    &ep1_ops
                } else {
                    &ep2_ops
                };
                Ok(ops
                    .iter()
                    .filter(|op| hashes.contains(&op.uo.hash()))
                    .cloned()
                    .collect())
            });
        mock_pool
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

    async fn assign_default(assigner: &Assigner, builder: Address) -> AssignmentResult {
        assigner
            .assign_work(builder, u64::MAX, GasFees::default())
            .await
            .unwrap()
    }

    async fn assign_expect_default(assigner: &Assigner, builder: Address) -> WorkAssignment {
        expect_assigned(assign_default(assigner, builder).await)
    }

    async fn assign_cycle(assigner: &Assigner, builder: Address) -> WorkAssignment {
        let assignment = assign_expect_default(assigner, builder).await;
        assigner.release_all(builder);
        assignment
    }

    #[tokio::test]
    async fn test_no_operations() {
        let mut mock_pool = MockPool::new();
        mock_pool_get_ops(&mut mock_pool, vec![]);
        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        let result = assign_default(&assigner, address(0)).await;
        assert!(matches!(result, AssignmentResult::NoOperations));
    }

    #[tokio::test]
    async fn test_assign_work() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let assignment = assign_expect_default(&assigner, address(0)).await;
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
        let _ = assign_default(&assigner, address(0)).await;

        // Same builder address should assign again
        let assignment = assign_expect_default(&assigner, address(0)).await;
        assert_eq!(assignment.operations.len(), 2);

        // Different builder address should not assign (ops locked to builder 0)
        let result = assign_default(&assigner, address(1)).await;
        assert!(matches!(result, AssignmentResult::NoOperations));
    }

    #[tokio::test]
    async fn test_assign_after_drop() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let _ = assign_default(&assigner, address(0)).await;

        // Confirm sender 1, drop sender 2
        assigner
            .confirm_senders_drop_unused(address(0), &[address(1)])
            .unwrap();

        // Different builder should be able to receive address(2)
        let assignment = assign_expect_default(&assigner, address(1)).await;
        assert_eq!(assignment.operations.len(), 1);
        assert_eq!(assignment.operations[0].uo.sender(), address(2));
    }

    #[tokio::test]
    async fn test_assign_after_release() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let _ = assign_default(&assigner, address(0)).await;

        // Release all locks
        assigner.release_all(address(0));

        // Different builder should get all ops
        let assignment = assign_expect_default(&assigner, address(1)).await;
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
        let _ = assign_default(&assigner, address(0)).await;

        // confirm address(1)
        assigner
            .confirm_senders_drop_unused(address(0), &[address(1)])
            .unwrap();
        // this should not drop lock on address(1)
        assigner
            .confirm_senders_drop_unused(address(0), &[])
            .unwrap();

        // Different builder should only get address(2)
        let assignment = assign_expect_default(&assigner, address(1)).await;
        assert_eq!(assignment.operations.len(), 1);
        assert_eq!(assignment.operations[0].uo.sender(), address(2));
    }

    #[tokio::test]
    async fn test_try_confirm_unknown_sender() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let err = assigner
            .confirm_senders_drop_unused(address(0), &[address(3)])
            .expect_err("should error on unknown sender");
        assert!(
            err.to_string().contains("not found in state"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn test_try_confirm_sender_not_assigned() {
        let mock_pool = MockPool::new();
        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let err = assigner
            .confirm_senders_drop_unused(address(1), &[address(1)])
            .expect_err("should error on unassigned sender");
        assert!(
            err.to_string().contains("not found in state"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn test_try_confirm_sender_assigned_to_other_builder() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let _ = assign_default(&assigner, address(0)).await;

        let err = assigner
            .confirm_senders_drop_unused(address(1), &[address(1)])
            .expect_err("should error on sender assigned to other builder");
        assert!(
            err.to_string().contains("lock contract broken"),
            "unexpected error: {err:#}"
        );
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

    fn create_test_ops_inner(
        senders: &[Address],
        entry_point: Address,
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

    fn create_test_ops_for_entrypoint(
        senders: &[Address],
        entry_point: Address,
    ) -> Vec<PoolOperation> {
        create_test_ops_inner(senders, entry_point, 0, 0)
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

        let mock_pool = mock_pool_two_eps(ep1_ops, ep2_ops);

        // High starvation ratio so starvation prevention doesn't interfere
        let assigner = Assigner::new(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

        // Cycle 1: Both unseen (last_selected=0). Tertiary tiebreak by config order keeps EP1 first.
        let r1 = assign_cycle(&assigner, address(0)).await;
        let first = r1.entry_point;

        // Cycle 2: The other EP should win the tiebreak (least recently selected).
        let r2 = assign_cycle(&assigner, address(0)).await;
        assert_ne!(
            r2.entry_point, first,
            "Cycle 2: should pick the other EP via tiebreak"
        );

        // Cycle 3: Should alternate back to the first EP.
        let r3 = assign_cycle(&assigner, address(0)).await;
        assert_eq!(
            r3.entry_point, first,
            "Cycle 3: should alternate back to first EP"
        );

        // Cycle 4: Should alternate again.
        let r4 = assign_cycle(&assigner, address(0)).await;
        assert_ne!(
            r4.entry_point, first,
            "Cycle 4: should alternate to other EP"
        );
    }

    #[tokio::test]
    async fn test_starvation_prevention() {
        // EP1 always has 10 ops, EP2 always has 2 ops
        // With num_signers=4 and starvation_ratio=0.50, threshold = 4 * 0.50 = 2 cycles
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

        let mock_pool = mock_pool_two_eps(ep1_ops, ep2_ops);

        // 4 signers = threshold of 2 cycles
        let assigner = Assigner::new(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 0.50);

        // Cycle 1: EP1 should be selected (more ops)
        let result = assign_cycle(&assigner, address(0)).await;
        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT,
            "Cycle 1: EP1 expected"
        );

        // Cycle 2: EP1 still has more ops, should still be selected
        let result = assign_cycle(&assigner, address(0)).await;
        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT,
            "Cycle 2: EP1 expected"
        );

        // Cycle 3: EP2 hasn't been selected in 2 cycles (threshold), should be force-selected
        let result = assign_cycle(&assigner, address(0)).await;
        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT_2,
            "Cycle 3: EP2 expected (starvation prevention)"
        );

        // Cycle 4: EP2 was just selected, back to normal - EP1 has more ops
        let result = assign_expect_default(&assigner, address(0)).await;
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

        let result = assign_expect_default(&assigner, address(0)).await;

        assert_eq!(
            result.entry_point, TEST_ENTRY_POINT_2,
            "assignment should fall back to next candidate in same call"
        );
        assert_eq!(result.operations.len(), 1);
        assert_eq!(result.operations[0].uo.sender(), address(20));
    }

    fn create_test_ops_with_fees(
        senders: &[Address],
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> Vec<PoolOperation> {
        create_test_ops_inner(
            senders,
            TEST_ENTRY_POINT,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        )
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
    async fn test_pinned_builder_stays_on_same_entrypoint() {
        // When a builder has confirmed locks, assign_work should delegate to the
        // pinned entrypoint rather than re-querying all entrypoints.
        let ep1_ops = create_test_ops_for_entrypoint(&[address(10), address(11)], TEST_ENTRY_POINT);
        let ep2_ops = create_test_ops_for_entrypoint(
            &[address(20), address(21), address(22)],
            TEST_ENTRY_POINT_2,
        );

        let mock_pool = mock_pool_two_eps(ep1_ops, ep2_ops);

        // High starvation ratio so starvation prevention doesn't interfere
        let assigner = Assigner::new(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

        // First assignment: EP2 has more ops so it should be selected
        let result = assign_expect_default(&assigner, address(0)).await;
        assert_eq!(result.entry_point, TEST_ENTRY_POINT_2);

        // Confirm senders to create confirmed locks
        let senders: Vec<Address> = result.operations.iter().map(|op| op.uo.sender()).collect();
        assigner
            .confirm_senders_drop_unused(address(0), &senders)
            .unwrap();

        // Verify pin is set
        assert_eq!(
            assigner.pinned_proposer(address(0)),
            Some((TEST_ENTRY_POINT_2, None))
        );

        // Second assignment should stay pinned to EP2
        let result2 = assign_expect_default(&assigner, address(0)).await;
        assert_eq!(result2.entry_point, TEST_ENTRY_POINT_2);
    }

    #[tokio::test]
    async fn test_pinned_builder_no_ops_returns_no_operations() {
        // A pinned builder with no available ops should get NoOperations.
        // First establish a pin, then clear all ops.
        let ep1_ops = create_test_ops_for_entrypoint(&[address(10)], TEST_ENTRY_POINT);
        let ep2_ops = create_test_ops_for_entrypoint(&[address(20)], TEST_ENTRY_POINT_2);

        let mut mock_pool = MockPool::new();
        let ep1_ops_clone = ep1_ops.clone();
        let ep2_ops_clone = ep2_ops.clone();
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        mock_pool
            .expect_get_ops_summaries()
            .returning(move |ep, _, _| {
                let count = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if count < 2 {
                    // First call (assign_work queries both EPs): return ops
                    if ep == TEST_ENTRY_POINT {
                        Ok(ep1_ops_clone.iter().map(|op| op.into()).collect())
                    } else {
                        Ok(ep2_ops_clone.iter().map(|op| op.into()).collect())
                    }
                } else {
                    // Subsequent calls: return empty (simulating no ops for pinned EP)
                    Ok(vec![])
                }
            });

        mock_pool
            .expect_get_ops_by_hashes()
            .returning(move |ep, hashes| {
                let ops = if ep == TEST_ENTRY_POINT {
                    &ep1_ops
                } else {
                    &ep2_ops
                };
                Ok(ops
                    .iter()
                    .filter(|op| hashes.contains(&op.uo.hash()))
                    .cloned()
                    .collect())
            });

        let assigner = Assigner::new(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

        // First: assign and confirm to establish pin
        let result = assign_expect_default(&assigner, address(0)).await;
        let senders: Vec<Address> = result.operations.iter().map(|op| op.uo.sender()).collect();
        assigner
            .confirm_senders_drop_unused(address(0), &senders)
            .unwrap();

        // Second call: pinned EP has no ops
        let result2 = assign_default(&assigner, address(0)).await;
        assert!(matches!(result2, AssignmentResult::NoOperations));
    }

    #[tokio::test]
    async fn test_confirm_drop_all_senders_clears_pin() {
        // When confirm_senders_drop_unused drops all remaining senders (none
        // confirmed), the pin should be cleared so the builder can select a
        // different entrypoint on the next cycle.
        let ep1_ops = create_test_ops_for_entrypoint(&[address(10), address(11)], TEST_ENTRY_POINT);
        let ep2_ops = create_test_ops_for_entrypoint(
            &[address(20), address(21), address(22)],
            TEST_ENTRY_POINT_2,
        );

        let mock_pool = mock_pool_two_eps(ep1_ops, ep2_ops);

        let assigner = Assigner::new(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

        // First assignment: EP2 has more ops so it should be selected
        let result = assign_expect_default(&assigner, address(0)).await;
        assert_eq!(result.entry_point, TEST_ENTRY_POINT_2);

        // Pin should be set after assignment
        assert!(assigner.pinned_proposer(address(0)).is_some());

        // Confirm with empty list — drops all assigned senders
        assigner
            .confirm_senders_drop_unused(address(0), &[])
            .unwrap();

        // Pin should be cleared because the builder has no remaining senders
        assert_eq!(assigner.pinned_proposer(address(0)), None);

        // Next assignment should be free to select any entrypoint (EP2 again,
        // since it still has more ops)
        let result2 = assign_expect_default(&assigner, address(0)).await;
        assert_eq!(result2.entry_point, TEST_ENTRY_POINT_2);
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
