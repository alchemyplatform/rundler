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

use alloy_primitives::{Address, B256, U256};
use anyhow::bail;
use metrics::{Counter, Gauge};
use metrics_derive::Metrics;
use rundler_signer::mapping::entry_point_name;
use rundler_types::{
    EntryPointVersion, GasFees,
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
    /// Whether this is an isolation bundle for a single suspect operation.
    /// See `docs/designs/poison-user-operations.md`.
    pub is_isolation: bool,
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
//
// Worker groups:
// - Workers are split into groups (see `WorkerGroup`). The legacy layout has one group serving
//   every entrypoint; the mapping layout has one group per entry point version.
// - Entrypoint selection, isolation capacity and starvation tracking are per group: a worker
//   only sees its group's entrypoints, and limits scale with its group's worker count.
// - Sender locks are shared by all groups, so a sender is bundled by at most one builder at a
//   time across all entry points.
pub(crate) struct Assigner {
    pool: Box<dyn Pool>,
    groups: Vec<GroupConfig>,
    starvation_ratio: f64,
    state: Mutex<State>,
    max_pool_ops_per_request: u64,
    max_bundle_size: u64,
    metrics: GlobalMetrics,
}

/// A group of workers that share entrypoint selection, isolation capacity and starvation
/// tracking within the assigner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkerGroup {
    /// The entry point all workers in the group serve, or `None` for the legacy shared group
    pub(crate) entry_point: Option<EntryPointVersion>,
    /// The (entry point, filter id) combinations the group serves
    pub(crate) infos: Vec<EntrypointInfo>,
    /// Number of workers in the group
    pub(crate) num_workers: usize,
}

/// A worker group with its metrics.
struct GroupConfig {
    entry_point: Option<EntryPointVersion>,
    infos: Vec<EntrypointInfo>,
    num_workers: usize,
    metrics: GroupMetrics,
}

/// Per-group mutable state. Indexed like `Assigner::groups`.
#[derive(Default)]
struct GroupState {
    /// Cycle counter incremented on each assignment for this group
    global_cycle: u64,
    /// Builders currently holding an isolation assignment for a suspect
    /// operation. Bounds isolation capacity while normal work is eligible.
    isolating_builders: HashSet<Address>,
    /// Monotonic counter incremented each time an entrypoint is chosen for an
    /// isolation assignment. Tracked independently of `global_cycle` so
    /// isolation rotation doesn't affect normal-work starvation accounting.
    isolation_cycle: u64,
    /// Builders currently holding a reservoir-mode assignment (a single op bundled alone with
    /// `tx.gas = 2^24 + R`). Bounded jointly with `isolating_builders`, so the two together
    /// cannot starve normal work.
    reservoir_builders: HashSet<Address>,
    /// Monotonic counter incremented each time an entrypoint is chosen for a reservoir-mode
    /// assignment, as `isolation_cycle` is for isolation.
    reservoir_cycle: u64,
    /// Whether the last assignment that reached reservoir or normal work was reservoir mode.
    /// Where the shared capacity is every builder of the group (one worker), reservoir mode and
    /// normal work then take turns, so a stream of reservoir-mode ops cannot starve normal work.
    reservoir_took_last_turn: bool,
}

struct State {
    /// Sender locks, shared by all groups.
    uo_sender_to_builder_state: HashMap<Address, (Address, LockState)>,
    builder_to_uo_senders: HashMap<Address, HashSet<Address>>,
    /// Per-group cycle counters and isolation and reservoir-mode slots.
    groups: Vec<GroupState>,
    /// Tracks when each entrypoint was last selected (by its group's cycle number)
    entrypoint_last_selected: HashMap<ProposerKey, u64>,
    /// Tracks which entrypoint a builder is pinned to for replacement attempts
    builder_to_pinned_proposer: HashMap<Address, ProposerKey>,
    /// The op hash a builder is isolating, if any. Tracked independently of
    /// the pool's suspect flag: `Success` clears suspect status as soon as
    /// the RPC accepts a transaction, well before it's mined, so a stuck
    /// isolation transaction needing a fee-bump replacement would otherwise
    /// look like ordinary work by the time it needs replacing. Cleared
    /// wherever `builder_to_pinned_proposer`/`isolating_builders` are.
    builder_to_isolation_hash: HashMap<Address, B256>,
    /// Tracks when each entrypoint was last chosen for an isolation
    /// assignment (by its group's `isolation_cycle`). Mirrors `entrypoint_last_selected`'s
    /// role for normal work: without it, suspect candidates are attempted in
    /// fixed config order every call, so an entrypoint with due suspects that
    /// happen to be unassignable this cycle can permanently block isolation
    /// slots from reaching suspects on other entrypoints.
    entrypoint_last_isolated: HashMap<ProposerKey, u64>,
    /// The reservoir-mode op hash a builder is bundling, if any, so a replacement (e.g. a fee
    /// bump) re-supplies exactly that op alone. Cleared with the builder's reservoir slot.
    builder_to_reservoir_hash: HashMap<Address, B256>,
    /// Tracks when each entrypoint was last chosen for a reservoir-mode assignment (by its
    /// group's `reservoir_cycle`), so reservoir-mode ops on one entrypoint cannot starve
    /// another's.
    entrypoint_last_reservoir: HashMap<ProposerKey, u64>,
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
    /// Create an assigner for the given worker groups.
    ///
    /// Either a single legacy group (`entry_point: None`) or one group per entry point
    /// version. Each (entry point, filter id) combination must belong to exactly one group.
    pub(crate) fn new(
        pool: Box<dyn Pool>,
        groups: Vec<WorkerGroup>,
        max_pool_ops_per_request: u64,
        max_bundle_size: u64,
        starvation_ratio: f64,
    ) -> anyhow::Result<Self> {
        if groups.is_empty() {
            bail!("assigner requires at least one worker group");
        }
        if groups.iter().any(|g| g.entry_point.is_none()) && groups.len() > 1 {
            bail!("the legacy worker group cannot be combined with other worker groups");
        }
        let mut seen_entry_points = Vec::new();
        let mut seen_keys = HashSet::new();
        for group in &groups {
            let name = group_name(group.entry_point);
            if seen_entry_points.contains(&group.entry_point) {
                bail!("duplicate worker group for entry point {name}");
            }
            seen_entry_points.push(group.entry_point);
            if group.infos.is_empty() {
                bail!("worker group for entry point {name} has no entrypoints");
            }
            for info in &group.infos {
                if !seen_keys.insert(info.key()) {
                    bail!(
                        "entrypoint {:?} (filter: {:?}) is in more than one worker group",
                        info.address,
                        info.filter_id
                    );
                }
            }
        }

        let group_states = groups.iter().map(|_| GroupState::default()).collect();
        let groups = groups
            .into_iter()
            .map(|group| GroupConfig {
                metrics: match group.entry_point {
                    // Legacy layout: unlabelled, as before worker groups existed.
                    None => GroupMetrics::default(),
                    Some(entry_point) => GroupMetrics::new_with_labels(&[(
                        "entry_point",
                        entry_point_name(entry_point),
                    )]),
                },
                entry_point: group.entry_point,
                infos: group.infos,
                num_workers: group.num_workers,
            })
            .collect();

        Ok(Self {
            pool,
            groups,
            starvation_ratio,
            state: Mutex::new(State {
                uo_sender_to_builder_state: HashMap::new(),
                builder_to_uo_senders: HashMap::new(),
                groups: group_states,
                entrypoint_last_selected: HashMap::new(),
                builder_to_pinned_proposer: HashMap::new(),
                builder_to_isolation_hash: HashMap::new(),
                entrypoint_last_isolated: HashMap::new(),
                builder_to_reservoir_hash: HashMap::new(),
                entrypoint_last_reservoir: HashMap::new(),
            }),
            max_pool_ops_per_request,
            max_bundle_size,
            metrics: GlobalMetrics::default(),
        })
    }

    /// Index of the group serving `entry_point` (`None` for the legacy group).
    fn group_index(&self, entry_point: Option<EntryPointVersion>) -> anyhow::Result<usize> {
        self.groups
            .iter()
            .position(|g| g.entry_point == entry_point)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no worker group for entry point {}",
                    group_name(entry_point)
                )
            })
    }

    /// Remove `builder_address` from every group's isolation slots. A builder only ever holds
    /// a slot in its own group, so this frees at most one slot.
    fn release_isolation_slot(&self, state: &mut State, builder_address: Address) {
        for (config, group_state) in self.groups.iter().zip(state.groups.iter_mut()) {
            if group_state.isolating_builders.remove(&builder_address) {
                config
                    .metrics
                    .isolating_builders
                    .set(group_state.isolating_builders.len() as f64);
            }
        }
    }

    /// Remove `builder_address` from every group's reservoir-mode slots and forget the op it was
    /// bundling.
    fn release_reservoir_slot(&self, state: &mut State, builder_address: Address) {
        for group_state in state.groups.iter_mut() {
            group_state.reservoir_builders.remove(&builder_address);
        }
        state.builder_to_reservoir_hash.remove(&builder_address);
    }

    /// Assigns work to a worker using priority-based entrypoint selection with starvation prevention.
    ///
    /// `group` is the worker's entry point (`None` in the legacy layout). Only that group's
    /// entrypoints are considered, and its worker count sets the isolation and starvation
    /// limits. Sender locks are checked across all groups.
    ///
    /// 1. Queries the group's entrypoints for pending operations
    /// 2. Filters to only eligible ops (not assigned to other builders, simulated before max_sim_block_number, meets fee requirements)
    /// 3. Selects an entrypoint using starvation-aware priority:
    ///    - If any entrypoint hasn't been selected in (num_workers * starvation_ratio) group cycles, force-select the most starved
    ///    - Otherwise, select the entrypoint with the most eligible ops
    /// 4. Attempts assignment from selected entrypoints in priority order until one succeeds
    /// 5. Returns no-work only if all candidates fail assignment
    pub(crate) async fn assign_work(
        &self,
        group: Option<EntryPointVersion>,
        builder_address: Address,
        max_sim_block_number: u64,
        required_fees: GasFees,
    ) -> anyhow::Result<AssignmentResult> {
        let group_idx = self.group_index(group)?;
        let group = &self.groups[group_idx];

        // If builder has confirmed locks, stay pinned to the same entrypoint.
        // This skips the all-entrypoint pool queries and candidate sorting.
        let (pinned_target, single_op_hash) = {
            let state = self.state.lock().unwrap();
            let pinned_target = state
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
                });
            let single_op_hash = pinned_target.as_ref().and_then(|_| {
                state
                    .builder_to_isolation_hash
                    .get(&builder_address)
                    .map(|hash| (*hash, true))
                    .or_else(|| {
                        state
                            .builder_to_reservoir_hash
                            .get(&builder_address)
                            .map(|hash| (*hash, false))
                    })
            });
            (pinned_target, single_op_hash)
        };
        if let Some(pinned_proposer) = pinned_target {
            // A builder is only ever pinned to an entrypoint of its own group.
            if !group.infos.iter().any(|info| info.key() == pinned_proposer) {
                bail!(
                    "builder {builder_address:?} of entry point group {} is pinned to {pinned_proposer:?}, outside its group",
                    group_name(group.entry_point)
                );
            }
            if let Some((hash, is_isolation)) = single_op_hash {
                return self
                    .assign_single_op_replacement(
                        builder_address,
                        hash,
                        pinned_proposer,
                        is_isolation,
                    )
                    .await;
            }
            return self
                .assign_work_for_entrypoint(
                    group_idx,
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
        let query_futures: Vec<_> = group
            .infos
            .iter()
            .map(|ep| {
                // Request a full page of due suspects, not just `num_signers`:
                // suspects are returned best-fee-first, and later filtering
                // (locks/fees/block height) happens after this query. Capping
                // here at a small number risked permanently hiding a lower-fee
                // but eligible suspect behind a handful of stuck/unassignable
                // ones ahead of it in the truncated page.
                self.pool.get_ops_summaries(
                    ep.address,
                    self.max_pool_ops_per_request,
                    self.max_pool_ops_per_request,
                    ep.filter_id.clone(),
                )
            })
            .collect();
        let query_results = futures_util::future::join_all(query_futures).await;

        let mut candidates = Vec::new();
        let mut suspect_candidates = Vec::new();
        let mut reservoir_candidates = Vec::new();
        let mut fee_filtered_candidate_exists = false;
        for (entrypoint_idx, (ep, result)) in group
            .infos
            .iter()
            .zip(query_results.into_iter())
            .enumerate()
        {
            let (suspects, ops): (Vec<_>, Vec<_>) = result?.into_iter().partition(|op| op.suspect);
            if !suspects.is_empty() {
                suspect_candidates.push((ep.clone(), suspects));
            }
            // Reservoir-mode ops are always bundled alone, never in normal work. (A suspect one
            // is isolated above, which is single-op too.)
            let (reservoir_ops, ops): (Vec<_>, Vec<_>) =
                ops.into_iter().partition(|op| op.reservoir);
            if !reservoir_ops.is_empty() {
                reservoir_candidates.push((ep.clone(), reservoir_ops));
            }
            let OpCounts {
                assignable: assignable_count,
                eligible: eligible_count,
                sponsorship_budget_blocked,
            } = self.count_ops(&ops, builder_address, max_sim_block_number, &required_fees);
            let ep_metrics = ep_metrics_for(ep);
            ep_metrics.ep_eligible_ops.set(eligible_count as f64);
            ep_metrics
                .ep_sponsorship_budget_blocked_ops
                .set(sponsorship_budget_blocked as f64);
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

        // Isolation, then reservoir mode, is filled before normal work:
        // while normal work is eligible, at most `max(1, num_workers / 2)` of
        // the group's builders isolate or bundle reservoir-mode ops, together,
        // so they cannot starve normal bundles; once normal work is exhausted,
        // any idle builder may take them. Recomputed on every assignment.
        let isolation_limit = if candidates.is_empty() {
            group.num_workers
        } else {
            (group.num_workers / 2).max(1)
        };
        group.metrics.isolation_limit.set(isolation_limit as f64);

        if !suspect_candidates.is_empty() {
            // Rotate entrypoint order by least-recently-isolated first (stable
            // sort keeps never-isolated entrypoints in config order relative
            // to each other). Without this, suspects are always tried in
            // fixed config order, so an entrypoint that's always got enough
            // due suspects to fill isolation capacity can starve every other
            // entrypoint's suspects indefinitely - the same starvation
            // problem entrypoint_last_selected already solves for normal work.
            {
                let state = self.state.lock().unwrap();
                suspect_candidates.sort_by_key(|(ep, _)| {
                    state
                        .entrypoint_last_isolated
                        .get(&ep.key())
                        .copied()
                        .unwrap_or(0)
                });
            }

            // Reserve the isolation slot under the same lock as the capacity
            // check: concurrent builders calling assign_work must not both
            // read a count below the limit and then both insert, exceeding
            // isolation_limit. Released below if no suspect ends up
            // claimable, so a failed attempt doesn't waste the slot. The
            // gauge is refreshed inside every critical section that touches
            // `isolating_builders` so it can't go stale between mutations.
            let reserved = {
                let mut state = self.state.lock().unwrap();
                let group_state = &mut state.groups[group_idx];
                let reserved = group_state.isolating_builders.len()
                    + group_state.reservoir_builders.len()
                    < isolation_limit
                    && group_state.isolating_builders.insert(builder_address);
                group
                    .metrics
                    .isolating_builders
                    .set(group_state.isolating_builders.len() as f64);
                reserved
            };
            if reserved {
                match self
                    .assign_isolation_work(
                        group_idx,
                        builder_address,
                        suspect_candidates,
                        max_sim_block_number,
                        &required_fees,
                    )
                    .await
                {
                    Ok(Some(assignment)) => return Ok(AssignmentResult::Assigned(assignment)),
                    // No claimable suspect, or an error: free the reserved slot.
                    other => {
                        let mut state = self.state.lock().unwrap();
                        self.release_isolation_slot(&mut state, builder_address);
                        other?;
                    }
                }
            }
        }

        // With one worker the shared capacity is the only builder: take turns with normal work.
        let reservoir_turn = candidates.is_empty()
            || isolation_limit < group.num_workers
            || !self.state.lock().unwrap().groups[group_idx].reservoir_took_last_turn;
        if !reservoir_candidates.is_empty() && reservoir_turn {
            // Least-recently-chosen entrypoint first, as for isolation.
            {
                let state = self.state.lock().unwrap();
                reservoir_candidates.sort_by_key(|(ep, _)| {
                    state
                        .entrypoint_last_reservoir
                        .get(&ep.key())
                        .copied()
                        .unwrap_or(0)
                });
            }
            // Reserve the reservoir slot under the same lock as the capacity check (shared with
            // isolation), and release it if no reservoir-mode op ends up claimable.
            let reserved = {
                let mut state = self.state.lock().unwrap();
                let group_state = &mut state.groups[group_idx];
                group_state.isolating_builders.len() + group_state.reservoir_builders.len()
                    < isolation_limit
                    && group_state.reservoir_builders.insert(builder_address)
            };
            if reserved {
                match self
                    .assign_reservoir_work(
                        group_idx,
                        builder_address,
                        reservoir_candidates,
                        max_sim_block_number,
                        &required_fees,
                    )
                    .await
                {
                    Ok(Some(assignment)) => {
                        self.state.lock().unwrap().groups[group_idx].reservoir_took_last_turn =
                            true;
                        return Ok(AssignmentResult::Assigned(assignment));
                    }
                    Ok(None) => {
                        let mut state = self.state.lock().unwrap();
                        self.release_reservoir_slot(&mut state, builder_address);
                    }
                    Err(e) => {
                        let mut state = self.state.lock().unwrap();
                        self.release_reservoir_slot(&mut state, builder_address);
                        return Err(e);
                    }
                }
            }
        }

        self.state.lock().unwrap().groups[group_idx].reservoir_took_last_turn = false;
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
            ((group.num_workers as f64 * self.starvation_ratio) as usize).max(1) as u64;

        // Build candidate order with starvation prevention
        let (current_cycle, candidates) = {
            let mut state = self.state.lock().unwrap();
            let group_state = &mut state.groups[group_idx];
            group_state.global_cycle += 1;
            let current_cycle = group_state.global_cycle;

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
                is_isolation: false,
            }));
        }

        Ok(AssignmentResult::NoOperations)
    }

    /// Attempts to assign a single-operation isolation bundle for one due
    /// suspect. Returns `None` if no suspect is claimable by this builder.
    ///
    /// The caller must have already reserved `builder_address`'s isolation
    /// slot in `isolating_builders` before calling this, and releases it if
    /// `None` or an error is returned.
    async fn assign_isolation_work(
        &self,
        group_idx: usize,
        builder_address: Address,
        suspect_candidates: Vec<(EntrypointInfo, Vec<PoolOperationSummary>)>,
        max_sim_block_number: u64,
        required_fees: &GasFees,
    ) -> anyhow::Result<Option<WorkAssignment>> {
        for (ep, suspects) in suspect_candidates {
            for suspect in suspects {
                let hash = suspect.hash;
                let assigned_ops = self
                    .assign_ops_internal(
                        builder_address,
                        &ep,
                        vec![suspect],
                        max_sim_block_number,
                        required_fees,
                    )
                    .await?;
                if assigned_ops.is_empty() {
                    continue;
                }

                tracing::info!(
                    "Builder Assigner: isolation assignment of suspect op {hash:?} to builder {builder_address:?}"
                );
                {
                    let mut state = self.state.lock().unwrap();
                    // isolating_builders was already reserved by the caller.
                    // Pin so revert processing can find the proposer; suspects
                    // do not refresh starvation tracking for normal work.
                    state
                        .builder_to_pinned_proposer
                        .insert(builder_address, ep.key());
                    state
                        .builder_to_isolation_hash
                        .insert(builder_address, hash);
                    // Record this entrypoint as most-recently-isolated so the
                    // rotation in assign_work's caller moves on to other
                    // entrypoints with due suspects next time.
                    let group_state = &mut state.groups[group_idx];
                    group_state.isolation_cycle += 1;
                    let isolation_cycle = group_state.isolation_cycle;
                    state
                        .entrypoint_last_isolated
                        .insert(ep.key(), isolation_cycle);
                }
                ep_metrics_for(&ep).ep_isolation_assignments.increment(1);

                return Ok(Some(WorkAssignment {
                    entry_point: ep.address,
                    filter_id: ep.filter_id,
                    operations: assigned_ops,
                    is_isolation: true,
                }));
            }
        }

        Ok(None)
    }

    /// Attempts to assign one reservoir-mode op alone. Returns `None` if none is claimable by
    /// this builder.
    ///
    /// The caller must have already reserved `builder_address`'s slot in `reservoir_builders`,
    /// and releases it if `None` or an error is returned.
    async fn assign_reservoir_work(
        &self,
        group_idx: usize,
        builder_address: Address,
        reservoir_candidates: Vec<(EntrypointInfo, Vec<PoolOperationSummary>)>,
        max_sim_block_number: u64,
        required_fees: &GasFees,
    ) -> anyhow::Result<Option<WorkAssignment>> {
        for (ep, reservoir_ops) in reservoir_candidates {
            for op in reservoir_ops {
                let hash = op.hash;
                let assigned_ops = self
                    .assign_ops_internal(
                        builder_address,
                        &ep,
                        vec![op],
                        max_sim_block_number,
                        required_fees,
                    )
                    .await?;
                if assigned_ops.is_empty() {
                    continue;
                }

                tracing::info!(
                    "Builder Assigner: reservoir-mode assignment of op {hash:?} to builder {builder_address:?}"
                );
                {
                    let mut state = self.state.lock().unwrap();
                    state
                        .builder_to_pinned_proposer
                        .insert(builder_address, ep.key());
                    state
                        .builder_to_reservoir_hash
                        .insert(builder_address, hash);
                    let group_state = &mut state.groups[group_idx];
                    group_state.reservoir_cycle += 1;
                    let reservoir_cycle = group_state.reservoir_cycle;
                    state
                        .entrypoint_last_reservoir
                        .insert(ep.key(), reservoir_cycle);
                }
                ep_metrics_for(&ep).ep_assignments.increment(1);

                return Ok(Some(WorkAssignment {
                    entry_point: ep.address,
                    filter_id: ep.filter_id,
                    operations: assigned_ops,
                    is_isolation: false,
                }));
            }
        }

        Ok(None)
    }

    /// Assigns work for a specific entrypoint configuration.
    ///
    /// This is used internally for replacement attempts to ensure the entrypoint does not change.
    async fn assign_work_for_entrypoint(
        &self,
        group_idx: usize,
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
                // Replacement attempts never start new isolation work: an
                // in-flight accepted bundle has already cleared its ops'
                // suspect status, so suspects are not requested here.
                0,
                filter_id.clone(),
            )
            .await?;
        // Reservoir-mode ops are only ever bundled alone (`assign_reservoir_work`).
        let ops: Vec<_> = ops.into_iter().filter(|op| !op.reservoir).collect();

        let OpCounts {
            assignable: assignable_count,
            eligible: eligible_count,
            sponsorship_budget_blocked,
        } = self.count_ops(&ops, builder_address, max_sim_block_number, &required_fees);

        let ep_info = EntrypointInfo {
            address: entry_point,
            filter_id: filter_id.clone(),
        };
        let ep_metrics = ep_metrics_for(&ep_info);
        ep_metrics.ep_eligible_ops.set(eligible_count as f64);
        ep_metrics
            .ep_sponsorship_budget_blocked_ops
            .set(sponsorship_budget_blocked as f64);

        // Always update starvation tracking, even with no eligible ops.
        // This intentionally inflates the starvation counter for this entrypoint during
        // replacement attempts, which is acceptable: the entrypoint is actively being
        // worked on (fee escalation), so it shouldn't trigger starvation prevention.
        {
            let mut state = self.state.lock().unwrap();
            let group_state = &mut state.groups[group_idx];
            group_state.global_cycle += 1;
            let global_cycle = group_state.global_cycle;
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

        let assignment = WorkAssignment {
            entry_point,
            filter_id,
            operations: assigned_ops,
            is_isolation: false,
        };
        tracing::info!("Builder Assigner: assignment: {assignment:?}");

        Ok(AssignmentResult::Assigned(assignment))
    }

    /// Re-supplies the same single suspect operation for a pinned builder
    /// that needs to replace a pending isolation bundle (e.g. a fee bump).
    ///
    /// `Success` clears an op's suspect flag as soon as the RPC accepts the
    /// transaction, well before it is mined, so by the time a stuck
    /// isolation transaction needs replacing, the pool no longer reports the
    /// op as suspect. Falling through to `assign_work_for_entrypoint` at
    /// that point would query ordinary (non-suspect) work: `assign_ops_internal`
    /// could then merge other senders into a multi-op replacement bundle -
    /// reintroducing exactly the contamination risk isolation exists to
    /// prevent - or drop the op entirely if it now fails the fee/block
    /// filters, leaving its pending transaction untracked. Tracking the
    /// isolation hash independently of pool suspect state avoids both: this
    /// always returns the original op alone, or no work if it has left the
    /// pool.
    ///
    /// A reservoir-mode op (`is_isolation` false) is re-supplied the same way: it must stay alone
    /// in the replacement too.
    async fn assign_single_op_replacement(
        &self,
        builder_address: Address,
        hash: B256,
        proposer_key: ProposerKey,
        is_isolation: bool,
    ) -> anyhow::Result<AssignmentResult> {
        let Some(op) = self.pool.get_op_by_hash(hash).await? else {
            tracing::warn!(
                "Builder Assigner: single-op bundle op {hash:?} for builder {builder_address:?} no longer in pool, cannot replace"
            );
            return Ok(AssignmentResult::NoOperations);
        };

        let assignment = WorkAssignment {
            entry_point: proposer_key.0,
            filter_id: proposer_key.1,
            operations: vec![op],
            is_isolation,
        };
        tracing::info!("Builder Assigner: single-op replacement assignment: {assignment:?}");

        Ok(AssignmentResult::Assigned(assignment))
    }

    /// Count ops in a single pass under one lock acquisition.
    fn count_ops(
        &self,
        ops: &[PoolOperationSummary],
        builder_address: Address,
        max_sim_block_number: u64,
        required_fees: &GasFees,
    ) -> OpCounts {
        let state = self.state.lock().unwrap();
        let mut counts = OpCounts::default();
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
            counts.assignable += 1;
            // Counting path: never log per-op rejections here. The assignment
            // path (`assign_ops_internal`) logs them.
            if self.op_meets_fee_requirements(op, required_fees, false) {
                counts.eligible += 1;
            } else if op.bundler_sponsorship_max_cost.is_some() {
                // The sponsorship budget is the only fee check applied to a
                // bundler-sponsored op, so failing it means the op is
                // budget-blocked.
                counts.sponsorship_budget_blocked += 1;
            }
        }
        counts
    }

    /// Check if an operation meets the fee requirements for bundling.
    ///
    /// NOTE: For bundler-sponsored ops, this is an approximate check using the summary's
    /// gas_limit which does not account for dynamic pre-verification gas (PVG) calculated
    /// later by the proposer. Some sponsored ops may pass this check but be rejected
    /// during bundle proposal when exact gas costs are known.
    ///
    /// When `log` is true, logs the reason for rejection at debug level (used
    /// during assignment). Set `log` to false for counting paths to avoid
    /// duplicate log noise. Rejections are steady-state conditions that
    /// recur on every assignment pass, so they are reported as levels via
    /// the `ep_eligible_ops` and `ep_sponsorship_budget_blocked_ops` gauges
    /// rather than at info.
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
                    tracing::debug!(
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
                tracing::debug!(
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
                state.builder_to_isolation_hash.remove(&builder_address);
                self.release_isolation_slot(&mut state, builder_address);
                self.release_reservoir_slot(&mut state, builder_address);
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
        state.builder_to_isolation_hash.remove(&builder_address);
        self.release_isolation_slot(&mut state, builder_address);
        self.release_reservoir_slot(&mut state, builder_address);
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
    /// Test helper: an assigner with a single legacy group (`entry_point: None`) serving
    /// `entrypoints` with `num_signers` workers. Call `assign_work` with group `None`.
    pub(crate) fn single_group(
        pool: Box<dyn Pool>,
        entrypoints: Vec<EntrypointInfo>,
        num_signers: usize,
        max_pool_ops_per_request: u64,
        max_bundle_size: u64,
        starvation_ratio: f64,
    ) -> Self {
        Self::new(
            pool,
            vec![WorkerGroup {
                entry_point: None,
                infos: entrypoints,
                num_workers: num_signers,
            }],
            max_pool_ops_per_request,
            max_bundle_size,
            starvation_ratio,
        )
        .unwrap()
    }

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

    /// Test helper: true when `sender` is still confirmed to `builder_address`.
    pub(crate) fn test_holds_confirmed_lock(
        &self,
        builder_address: Address,
        sender: Address,
    ) -> bool {
        self.state
            .lock()
            .unwrap()
            .uo_sender_to_builder_state
            .get(&sender)
            == Some(&(builder_address, LockState::Confirmed))
    }
}

#[derive(Metrics, Clone)]
#[metrics(scope = "builder_assigner")]
struct GlobalMetrics {
    #[metric(describe = "the number of active builders.")]
    active_builders: Gauge,
}

/// Isolation metrics for one worker group. Unlabelled for the legacy group, labelled with
/// `entry_point` in the mapping layout.
#[derive(Metrics, Clone)]
#[metrics(scope = "builder_assigner")]
struct GroupMetrics {
    #[metric(describe = "the computed isolation capacity limit for the current assignment cycle.")]
    isolation_limit: Gauge,
    #[metric(describe = "the number of builders currently holding an isolation assignment.")]
    isolating_builders: Gauge,
}

/// Name of a worker group's entry point for logs and errors.
fn group_name(entry_point: Option<EntryPointVersion>) -> &'static str {
    entry_point.map_or("legacy (all)", entry_point_name)
}

/// Result of `Assigner::count_ops` for one entrypoint's ops.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct OpCounts {
    /// Not assigned to another builder and simulated at or before the max block.
    assignable: usize,
    /// Assignable and meets the fee requirements.
    eligible: usize,
    /// Assignable but bundler-sponsored with a budget that does not cover the
    /// required fee. A level, not an event: these ops are re-checked on every
    /// assignment pass and stay blocked until fees drop or the op expires.
    sponsorship_budget_blocked: usize,
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
    #[metric(
        describe = "the last-seen count of bundler-sponsored ops for this entrypoint whose sponsorship budget does not cover the required fee."
    )]
    ep_sponsorship_budget_blocked_ops: Gauge,
    #[metric(describe = "the total number of suspect isolation assignments from this entrypoint.")]
    ep_isolation_assignments: Counter,
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
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use alloy_primitives::B256;
    use rundler_types::{
        BundlerSponsorship, EntityInfos, UserOperation, UserOperationPermissions, ValidTimeRange,
        chain::ChainSpec,
        pool::MockPool,
        v0_6::{UserOperationBuilder, UserOperationRequiredFields},
    };
    use tracing::{Event, Metadata, Subscriber, span};

    use super::*;

    const TEST_ENTRY_POINT: Address = Address::ZERO;

    fn create_test_ops(senders: &[Address]) -> Vec<PoolOperation> {
        create_test_ops_for_entrypoint(senders, TEST_ENTRY_POINT)
    }

    fn mock_pool_get_ops(mock_pool: &mut MockPool, ops: Vec<PoolOperation>) {
        let ops_cloned = ops.clone();
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |_, _, _, _| {
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
            .returning(move |ep, _, _, _| {
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
            .assign_work(None, builder, u64::MAX, GasFees::default())
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
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        let result = assign_default(&assigner, address(0)).await;
        assert!(matches!(result, AssignmentResult::NoOperations));
    }

    #[tokio::test]
    async fn test_assign_work() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
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

        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
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

        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
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

        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
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

        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
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

        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
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
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
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

        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);
        let _ = assign_default(&assigner, address(0)).await;

        let err = assigner
            .confirm_senders_drop_unused(address(1), &[address(1)])
            .expect_err("should error on sender assigned to other builder");
        assert!(
            err.to_string().contains("lock contract broken"),
            "unexpected error: {err:#}"
        );
    }

    fn mock_pool_with_suspects(ops: Vec<PoolOperation>, suspect_senders: Vec<Address>) -> MockPool {
        let mut mock_pool = MockPool::new();
        let ops_cloned = ops.clone();
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |_, _, max_suspects, _| {
                Ok(ops_cloned
                    .iter()
                    .map(|op| {
                        let mut summary: PoolOperationSummary = op.into();
                        summary.suspect = suspect_senders.contains(&op.uo.sender());
                        summary
                    })
                    .filter(|summary| !summary.suspect || max_suspects > 0)
                    .collect::<Vec<_>>())
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
        mock_pool
    }

    fn mock_pool_with_reservoir(
        ops: Vec<PoolOperation>,
        reservoir_senders: Vec<Address>,
    ) -> MockPool {
        mock_pool_with_suspects_and_reservoir(ops, vec![], reservoir_senders)
    }

    fn mock_pool_with_suspects_and_reservoir(
        ops: Vec<PoolOperation>,
        suspect_senders: Vec<Address>,
        reservoir_senders: Vec<Address>,
    ) -> MockPool {
        let mut mock_pool = MockPool::new();
        let ops_cloned = ops.clone();
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |_, _, max_suspects, _| {
                Ok(ops_cloned
                    .iter()
                    .map(|op| {
                        let mut summary: PoolOperationSummary = op.into();
                        summary.suspect = suspect_senders.contains(&op.uo.sender());
                        summary.reservoir = reservoir_senders.contains(&op.uo.sender());
                        summary
                    })
                    .filter(|summary| !summary.suspect || max_suspects > 0)
                    .collect::<Vec<_>>())
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
        mock_pool
    }

    #[tokio::test]
    async fn test_reservoir_op_assigned_alone() {
        // 1 reservoir-mode op + 2 normal ops with 4 signers
        let ops = create_test_ops(&[address(1), address(2), address(3)]);
        let mock_pool = mock_pool_with_reservoir(ops, vec![address(3)]);
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        let reservoir = assign_expect_default(&assigner, address(10)).await;
        assert!(!reservoir.is_isolation);
        assert_eq!(reservoir.operations.len(), 1);
        assert_eq!(reservoir.operations[0].uo.sender(), address(3));

        let normal = assign_expect_default(&assigner, address(11)).await;
        assert_eq!(normal.operations.len(), 2);
        assert!(
            normal
                .operations
                .iter()
                .all(|op| op.uo.sender() != address(3))
        );
    }

    #[tokio::test]
    async fn test_reservoir_capped_while_normal_work_eligible() {
        // 2 reservoir-mode ops + 1 normal op with 2 signers: reservoir limit is 1
        let ops = create_test_ops(&[address(1), address(2), address(3)]);
        let mock_pool = mock_pool_with_reservoir(ops, vec![address(2), address(3)]);
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 2, 10, 10, 0.50);

        let first = assign_expect_default(&assigner, address(10)).await;
        assert_eq!(first.operations.len(), 1);
        assert_ne!(first.operations[0].uo.sender(), address(1));

        // the second builder gets the normal op, never the other reservoir-mode op
        let second = assign_expect_default(&assigner, address(11)).await;
        assert_eq!(second.operations.len(), 1);
        assert_eq!(second.operations[0].uo.sender(), address(1));
    }

    /// With one signer, reservoir mode and normal work take turns: a stream of reservoir-mode
    /// ops cannot starve normal work.
    #[tokio::test]
    async fn reservoir_single_signer_takes_turns_with_normal_work() {
        let ops = create_test_ops(&[address(1), address(2)]);
        let mock_pool = mock_pool_with_reservoir(ops, vec![address(2)]);
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 1, 10, 10, 0.50);
        let mut senders = vec![];
        for _ in 0..4 {
            let assignment = assign_cycle(&assigner, address(10)).await;
            assert_eq!(assignment.operations.len(), 1);
            senders.push(assignment.operations[0].uo.sender());
        }
        assert_eq!(senders, [address(2), address(1), address(2), address(1)]);
    }

    /// Isolation and reservoir mode share one capacity: with 2 signers, a suspect and a
    /// reservoir-mode op cannot take both builders while normal work is eligible.
    #[tokio::test]
    async fn test_reservoir_and_isolation_capped_jointly() {
        let ops = create_test_ops(&[address(1), address(2), address(3)]);
        let mock_pool =
            mock_pool_with_suspects_and_reservoir(ops, vec![address(2)], vec![address(3)]);
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 2, 10, 10, 0.50);

        let first = assign_expect_default(&assigner, address(10)).await;
        assert!(first.is_isolation);
        assert_eq!(first.operations[0].uo.sender(), address(2));

        // the second builder gets the normal op, not the reservoir-mode op
        let second = assign_expect_default(&assigner, address(11)).await;
        assert!(!second.is_isolation);
        assert_eq!(second.operations.len(), 1);
        assert_eq!(second.operations[0].uo.sender(), address(1));
    }

    #[tokio::test]
    async fn test_reservoir_replacement_stays_singleton() {
        let ops = create_test_ops(&[address(1), address(2), address(3)]);
        let reservoir_op = ops
            .iter()
            .find(|op| op.uo.sender() == address(3))
            .unwrap()
            .clone();
        let mut mock_pool = mock_pool_with_reservoir(ops, vec![address(3)]);
        mock_pool.expect_get_op_by_hash().returning(move |hash| {
            Ok((hash == reservoir_op.uo.hash()).then(|| reservoir_op.clone()))
        });
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        let first = assign_expect_default(&assigner, address(10)).await;
        assert_eq!(first.operations[0].uo.sender(), address(3));
        assigner
            .confirm_senders_drop_unused(address(10), &[address(3)])
            .unwrap();

        // a fee bump for the same builder re-supplies the op alone
        let replacement = assign_expect_default(&assigner, address(10)).await;
        assert!(!replacement.is_isolation);
        assert_eq!(replacement.operations.len(), 1);
        assert_eq!(replacement.operations[0].uo.sender(), address(3));
    }

    #[tokio::test]
    async fn test_reservoir_op_never_joins_pinned_normal_work() {
        let ops = create_test_ops(&[address(1), address(2), address(3)]);
        let mock_pool = mock_pool_with_reservoir(ops, vec![address(3)]);
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        // builder 10 takes the reservoir-mode op, builder 11 the normal work
        let _ = assign_expect_default(&assigner, address(10)).await;
        let normal = assign_expect_default(&assigner, address(11)).await;
        assert_eq!(normal.operations.len(), 2);
        assigner
            .confirm_senders_drop_unused(address(11), &[address(1)])
            .unwrap();

        // the reservoir-mode op's sender is free again, but builder 11's pinned replacement
        // still only gets normal work
        assigner.release_all(address(10));
        let replacement = assign_expect_default(&assigner, address(11)).await;
        assert!(
            replacement
                .operations
                .iter()
                .all(|op| op.uo.sender() != address(3))
        );
    }

    #[tokio::test]
    async fn test_suspect_isolated_alone() {
        // 1 suspect + 2 normal ops with 4 signers: isolation limit is 2
        let ops = create_test_ops(&[address(1), address(2), address(3)]);
        let mock_pool = mock_pool_with_suspects(ops, vec![address(3)]);
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        // the first builder isolates the suspect
        let isolation = assign_expect_default(&assigner, address(10)).await;
        assert!(isolation.is_isolation);
        assert_eq!(isolation.operations.len(), 1);
        assert_eq!(isolation.operations[0].uo.sender(), address(3));

        // the suspect is locked, so the second builder receives the normal work
        let normal = assign_expect_default(&assigner, address(11)).await;
        assert!(!normal.is_isolation);
        assert_eq!(normal.operations.len(), 2);
        assert!(
            normal
                .operations
                .iter()
                .all(|op| op.uo.sender() != address(3))
        );
    }

    #[tokio::test]
    async fn test_isolation_capped_while_normal_work_eligible() {
        // 2 suspects + 1 normal op with 2 signers: isolation limit is 1
        let ops = create_test_ops(&[address(1), address(2), address(3)]);
        let mock_pool = mock_pool_with_suspects(ops, vec![address(2), address(3)]);
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 2, 10, 10, 0.50);

        let first = assign_expect_default(&assigner, address(10)).await;
        assert!(first.is_isolation);

        // isolation capacity is used up: the second builder gets normal work
        // even though a second suspect is due
        let second = assign_expect_default(&assigner, address(11)).await;
        assert!(!second.is_isolation);
        assert_eq!(second.operations.len(), 1);
        assert_eq!(second.operations[0].uo.sender(), address(1));
    }

    #[tokio::test]
    async fn test_isolation_expands_when_no_normal_work() {
        // only suspects with 2 signers: every builder may isolate
        let ops = create_test_ops(&[address(1), address(2)]);
        let mock_pool = mock_pool_with_suspects(ops, vec![address(1), address(2)]);
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 2, 10, 10, 0.50);

        let first = assign_expect_default(&assigner, address(10)).await;
        assert!(first.is_isolation);
        assert_eq!(first.operations.len(), 1);

        let second = assign_expect_default(&assigner, address(11)).await;
        assert!(second.is_isolation);
        assert_eq!(second.operations.len(), 1);
        assert_ne!(
            first.operations[0].uo.sender(),
            second.operations[0].uo.sender()
        );
    }

    #[tokio::test]
    async fn test_isolation_slot_freed_after_release() {
        let ops = create_test_ops(&[address(1), address(2), address(3)]);
        let mock_pool = mock_pool_with_suspects(ops, vec![address(2), address(3)]);
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 2, 10, 10, 0.50);

        let first = assign_expect_default(&assigner, address(10)).await;
        assert!(first.is_isolation);

        // the isolation limit is recomputed per assignment: releasing the
        // isolating builder frees its slot for the next assignment
        assigner.release_all(address(10));

        let second = assign_expect_default(&assigner, address(11)).await;
        assert!(second.is_isolation);
    }

    #[tokio::test]
    async fn test_isolation_replacement_stays_singleton_and_pinned() {
        // 1 suspect + 2 normal ops. Once the isolation bundle is sent and its
        // sender confirmed (simulating the RPC accepting it - which reports
        // Success and clears the op's suspect flag in the real pool, well
        // before it's mined), a replacement/fee-bump attempt for the same
        // builder must keep re-supplying just the original suspect alone,
        // not fall back to ordinary (now non-suspect-looking) multi-op work.
        let ops = create_test_ops(&[address(1), address(2), address(3)]);
        let suspect_op = ops
            .iter()
            .find(|op| op.uo.sender() == address(3))
            .unwrap()
            .clone();
        let mut mock_pool = mock_pool_with_suspects(ops, vec![address(3)]);
        mock_pool
            .expect_get_op_by_hash()
            .returning(move |hash| Ok((hash == suspect_op.uo.hash()).then(|| suspect_op.clone())));
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        let isolation = assign_expect_default(&assigner, address(10)).await;
        assert!(isolation.is_isolation);
        assert_eq!(isolation.operations.len(), 1);
        assert_eq!(isolation.operations[0].uo.sender(), address(3));

        // Simulate the bundle sender confirming the isolation bundle was
        // sent (this is what promotes the sender's lock to `Confirmed`,
        // making the builder eligible for the pinned-replacement path).
        assigner
            .confirm_senders_drop_unused(address(10), &[address(3)])
            .unwrap();

        // Replacement attempt for the same builder: must stay singleton and
        // keep targeting the original suspect, not the normal ops for
        // address(1)/address(2) that a fresh query would otherwise offer.
        let replacement = assign_expect_default(&assigner, address(10)).await;
        assert!(replacement.is_isolation);
        assert_eq!(replacement.operations.len(), 1);
        assert_eq!(replacement.operations[0].uo.sender(), address(3));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_isolation_reservation_atomic_under_concurrency() {
        // 2 suspects + 1 normal op with 2 signers: isolation limit is 1.
        // Two builders race to isolate concurrently; the capacity check and
        // the isolating_builders reservation must happen under the same lock
        // so at most 1 can claim the single slot, even when both requests
        // are genuinely running in parallel (not just interleaved awaits).
        let ops = create_test_ops(&[address(1), address(2), address(3)]);
        let suspect_senders = [address(2), address(3)];
        let ops_for_summaries = ops.clone();
        let mut mock_pool = MockPool::new();
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |_, _, max_suspects, _| {
                Ok(ops_for_summaries
                    .iter()
                    .map(|op| {
                        let mut summary: PoolOperationSummary = op.into();
                        summary.suspect = suspect_senders.contains(&op.uo.sender());
                        summary
                    })
                    .filter(|summary| !summary.suspect || max_suspects > 0)
                    .collect::<Vec<_>>())
            });
        let ops_for_hashes = ops.clone();
        mock_pool
            .expect_get_ops_by_hashes()
            .returning(move |_, hashes| {
                // Widen the race window so both concurrent callers are
                // inside assign_isolation_work at the same time.
                std::thread::sleep(std::time::Duration::from_millis(20));
                Ok(ops_for_hashes
                    .iter()
                    .filter(|op| hashes.contains(&op.uo.hash()))
                    .cloned()
                    .collect::<Vec<_>>())
            });

        let assigner = Arc::new(Assigner::single_group(
            Box::new(mock_pool),
            test_entrypoints(),
            2,
            10,
            10,
            0.50,
        ));

        let a1 = assigner.clone();
        let a2 = assigner.clone();
        let h1 = tokio::spawn(async move {
            a1.assign_work(None, address(10), u64::MAX, GasFees::default())
                .await
        });
        let h2 = tokio::spawn(async move {
            a2.assign_work(None, address(11), u64::MAX, GasFees::default())
                .await
        });

        let r1 = h1.await.unwrap().unwrap();
        let r2 = h2.await.unwrap().unwrap();

        let isolating_count = [&r1, &r2]
            .into_iter()
            .filter(|r| matches!(r, AssignmentResult::Assigned(a) if a.is_isolation))
            .count();
        assert_eq!(
            isolating_count, 1,
            "exactly one concurrent request should claim the single isolation slot"
        );
    }

    #[tokio::test]
    async fn test_locked_suspect_not_reassigned() {
        let ops = create_test_ops(&[address(1)]);
        let mock_pool = mock_pool_with_suspects(ops, vec![address(1)]);
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        let first = assign_expect_default(&assigner, address(10)).await;
        assert!(first.is_isolation);

        let second = assign_default(&assigner, address(11)).await;
        assert!(matches!(second, AssignmentResult::NoOperations));
    }

    #[tokio::test]
    async fn test_suspect_respects_fee_filter() {
        // the suspect op has zero fees and doesn't meet the fee requirement
        let ops = create_test_ops(&[address(1)]);
        let mock_pool = mock_pool_with_suspects(ops, vec![address(1)]);
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        let result = assigner
            .assign_work(
                None,
                address(10),
                u64::MAX,
                GasFees {
                    max_fee_per_gas: 1,
                    max_priority_fee_per_gas: 1,
                },
            )
            .await
            .unwrap();
        assert!(matches!(result, AssignmentResult::NoOperations));
    }

    #[tokio::test]
    async fn test_suspect_query_requests_full_page_not_num_signers() {
        // Suspects come back best-fee-first, and lock/fee/block-height
        // filtering happens only after this query returns. Capping the
        // query itself at `num_signers` could hide an eligible suspect
        // behind a handful of unassignable ones ahead of it in the
        // truncated page, so the query must request a full page (matching
        // `max_ops`) instead.
        let requested_max_suspects = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let requested_max_suspects_clone = requested_max_suspects.clone();
        let mut mock_pool = MockPool::new();
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |_, _, max_suspects, _| {
                requested_max_suspects_clone
                    .store(max_suspects, std::sync::atomic::Ordering::SeqCst);
                Ok(vec![])
            });
        // num_signers deliberately small and distinct from max_pool_ops_per_request
        // so a regression back to `num_signers` would be caught.
        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 2, 1024, 10, 0.50);
        let _ = assign_default(&assigner, address(0)).await;

        assert_eq!(
            requested_max_suspects.load(std::sync::atomic::Ordering::SeqCst),
            1024,
            "suspect query should request a full page (max_pool_ops_per_request), not num_signers"
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
                    reservoir_gas: None,
                }
            })
            .collect()
    }

    const TEST_ENTRY_POINT_3: Address = Address::new([0xCC; 20]);

    fn info(address: Address) -> EntrypointInfo {
        EntrypointInfo {
            address,
            filter_id: None,
        }
    }

    fn group(
        entry_point: EntryPointVersion,
        infos: Vec<EntrypointInfo>,
        num_workers: usize,
    ) -> WorkerGroup {
        WorkerGroup {
            entry_point: Some(entry_point),
            infos,
            num_workers,
        }
    }

    /// A pool holding `(entry point, ops, suspect senders)` for any number of entry points.
    fn mock_pool_eps(eps: Vec<(Address, Vec<PoolOperation>, Vec<Address>)>) -> MockPool {
        let eps = Arc::new(eps);
        let eps_clone = eps.clone();
        let mut mock_pool = MockPool::new();
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |ep, _, _, _| {
                Ok(eps_clone
                    .iter()
                    .filter(|(address, _, _)| *address == ep)
                    .flat_map(|(_, ops, suspects)| {
                        ops.iter().map(|op| {
                            let mut summary: PoolOperationSummary = op.into();
                            summary.suspect = suspects.contains(&op.uo.sender());
                            summary
                        })
                    })
                    .collect())
            });
        mock_pool
            .expect_get_ops_by_hashes()
            .returning(move |ep, hashes| {
                Ok(eps
                    .iter()
                    .filter(|(address, _, _)| *address == ep)
                    .flat_map(|(_, ops, _)| ops.iter())
                    .filter(|op| hashes.contains(&op.uo.hash()))
                    .cloned()
                    .collect())
            });
        mock_pool
    }

    async fn assign_group(
        assigner: &Assigner,
        entry_point: EntryPointVersion,
        builder: Address,
    ) -> AssignmentResult {
        assigner
            .assign_work(Some(entry_point), builder, u64::MAX, GasFees::default())
            .await
            .unwrap()
    }

    /// Mapping layout: one assigner with a group per entry point over a pool holding work for
    /// two entry points. A builder of one group must never be handed the other's work,
    /// however many cycles run and however the work is spread.
    #[tokio::test]
    async fn test_worker_groups_never_cross_entry_points() {
        let senders_1: Vec<Address> = (1..=6).map(address).collect();
        let senders_2: Vec<Address> = (11..=16).map(address).collect();
        let ops_1 = create_test_ops_for_entrypoint(&senders_1, TEST_ENTRY_POINT);
        let ops_2 = create_test_ops_for_entrypoint(&senders_2, TEST_ENTRY_POINT_2);
        let assigner = Assigner::new(
            Box::new(mock_pool_two_eps(ops_1, ops_2)),
            vec![
                group(EntryPointVersion::V0_6, vec![info(TEST_ENTRY_POINT)], 2),
                group(EntryPointVersion::V0_7, vec![info(TEST_ENTRY_POINT_2)], 2),
            ],
            1024,
            1024,
            0.5,
        )
        .unwrap();
        let builders_1 = [address(101), address(102)];
        let builders_2 = [address(201), address(202)];

        let mut assigned = [0, 0];
        for _ in 0..20 {
            for (i, (entry_point, builders, expected)) in [
                (EntryPointVersion::V0_6, &builders_1, TEST_ENTRY_POINT),
                (EntryPointVersion::V0_7, &builders_2, TEST_ENTRY_POINT_2),
            ]
            .into_iter()
            .enumerate()
            {
                for builder in builders {
                    if let AssignmentResult::Assigned(work) =
                        assign_group(&assigner, entry_point, *builder).await
                    {
                        assert_eq!(work.entry_point, expected);
                        assigned[i] += 1;
                    }
                    assigner.release_all(*builder);
                }
            }
        }
        assert!(
            assigned.iter().all(|n| *n > 0),
            "expected both groups to receive work, got {assigned:?}"
        );
    }

    /// A sender locked by one group's builder is not assignable to another group's builder
    /// until the lock is released: sender locks are shared across entry points.
    #[tokio::test]
    async fn test_sender_lock_shared_across_worker_groups() {
        let shared_sender = address(1);
        let ops_1 = create_test_ops_for_entrypoint(&[shared_sender], TEST_ENTRY_POINT);
        let ops_2 = create_test_ops_for_entrypoint(&[shared_sender], TEST_ENTRY_POINT_2);
        let assigner = Assigner::new(
            Box::new(mock_pool_two_eps(ops_1, ops_2)),
            vec![
                group(EntryPointVersion::V0_6, vec![info(TEST_ENTRY_POINT)], 2),
                group(EntryPointVersion::V0_7, vec![info(TEST_ENTRY_POINT_2)], 2),
            ],
            1024,
            1024,
            0.5,
        )
        .unwrap();
        let builder_1 = address(101);
        let builder_2 = address(201);

        let work =
            expect_assigned(assign_group(&assigner, EntryPointVersion::V0_6, builder_1).await);
        assert_eq!(work.entry_point, TEST_ENTRY_POINT);
        assert_eq!(work.operations[0].uo.sender(), shared_sender);

        // the sender is locked by the v0.6 builder, so the v0.7 builder gets nothing
        assert!(matches!(
            assign_group(&assigner, EntryPointVersion::V0_7, builder_2).await,
            AssignmentResult::NoOperations
        ));

        // once released, the v0.7 builder can take it
        assigner.release_all(builder_1);
        let work =
            expect_assigned(assign_group(&assigner, EntryPointVersion::V0_7, builder_2).await);
        assert_eq!(work.entry_point, TEST_ENTRY_POINT_2);
        assert_eq!(work.operations[0].uo.sender(), shared_sender);
    }

    /// Isolation capacity is per group: `max(1, num_workers / 2)` of each group's own
    /// workers, not a shared pool of slots.
    #[tokio::test]
    async fn test_isolation_limit_per_worker_group() {
        // v0.6: 2 workers -> 1 isolation slot; 2 suspects + 1 normal op
        let ops_1 =
            create_test_ops_for_entrypoint(&[address(1), address(2), address(3)], TEST_ENTRY_POINT);
        // v0.7: 4 workers -> 2 isolation slots; 3 suspects + 1 normal op
        let ops_2 = create_test_ops_for_entrypoint(
            &[address(11), address(12), address(13), address(14)],
            TEST_ENTRY_POINT_2,
        );
        let assigner = Assigner::new(
            Box::new(mock_pool_eps(vec![
                (TEST_ENTRY_POINT, ops_1, vec![address(1), address(2)]),
                (
                    TEST_ENTRY_POINT_2,
                    ops_2,
                    vec![address(11), address(12), address(13)],
                ),
            ])),
            vec![
                group(EntryPointVersion::V0_6, vec![info(TEST_ENTRY_POINT)], 2),
                group(EntryPointVersion::V0_7, vec![info(TEST_ENTRY_POINT_2)], 4),
            ],
            1024,
            1024,
            0.5,
        )
        .unwrap();

        let is_isolation = |result: AssignmentResult| expect_assigned(result).is_isolation;

        // v0.6 uses its single slot, then falls back to normal work
        assert!(is_isolation(
            assign_group(&assigner, EntryPointVersion::V0_6, address(101)).await
        ));
        assert!(!is_isolation(
            assign_group(&assigner, EntryPointVersion::V0_6, address(102)).await
        ));

        // v0.7 still has both of its slots, despite v0.6 holding one
        assert!(is_isolation(
            assign_group(&assigner, EntryPointVersion::V0_7, address(201)).await
        ));
        assert!(is_isolation(
            assign_group(&assigner, EntryPointVersion::V0_7, address(202)).await
        ));
        assert!(!is_isolation(
            assign_group(&assigner, EntryPointVersion::V0_7, address(203)).await
        ));

        // releasing a v0.6 builder frees only a v0.6 slot
        assigner.release_all(address(101));
        assert!(is_isolation(
            assign_group(&assigner, EntryPointVersion::V0_6, address(101)).await
        ));
    }

    /// Starvation tracking is per group: cycles run by another group's workers don't count
    /// towards this group's starvation threshold.
    #[tokio::test]
    async fn test_starvation_counters_per_worker_group() {
        // v0.6 group serves EP1 (10 ops) and EP2 (2 ops) with 4 workers: threshold 2 cycles
        let ep1_ops = create_test_ops_for_entrypoint(
            &(10..20).map(address).collect::<Vec<_>>(),
            TEST_ENTRY_POINT,
        );
        let ep2_ops =
            create_test_ops_for_entrypoint(&[address(20), address(21)], TEST_ENTRY_POINT_2);
        // v0.7 group serves EP3
        let ep3_ops = create_test_ops_for_entrypoint(&[address(30)], TEST_ENTRY_POINT_3);
        let assigner = Assigner::new(
            Box::new(mock_pool_eps(vec![
                (TEST_ENTRY_POINT, ep1_ops, vec![]),
                (TEST_ENTRY_POINT_2, ep2_ops, vec![]),
                (TEST_ENTRY_POINT_3, ep3_ops, vec![]),
            ])),
            vec![
                group(
                    EntryPointVersion::V0_6,
                    vec![info(TEST_ENTRY_POINT), info(TEST_ENTRY_POINT_2)],
                    4,
                ),
                group(EntryPointVersion::V0_7, vec![info(TEST_ENTRY_POINT_3)], 4),
            ],
            1024,
            1024,
            0.5,
        )
        .unwrap();

        async fn cycle(assigner: &Assigner, entry_point: EntryPointVersion) -> Address {
            let work = expect_assigned(assign_group(assigner, entry_point, address(0)).await);
            assigner.release_all(address(0));
            work.entry_point
        }

        assert_eq!(
            cycle(&assigner, EntryPointVersion::V0_6).await,
            TEST_ENTRY_POINT
        );
        // many v0.7 cycles must not push EP2 past the v0.6 group's threshold
        for _ in 0..5 {
            assert_eq!(
                cycle(&assigner, EntryPointVersion::V0_7).await,
                TEST_ENTRY_POINT_3
            );
        }
        assert_eq!(
            cycle(&assigner, EntryPointVersion::V0_6).await,
            TEST_ENTRY_POINT
        );
        // the third v0.6 cycle force-selects EP2, as with a dedicated assigner
        assert_eq!(
            cycle(&assigner, EntryPointVersion::V0_6).await,
            TEST_ENTRY_POINT_2
        );
    }

    #[tokio::test]
    async fn test_new_rejects_invalid_worker_groups() {
        let new = |groups| Assigner::new(Box::new(MockPool::new()), groups, 10, 10, 0.5);
        let legacy = |infos| WorkerGroup {
            entry_point: None,
            infos,
            num_workers: 2,
        };

        assert!(new(vec![]).is_err(), "no groups");
        assert!(
            new(vec![
                group(EntryPointVersion::V0_6, vec![info(TEST_ENTRY_POINT)], 2),
                group(EntryPointVersion::V0_6, vec![info(TEST_ENTRY_POINT_2)], 2),
            ])
            .is_err(),
            "duplicate entry point"
        );
        assert!(
            new(vec![group(EntryPointVersion::V0_6, vec![], 2)]).is_err(),
            "empty infos"
        );
        assert!(
            new(vec![
                legacy(vec![info(TEST_ENTRY_POINT)]),
                group(EntryPointVersion::V0_7, vec![info(TEST_ENTRY_POINT_2)], 2),
            ])
            .is_err(),
            "legacy mixed with per-entry-point groups"
        );
        assert!(
            new(vec![
                group(EntryPointVersion::V0_6, vec![info(TEST_ENTRY_POINT)], 2),
                group(EntryPointVersion::V0_7, vec![info(TEST_ENTRY_POINT)], 2),
            ])
            .is_err(),
            "entrypoint in two groups"
        );

        let assigner = new(vec![group(
            EntryPointVersion::V0_6,
            vec![info(TEST_ENTRY_POINT)],
            2,
        )])
        .unwrap();
        assert!(
            assigner
                .assign_work(
                    Some(EntryPointVersion::V0_7),
                    address(1),
                    u64::MAX,
                    GasFees::default()
                )
                .await
                .is_err(),
            "unknown group"
        );
        assert!(
            assigner
                .assign_work(None, address(1), u64::MAX, GasFees::default())
                .await
                .is_err(),
            "legacy group not configured"
        );
    }

    fn create_test_ops_for_entrypoint(
        senders: &[Address],
        entry_point: Address,
    ) -> Vec<PoolOperation> {
        create_test_ops_inner(senders, entry_point, 0, 0)
    }

    /// Counts every tracing event emitted while installed as the default subscriber.
    struct EventCounter(Arc<AtomicUsize>);

    impl Subscriber for EventCounter {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

        fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

        fn event(&self, _event: &Event<'_>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn enter(&self, _span: &span::Id) {}

        fn exit(&self, _span: &span::Id) {}
    }

    /// A bundler-sponsored op with zero fees of its own, `call_gas_limit` gas,
    /// and a sponsorship budget of `max_cost` wei.
    fn create_sponsored_test_op(
        sender: Address,
        call_gas_limit: u128,
        max_cost: U256,
    ) -> PoolOperation {
        let mut op = create_test_ops_inner(&[sender], TEST_ENTRY_POINT, 0, 0).remove(0);
        op.uo = UserOperationBuilder::new(
            &ChainSpec::default(),
            UserOperationRequiredFields {
                sender,
                call_gas_limit,
                ..Default::default()
            },
        )
        .build()
        .into();
        op.perms.bundler_sponsorship = Some(BundlerSponsorship {
            max_cost,
            valid_until: u64::MAX,
        });
        op
    }

    fn summaries_of(ops: &[PoolOperation]) -> Vec<PoolOperationSummary> {
        ops.iter().map(|op| op.into()).collect()
    }

    fn test_assigner_with_empty_pool() -> Assigner {
        Assigner::single_group(
            Box::new(MockPool::new()),
            test_entrypoints(),
            4,
            10,
            10,
            0.50,
        )
    }

    const TEST_REQUIRED_FEES: GasFees = GasFees {
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 10,
    };

    #[test]
    fn test_count_ops_does_not_log_rejections() {
        // A bundler-sponsored op whose budget cannot cover the required fee
        // (gas_limit * required.max_fee_per_gas > max_cost), and a non-sponsored
        // op whose own fees are below the required fees. Both are rejected by
        // the fee check, and `count_ops` must count them silently: it runs on
        // every assignment pass for every entrypoint, so a per-op log line here
        // is emitted thousands of times per second for stranded ops.
        let ops = vec![
            create_sponsored_test_op(address(1), 100_000, U256::from(1)),
            create_test_ops_with_fees(&[address(2)], 1, 1).remove(0),
        ];
        let summaries = summaries_of(&ops);
        assert!(summaries[0].bundler_sponsorship_max_cost.is_some());
        assert!(summaries[1].bundler_sponsorship_max_cost.is_none());

        let assigner = test_assigner_with_empty_pool();

        let events = Arc::new(AtomicUsize::new(0));
        let counts = tracing::subscriber::with_default(EventCounter(events.clone()), || {
            assigner.count_ops(&summaries, address(0), u64::MAX, &TEST_REQUIRED_FEES)
        });

        assert_eq!(
            counts,
            OpCounts {
                assignable: 2,
                eligible: 0,
                sponsorship_budget_blocked: 1,
            }
        );
        assert_eq!(
            events.load(Ordering::SeqCst),
            0,
            "count_ops must not log per-op fee rejections"
        );
    }

    #[test]
    fn test_count_ops_reports_sponsorship_budget_blocked() {
        // gas_limit * required.max_fee_per_gas = 100_000 * 100 = 10_000_000 wei.
        let over_budget = U256::from(9_999_999);
        let exactly_budget = U256::from(10_000_000);
        let ops = vec![
            // Non-sponsored, meets the required fees: eligible.
            create_test_ops_with_fees(&[address(1)], 100, 10).remove(0),
            create_test_ops_with_fees(&[address(2)], 200, 20).remove(0),
            // Sponsored, budget covers the required fee exactly: eligible even
            // though the op's own fees are zero.
            create_sponsored_test_op(address(3), 100_000, exactly_budget),
            // Sponsored, budget one wei short: blocked.
            create_sponsored_test_op(address(4), 100_000, over_budget),
            create_sponsored_test_op(address(5), 100_000, over_budget),
            // Non-sponsored, underpriced: neither eligible nor budget-blocked.
            create_test_ops_with_fees(&[address(6)], 1, 1).remove(0),
        ];
        let assigner = test_assigner_with_empty_pool();

        let counts = assigner.count_ops(
            &summaries_of(&ops),
            address(0),
            u64::MAX,
            &TEST_REQUIRED_FEES,
        );

        assert_eq!(
            counts,
            OpCounts {
                assignable: 6,
                eligible: 3,
                sponsorship_budget_blocked: 2,
            }
        );
    }

    #[test]
    fn test_count_ops_budget_blocked_recovers_when_fees_drop() {
        // The budget check is re-evaluated against the current required fees
        // on every pass: a blocked op becomes eligible again once fees fall.
        let ops = vec![create_sponsored_test_op(
            address(1),
            100_000,
            U256::from(5_000_000),
        )];
        let summaries = summaries_of(&ops);
        let assigner = test_assigner_with_empty_pool();

        let blocked = assigner.count_ops(&summaries, address(0), u64::MAX, &TEST_REQUIRED_FEES);
        assert_eq!(
            (blocked.eligible, blocked.sponsorship_budget_blocked),
            (0, 1)
        );

        let lower_fees = GasFees {
            max_fee_per_gas: 50,
            max_priority_fee_per_gas: 5,
        };
        let recovered = assigner.count_ops(&summaries, address(0), u64::MAX, &lower_fees);
        assert_eq!(
            (recovered.eligible, recovered.sponsorship_budget_blocked),
            (1, 0)
        );
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
        let assigner =
            Assigner::single_group(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

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

    fn mock_pool_two_eps_with_suspects(
        ep1_ops: Vec<PoolOperation>,
        ep1_suspects: Vec<Address>,
        ep2_ops: Vec<PoolOperation>,
        ep2_suspects: Vec<Address>,
    ) -> MockPool {
        let mut mock_pool = MockPool::new();
        let ep1_ops_clone = ep1_ops.clone();
        let ep2_ops_clone = ep2_ops.clone();
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |ep, _, _, _| {
                let (ops, suspects) = if ep == TEST_ENTRY_POINT {
                    (&ep1_ops_clone, &ep1_suspects)
                } else {
                    (&ep2_ops_clone, &ep2_suspects)
                };
                Ok(ops
                    .iter()
                    .map(|op| {
                        let mut summary: PoolOperationSummary = op.into();
                        summary.suspect = suspects.contains(&op.uo.sender());
                        summary
                    })
                    .collect::<Vec<_>>())
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
                    .collect::<Vec<_>>())
            });
        mock_pool
    }

    #[tokio::test]
    async fn test_isolation_rotates_across_entrypoints() {
        // EP1 has 2 due suspects (address(1), address(2)) plus a normal op
        // (address(4)) so isolation stays capacity-limited to 1 slot
        // (num_signers=2 -> isolation_limit = max(1, num_signers/2) = 1
        // while normal work is eligible). EP2 has a single due suspect
        // (address(3)) and no normal work.
        //
        // Before rotation tracking, suspect candidates were always tried in
        // fixed config order [EP1, EP2]. Since EP1's suspects are always
        // assignable once released, every single isolation slot would go to
        // EP1 forever, and EP2's suspect would never be reached. With
        // last-isolated rotation, isolation assignments should alternate
        // between the two entrypoints instead.
        let ep1_ops =
            create_test_ops_for_entrypoint(&[address(1), address(2), address(4)], TEST_ENTRY_POINT);
        let ep2_ops = create_test_ops_for_entrypoint(&[address(3)], TEST_ENTRY_POINT_2);
        let mock_pool = mock_pool_two_eps_with_suspects(
            ep1_ops,
            vec![address(1), address(2)],
            ep2_ops,
            vec![address(3)],
        );
        let assigner =
            Assigner::single_group(Box::new(mock_pool), two_entrypoints(), 2, 1024, 1024, 0.50);

        let mut entry_points = Vec::new();
        for i in 0..4 {
            let assignment = assign_cycle(&assigner, address(0)).await;
            assert!(
                assignment.is_isolation,
                "round {i} should be an isolation assignment"
            );
            entry_points.push(assignment.entry_point);
        }

        assert_eq!(
            entry_points,
            vec![
                TEST_ENTRY_POINT,
                TEST_ENTRY_POINT_2,
                TEST_ENTRY_POINT,
                TEST_ENTRY_POINT_2,
            ],
            "isolation should alternate across entrypoints instead of starving EP2"
        );
    }

    /// Reservoir-mode ops on two entrypoints, with normal work on the first so one builder at a
    /// time bundles reservoir-mode ops: assignments alternate rather than starve the second.
    #[tokio::test]
    async fn test_reservoir_rotates_across_entrypoints() {
        let ep1_ops =
            create_test_ops_for_entrypoint(&[address(1), address(2), address(4)], TEST_ENTRY_POINT);
        let ep2_ops = create_test_ops_for_entrypoint(&[address(3)], TEST_ENTRY_POINT_2);
        let reservoir = [address(1), address(2), address(3)];
        let mut mock_pool = MockPool::new();
        let (ep1_clone, ep2_clone) = (ep1_ops.clone(), ep2_ops.clone());
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |ep, _, _, _| {
                let ops = if ep == TEST_ENTRY_POINT {
                    &ep1_clone
                } else {
                    &ep2_clone
                };
                Ok(ops
                    .iter()
                    .map(|op| {
                        let mut summary: PoolOperationSummary = op.into();
                        summary.reservoir = reservoir.contains(&op.uo.sender());
                        summary
                    })
                    .collect::<Vec<_>>())
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
                    .collect::<Vec<_>>())
            });
        let assigner =
            Assigner::single_group(Box::new(mock_pool), two_entrypoints(), 2, 1024, 1024, 0.50);

        let mut entry_points = Vec::new();
        for _ in 0..4 {
            let assignment = assign_cycle(&assigner, address(0)).await;
            assert_eq!(assignment.operations.len(), 1);
            entry_points.push(assignment.entry_point);
        }
        assert_eq!(
            entry_points,
            vec![
                TEST_ENTRY_POINT,
                TEST_ENTRY_POINT_2,
                TEST_ENTRY_POINT,
                TEST_ENTRY_POINT_2,
            ]
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
        let assigner =
            Assigner::single_group(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 0.50);

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
            .returning(move |ep, _, _, _| {
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

        let assigner =
            Assigner::single_group(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

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
            .returning(move |_, _, _, _| {
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

        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        // Request with required_fees=(50, 5)
        // Only ops with max_fee >= 50 and priority_fee >= 5 should be eligible
        let required_fees = GasFees {
            max_fee_per_gas: 50,
            max_priority_fee_per_gas: 5,
        };

        let assignment = expect_assigned(
            assigner
                .assign_work(None, address(0), u64::MAX, required_fees)
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
        let assigner =
            Assigner::single_group(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

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
            .returning(move |ep, _, _, _| {
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

        let assigner =
            Assigner::single_group(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

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

        let assigner =
            Assigner::single_group(Box::new(mock_pool), two_entrypoints(), 4, 1024, 1024, 100.0);

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
            .returning(move |_, _, _, _| {
                Ok(low_fee_ops.iter().map(|op| op.into()).collect::<Vec<_>>())
            });

        let assigner =
            Assigner::single_group(Box::new(mock_pool), test_entrypoints(), 4, 10, 10, 0.50);

        // Request with high fee requirements - no ops should be eligible
        let required_fees = GasFees {
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 50,
        };

        let result = assigner
            .assign_work(None, address(0), u64::MAX, required_fees)
            .await
            .unwrap();

        assert!(matches!(
            result,
            AssignmentResult::NoOperationsAfterFeeFilter
        ));
    }
}
