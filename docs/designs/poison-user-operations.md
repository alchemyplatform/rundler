# Poison User Operations

Status: Draft

## Goals

1. **Liveness:** isolate suspected poison UOs and eventually remove UOs that continue to
   fail, preventing them from blocking bundle submission indefinitely.
2. **Fairness:** schedule healthy and suspect UOs so neither work class can starve the
   other.
3. **Provider resilience:** prevent provider-health events from converting healthy UOs
   into suspects (best effort, via detection) or removing them (unconditional, via
   evidence spacing).

## How the goals are achieved

### Liveness

Attributed execution failures and singleton terminal RPC errors remove their UOs
immediately. Ambiguous multi-UO failures move their UOs into suspect isolation, where
each is attempted alone. Repeated non-terminal failures from an isolated UO are spaced
with exponential backoff and eventually remove the UO at the configured threshold.

Setting `--pool.max_suspect_rpc_failures=0` deliberately disables the eventual-removal
guarantee for non-terminal failures.

### Fairness

Suspects cannot consume normal bundle capacity because they are submitted alone and
isolation is capped while normal work remains. When both work classes are eligible, the
assigner fills isolation capacity up to `max(1, num_signers / 2)` and uses the remaining
builders for normal bundles. When normal work is exhausted, the limit expands so idle
builders can drain suspects. Per-suspect backoff prevents one suspect from continuously
consuming isolation capacity.

Two-way starvation protection requires at least two builders. With one builder and no
alternation rule, the scheduler cannot guarantee progress for both work classes when
both remain continuously eligible.

### Provider resilience

Protection is two-tier. Suspect creation is gated by detection: only final outcomes
after provider retries and fallbacks affect the provider-event signal, and while an
event is active, non-terminal failures do not advance pre-suspect counts, so an outage
cannot mass-convert the pool into suspects. Removal is protected independently of
detection: the suspect backoff schedule spaces removal-counter increments so that a
single provider incident contributes at most one increment (see "Non-terminal RPC
evidence").

Detection requires a rolling sample, so failures observed before the signal activates
may still create suspects. Because suspicion is recoverable — a healthy suspect
succeeds in isolation and clears — detection lag costs wasted singleton attempts, not
false removals. Terminal RPC errors bypass provider-health gating because they
definitively reject the transaction.

## Failure flow

| Failure | Bundle size | Action |
| --- | ---: | --- |
| Attributed execution failure | Any | Remove the attributed UOs immediately. |
| Unattributed mined revert | 1 | Remove the sole UO immediately. |
| Unattributed mined revert | More than 1 | Mark every UO as suspect. |
| Terminal RPC error | 1 | Remove the sole UO immediately. |
| Terminal RPC error | More than 1 | Mark every UO as suspect immediately. |
| Non-terminal provider failure while provider is healthy | Any | Increment each non-suspect UO's RPC-failure count; mark it suspect at the configured threshold. |
| Non-terminal provider failure from an isolated suspect | 1 | Increment its suspect removal count, back off, and remove it at the configured threshold. |
| Non-terminal provider failure from a normal bundle during a provider event | Any | Do not advance pre-suspect counts; no other UO state change. |
| Known operational error | Any | Preserve existing behavior. |

Provider retries and configured fallbacks are exhausted before an RPC outcome enters
this flow. A successful fallback has no effect on UO state.

A terminal RPC error is a final response indicating that the transaction was rejected
and should not be retried unchanged. It bypasses provider-health gating and repeated-
failure thresholds. Transport failures, timeouts, and responses that leave acceptance
unknown are non-terminal.

## Provider-event signal

Each configured submission route, including its primary and fallbacks, maintains a
rolling window shared by its builders. Only final submission outcomes are recorded:

- `Success`: the transaction was accepted.
- `ProviderFailure`: non-terminal transport failure, timeout, sender unavailable, or
  exhausted rate limit.
- `Neutral`: known operational errors such as underpriced or nonce-too-low. Neutral
  outcomes are excluded from the window.

Terminal RPC errors are handled before this signal and are excluded from its window.

Initial parameters:

- Window: last 20 non-neutral outcomes.
- Enter a provider event after at least 10 observations when at least 30% are failures.
- Exit the event when fewer than 10% are failures.

Different enter and exit thresholds prevent flapping. The signal does not change bundle
construction or submission rate; existing provider rate limiting handles request pacing.

The signal has exactly one effect: while a provider event is active, non-terminal
failures do not advance pre-suspect counts, so no new suspects are created. Suspect
backoff and removal counting are unaffected by the signal; false removal is bounded by
the backoff schedule's evidence spacing rather than by detection. Because the gate's
only failure mode is recoverable suspicion, no counter state is cleared when an event
is entered or exited.

## Non-terminal RPC evidence

Each UO carries a single failure counter measured against two thresholds. Suspect
status is derived, not stored: a UO is a suspect once its counter reaches
`--pool.rpc_failures_before_suspect` (default `3`), and is removed
`--pool.max_suspect_rpc_failures` (default `3`) failures later.

1. Outside a provider event, a final non-terminal provider failure increments the
   failure counter of every UO in the failed bundle. During an event, only counters
   already past the suspect threshold advance.
2. A successful submission resets the failure counter of every UO in that bundle,
   clearing suspect status.
3. At the suspect threshold the UO is excluded from normal bundles and becomes
   eligible for an immediate isolation attempt.
4. Each failure past the suspect threshold schedules an exponentially increasing
   retry delay with jitter, and counts toward removal regardless of provider-event
   state.
5. At `suspect threshold + max_suspect_rpc_failures` total failures, the pool removes
   the UO and logs `RepeatedNonTerminalRpcFailure`.

Ambiguous multi-UO terminal failures and unattributed mined reverts force suspicion
by raising the counter directly to the suspect threshold, never lowering it.

`--pool.max_suspect_rpc_failures=0` disables RPC-based removal. Provider events pause
pre-suspect counting only; suspect removal counting and backoff continue.

Suspect backoff is configured with `--pool.suspect_rpc_backoff_initial_secs`
(default `1`) and `--pool.suspect_rpc_backoff_max_secs` (default `600`). The schedule
bounds false removal: the cumulative delay across `max_suspect_rpc_failures`
consecutive attempts must exceed the longest provider incident that removal should
tolerate, so that a single incident contributes at most one removal increment. The
defaults favor fast poison eviction — the first three increments span only a few
seconds, so a provider blip can remove a suspect. Tolerating a 30-minute incident
requires a larger initial (for example 600 seconds: 10 m + 20 m between increments),
a steeper curve, or a higher removal threshold.

## Suspect scheduling

- Suspects are excluded from normal bundles and are attempted one UO at a time after
  their retry delay has elapsed.
- When both work classes are eligible, isolation assignments are filled up to the
  current isolation limit and remaining builders receive normal work.
- When normal work is eligible, new isolation assignments may use at most
  `max(1, num_signers / 2)` builders.
- When all normal work has been assigned or is otherwise ineligible, every builder may
  isolate.
- The assigner recomputes this limit for every assignment.
- Existing isolation transactions are not canceled when normal work arrives, but no new
  isolation work is assigned above the reduced limit.

A successful isolation submission follows normal transaction tracking. A mined revert
or terminal RPC error removes the UO immediately. Other failures preserve its suspect
state.

## State ownership

The submission route owns the provider-event signal; the pool consumes it as a single
boolean gate on pre-suspect counting. The pool owns each UO's failure counter (from
which suspect status is derived) and suspect retry time so they are shared across
builders and cleared with the UO lifecycle. This state is in-memory and does not track
transaction hashes for deduplication.

## Tradeoffs

- **Liveness versus false removal:** eventual removal protects bundling, but failures
  persisting across the entire backoff span can still remove a healthy UO — for
  example, a provider incident longer than the cumulative suspect backoff. Higher
  thresholds and longer backoff reduce false removals but extend poison lifetime.
- **Isolation versus throughput:** singleton attempts identify poison UOs without adding
  innocent fillers, but consume more transactions than normal bundles. The dynamic
  isolation limit preserves normal capacity at the cost of slower suspect draining.
- **Provider protection versus poison detection:** pausing pre-suspect counting during
  provider events prevents mass false suspicion, but a poison UO encountered during an
  event takes longer to identify. Detection lag can still create false suspects before
  the signal activates; each costs one wasted singleton attempt after recovery and then
  self-clears. An outage that outlasts detection lag may still suspect part of the
  pool, which drains at singleton throughput after recovery.
- **Backoff versus recovery latency:** per-suspect backoff prevents hot loops and resource
  churn, but delays successful retry after a transient failure.

## Implementation plan

Five self-contained PRs that build in order. PRs 1–2 are inert plumbing (no visible
behavior change), PR 3 is the behavior switch, and PRs 4–5 are independent of each
other once PR 3 lands.

### PR 1 — Terminal vs. non-terminal error classification (foundation)

Everything downstream depends on knowing whether a submission failure is terminal,
non-terminal, or neutral. Today that distinction is destroyed before the bundle sender
sees it.

- Add a classification to `TxSenderError` (`crates/builder/src/sender/mod.rs`):
  terminal (final rejection, don't retry unchanged), non-terminal (transport failure,
  timeout, `SenderUnavailable`, rate-limit exhaustion), neutral (underpriced,
  nonce-too-low, other known operational errors). A small `enum RpcOutcomeClass` plus a
  `classify()` method is enough.
- Fix the collapse in `From<TxSenderError> for TransactionTrackerError`
  (`crates/builder/src/transaction_tracker.rs`), where `SenderUnavailable` and `Other`
  both become `TransactionTrackerError::Other`. The tracker error must carry the class
  through to `bundle_sender.rs`.
- Route the `-32000: internal error` class to non-terminal-ambiguous (it currently maps
  to `SenderUnavailable`). Per this design, this supersedes the PR #1304 approach —
  that PR's remove-all behavior must not land alongside this.

### PR 2 — Pool-owned suspect state + trait surface

- Add per-UO mutable state to `OrderedPoolOperation`
  (`crates/pool/src/mempool/pool.rs`), which already uses interior `RwLock`s: a single
  `failures: u32` counter plus `retry_after: Option<Instant>`. Suspect status is
  derived from the counter against the two thresholds; a success resets it. State
  dies with the UO — no separate tracker needed.
- Add config to `PoolConfig` (`crates/pool/src/mempool/mod.rs`) and CLI args in
  `bin/rundler/src/cli/pool.rs`: `rpc_failures_before_suspect` (default 3),
  `max_suspect_rpc_failures` (default 3, 0 disables removal),
  `suspect_rpc_backoff_initial_secs` (default 1), `suspect_rpc_backoff_max_secs`
  (default 600).
- Add one new `Pool` trait method (`crates/types/src/pool/traits.rs`),
  `report_bundle_outcome(entry_point, ops, outcome, provider_event_active)`, where
  outcome is success / non-terminal failure / terminal failure / mark-suspect. The
  pool applies the failure-flow table internally: reset counters on success,
  increment counters on non-terminal failure (skipping non-suspects while a provider
  event is active), compute backoff for isolated suspects, remove at the removal
  threshold with a new `OpRemovalReason::RepeatedNonTerminalRpcFailure`, and remove
  terminally rejected singletons with `OpRemovalReason::TerminalRpcError`
  (`crates/pool/src/emit.rs`). Implement in `UoPool`, `LocalPoolHandle`, and the
  remote protobuf client/server.
- Exclude suspects from `best_operations` (`crates/pool/src/mempool/pool.rs`). Rather
  than a new query method, `get_ops_summaries` takes a `max_suspects` cap and appends
  due suspects (retry delay elapsed) to its response, marked with a `suspect` flag on
  `PoolOperationSummary`; the assigner passes `max_suspects: 0` until PR 4. Because
  the flag rides on the summary, this degrades gracefully if PR 3 lands first:
  requesting no suspects leaves them waiting invisibly, and any nonzero cap without
  isolation scheduling simply restores today's behavior.

### PR 3 — Failure flow in the bundle sender

Wire `bundle_sender.rs` to call `report_bundle_outcome` per the failure-flow table:

- **Attributed execution failures**: already removed via `rejected_op_hashes` —
  unchanged.
- **Unattributed mined revert** (`handle_pending_state` → `process_revert`, decoding in
  `bundle_proposer.rs`): the `None | Revert | PostOpRevert` arm currently removes all
  ops; change to remove if bundle size is 1, mark all suspect if greater than 1.
  `FailedOp` stays remove-attributed.
- **Terminal RPC error**: same size-1-remove / larger-suspect branch, in the
  `Err(error)` arm of `handle_building_state` using PR 1's classification.
- **Non-terminal failure**: report to the pool so it increments pre-suspect counts
  (normal bundle) or removal count + backoff (isolation bundle). The sender needs to
  know which kind of bundle it sent — a flag on the assignment (PR 4) or on the send
  context.
- **Success**: report so the pool clears pre-suspect counts for the bundle's ops.

Risk note: once the multi-UO remove-all path becomes mark-suspect, suspects sit
excluded from bundles with nothing draining them until PR 4 lands. Either land PR 3
and PR 4 together, or keep suspects eligible for normal bundles in PR 3 and gate
exclusion behind PR 4.

### PR 4 — Suspect scheduling in the assigner

- In `Assigner` (`crates/builder/src/assigner.rs`, which already holds `num_signers`):
  when assigning work, fetch due suspects alongside normal summaries. While normal work
  is eligible, cap new isolation assignments at `max(1, num_signers / 2)`; when normal
  work is exhausted, let any idle builder isolate. Recompute the limit per assignment;
  never cancel in-flight isolation work.
- An isolation assignment is a single-UO bundle for one suspect, tagged so the bundle
  sender reports outcomes down the suspect path (PR 3). Mined revert or terminal error
  in isolation removes immediately; success follows normal tracking and clears suspect
  state; other failures keep it suspect and back off.
- The one-builder caveat (no two-way starvation guarantee with a single signer) needs
  no code — document it on the CLI args.

### PR 5 — Provider-event signal

- Implement the rolling window (last 20 non-neutral final outcomes; enter event at ≥10
  observations with ≥30% failures, exit below 10%) as a small shared struct owned by
  the submission route. Record outcomes in `FallbackTransactionSender`
  (`crates/builder/src/sender/fallback.rs`) after retries/fallbacks are exhausted —
  success, `ProviderFailure`, or neutral (excluded). Non-fallback senders wrap the same
  recorder.
- Expose it as a shared `Arc` boolean checked by the bundle sender when calling
  `report_bundle_outcome` (the `provider_event_active` flag from PR 2). Its only
  effect: pause pre-suspect counting. No counters are cleared on enter/exit, and
  suspect backoff/removal counting are unaffected.
- Ships last deliberately — without it the system is fully functional, just without
  outage protection for suspect creation (removal is already protected by backoff
  spacing from PR 2).

## Related work

- **EIP-7702 auth-nonce recheck at bundle assembly** (fix 2 in
  `INVESTIGATION-empty-revert-bundle-livelock.md`): re-validating authorization tuple
  nonces at proposal time deterministically prevents the primary observed poison class
  before it ever reaches this system. Companion change, tracked separately.
- **PR #1304 (`fix(builder): remove ops after internal RPC error`):** removing every UO
  in a bundle on a terminal `-32000: internal error` is superseded by this design. That
  error class should instead follow the ambiguous multi-UO path (mark every UO suspect)
  so innocent UOs survive; the two mechanisms must not both fire on the same error.
