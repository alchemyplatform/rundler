# Poison User Operations

Status: Draft

## Goals

1. **Liveness:** isolate suspected poison UOs and eventually remove UOs that continue to
   fail, preventing them from blocking bundle submission indefinitely.
2. **Fairness:** schedule healthy and suspect UOs so neither work class can starve the
   other.
3. **Provider resilience:** once a provider-health event is detected, no UO makes
   progress toward removal, so provider issues cannot remove operations. Suspect
   analysis continues during events because suspicion is recoverable and isolation is
   what protects bundling. Detection is best effort; the suspect backoff schedule
   spaces evidence to bound damage from undetected incidents.

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

A detected provider event pauses removal, not analysis. While an event is active,
non-terminal failures still count toward suspicion — quarantine keeps working — but a
suspect's counter freezes: it makes no progress toward removal, and failures during
the event never contribute to a later removal. Suspects failing during an event still
refresh their isolation backoff so retries stay spaced.

Suspicion deliberately stays live during events because gating it is exploitable: a
herd of poison UOs large enough to trip the provider-event signal with its own
failures would otherwise keep riding in normal bundles — unsuspectable for exactly as
long as it sustains the event. With analysis live, such a herd is quarantined into
isolation even while the event is active; once quarantined, normal bundles recover,
the event clears, and removal resumes. The cost is that a genuine outage progressively
suspects the UOs it touches; suspicion is recoverable, so after recovery each false
suspect clears itself with one successful singleton, at isolation throughput.

Detection requires a rolling sample, so failures observed before the signal activates
still count; the suspect backoff schedule spaces those increments to bound the damage
from an undetected incident. Because suspicion is recoverable — a healthy suspect
succeeds in isolation and clears — detection lag mostly costs wasted singleton
attempts. Terminal RPC errors bypass provider-health gating because they definitively
reject the transaction.

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
| Non-terminal provider failure during a provider event | Any | Non-suspects accrue toward suspicion as normal; suspects only refresh their isolation backoff, making no removal progress. |
| Known operational error | Any | Preserve existing behavior. |

The entire flow is gated behind `--pool.suspect_tracking_enabled` (default `false`).
When disabled, no operation is ever suspected, and no new removal path (RPC-failure
thresholds, terminal-error suspicion) fires. The one exception: an unattributed
multi-op revert still removes every op, exactly as it did before this system existed —
disabling the switch must not regress bundling to the pre-feature livelock this
mechanism was partly designed to close (see
`INVESTIGATION-empty-revert-bundle-livelock.md`). This allows the mechanism to ship
dark and be enabled deliberately once every stage — including the provider-event
signal — is deployed.

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

The signal has exactly one effect: while a provider event is active, suspects make no
progress toward removal. Suspect creation and isolation backoff are unaffected. No
counter state is cleared when an event is entered or exited.

## Non-terminal RPC evidence

Each UO carries a single failure counter measured against two thresholds. Suspect
status is derived, not stored: a UO is a suspect once its counter reaches
`--pool.rpc_failures_before_suspect` (default `3`), and is removed
`--pool.max_suspect_rpc_failures` (default `8`) failures later.

1. A final non-terminal provider failure increments the failure counter of every
   non-suspect UO in the failed bundle. During a provider event, suspects' counters
   freeze; non-suspects continue to accrue.
2. A successful submission resets the failure counter of every UO in that bundle,
   clearing suspect status.
3. At the suspect threshold the UO is excluded from normal bundles and becomes
   eligible for an immediate isolation attempt.
4. Each counted failure past the suspect threshold schedules an exponentially
   increasing retry delay with jitter.
5. At `suspect threshold + max_suspect_rpc_failures` total failures, the pool removes
   the UO and logs `RepeatedNonTerminalRpcFailure`.

Ambiguous multi-UO terminal failures and unattributed mined reverts force suspicion
by raising the counter directly to the suspect threshold, never lowering it.

`--pool.max_suspect_rpc_failures=0` disables RPC-based removal. Provider events pause
removal progress only; suspect creation and isolation backoff continue.

Suspect backoff is configured with `--pool.suspect_rpc_backoff_initial_secs`
(default `1`) and `--pool.suspect_rpc_backoff_max_secs` (default `600`). Detected
provider events pause removal progress entirely; the backoff schedule bounds false
removal from incidents the signal misses (detection lag, or failure rates below the
event threshold): the cumulative delay across `max_suspect_rpc_failures` consecutive
attempts must exceed the longest undetected incident that removal should tolerate.
The defaults spend roughly four minutes of cumulative backoff (1+2+4+8+16+32+64+128s
before jitter) across the 8 allowed failures before removal, giving the
provider-event signal a real chance to observe a genuine incident and pause removal
before it fires. Tolerating longer undetected incidents still requires a larger
initial, a steeper curve, or a higher removal threshold.

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

One provider-event signal exists per submission route, shared by the route's builders;
the bundle sender records final outcomes into it downstream of provider retries and
fallbacks, and the pool consumes it as a single boolean gate on suspect removal
progress. The pool owns each UO's failure counter (from
which suspect status is derived) and suspect retry time so they are shared across
builders and cleared with the UO lifecycle. This state is in-memory and does not track
transaction hashes for deduplication.

## Tradeoffs

- **Liveness versus false removal:** eventual removal protects bundling, but
  failures persisting across the backoff span during an undetected incident can
  still remove a healthy UO. Higher thresholds and longer backoff reduce false
  removals but extend poison lifetime. Poison that sustains a provider event is
  quarantined but not removed until the event clears; bundling is protected by the
  quarantine, and pool size and age limits bound the accumulation.
- **Isolation versus throughput:** singleton attempts identify poison UOs without adding
  innocent fillers, but consume more transactions than normal bundles. The dynamic
  isolation limit preserves normal capacity at the cost of slower suspect draining.
- **Provider protection versus poison detection:** pausing removal during provider
  events guarantees provider issues cannot remove UOs, at the cost that poison
  sustaining an event lingers in isolation until the event clears. Keeping suspect
  analysis live during events closes the herd loophole but means a genuine outage
  progressively suspects the UOs it touches; each false suspect self-clears with one
  successful singleton after recovery, so a long outage drains at isolation
  throughput afterward.
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
  `bin/rundler/src/cli/pool.rs`: `suspect_tracking_enabled` (default false, the
  master switch), `rpc_failures_before_suspect` (default 3),
  `max_suspect_rpc_failures` (default 8, 0 disables removal),
  `suspect_rpc_backoff_initial_secs` (default 1), `suspect_rpc_backoff_max_secs`
  (default 600).
- Add one new `Pool` trait method (`crates/types/src/pool/traits.rs`),
  `report_bundle_outcome(entry_point, ops, outcome, provider_event_active)`, where
  outcome is success / non-terminal failure / terminal failure / mark-suspect. The
  pool applies the failure-flow table internally: reset counters on success,
  increment counters on non-terminal failure (suspects' counters freeze while a
  provider event is active), compute backoff for isolated suspects, remove at the
  removal threshold with a new `OpRemovalReason::RepeatedNonTerminalRpcFailure`, and
  remove
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
  observations with ≥30% failures, exit below 10%) as a small shared struct
  (`ProviderEventSignal`, `crates/builder/src/sender/health.rs`), one per submission
  route, shared by the route's builders.
- Record outcomes in the bundle sender where it already classifies final submission
  results (`send_bundle_from_data`): this sits downstream of the
  `FallbackTransactionSender`'s internal retries and failover, so only final outcomes
  after retries/fallbacks are observed — success, non-terminal provider failure, or
  neutral/terminal (excluded). Cancellation transactions are not recorded.
- The bundle sender checks the signal when calling `report_bundle_outcome` (the
  `provider_event_active` flag from PR 2), recording a failure before reporting it so
  the report is gated by the freshest state. The signal's only effect: pause suspect
  removal progress. Suspect creation and backoff are unaffected, and no counters are
  cleared on enter/exit.
- Consider recording only transport-level failures (timeouts, connection failures,
  sender unavailable) in the window and excluding error responses: a node that
  evaluates a transaction and answers is not an outage, and rejected-with-a-response
  is what poison looks like, so this keeps poison herds from tripping the signal at
  all.
- Ships last deliberately — without it the system is fully functional, just without
  outage protection (bounded in the interim only by the backoff spacing from PR 2).
- Deliberately independent of `FallbackTransactionSender`'s own consecutive-failure
  failover: that counter reacts to a handful of consecutive errors from one builder's
  primary sender so it can reroute traffic quickly, while this signal needs a larger,
  hysteretic sample across all of a route's builders before it gates something as
  consequential as pausing removal pool-wide. It's also circular to feed one from the
  other — the signal only observes outcomes *after* failover has already run. The two
  stay independently tunable.

## Related work

- **EIP-7702 auth-nonce recheck at bundle assembly** (fix 2 in
  `INVESTIGATION-empty-revert-bundle-livelock.md`): re-validating authorization tuple
  nonces at proposal time deterministically prevents the primary observed poison class
  before it ever reaches this system. Companion change, tracked separately.
- **PR #1304 (`fix(builder): remove ops after internal RPC error`):** removing every UO
  in a bundle on a terminal `-32000: internal error` is superseded by this design. That
  error class should instead follow the ambiguous multi-UO path (mark every UO suspect)
  so innocent UOs survive; the two mechanisms must not both fire on the same error.
