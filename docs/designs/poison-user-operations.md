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

1. Outside a provider event, a final non-terminal provider failure increments the
   pre-suspect count of every UO in the failed bundle. During an event, pre-suspect
   counts do not advance.
2. A successful submission clears the pre-suspect counts of every UO in that bundle.
3. At `--pool.rpc_failures_before_suspect` (default `3`), a UO becomes a suspect and its
   count resets.
4. A final provider failure from its single-UO attempt schedules an exponentially
   increasing retry delay with jitter.
5. The failure also increments the suspect's removal count, regardless of
   provider-event state.
6. At `--pool.max_suspect_rpc_failures` (default `3`), the pool removes the UO and logs
   `RepeatedNonTerminalRpcFailure`.

`--pool.max_suspect_rpc_failures=0` disables RPC-based removal. Provider events pause
pre-suspect counting only; suspect removal counting and backoff continue.

Suspect backoff is configured with `--pool.suspect_rpc_backoff_initial_secs` and
`--pool.suspect_rpc_backoff_max_secs`. The schedule is load-bearing for the
false-removal bound: the cumulative delay across `max_suspect_rpc_failures` consecutive
attempts must exceed the longest provider incident that removal should tolerate, so
that a single incident contributes at most one removal increment. With doubling from a
60-second initial, three increments span only about three minutes; tolerating a
30-minute incident requires a larger initial (for example 600 seconds: 10 m + 20 m
between increments), a steeper curve, or a higher removal threshold.

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
boolean gate on pre-suspect counting. The pool owns pre-suspect counts, suspect status,
suspect removal counts, and suspect retry times so they are shared across builders and
cleared with the UO lifecycle. This state is in-memory and does not track transaction
hashes for deduplication.

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

## Related work

- **EIP-7702 auth-nonce recheck at bundle assembly** (fix 2 in
  `INVESTIGATION-empty-revert-bundle-livelock.md`): re-validating authorization tuple
  nonces at proposal time deterministically prevents the primary observed poison class
  before it ever reaches this system. Companion change, tracked separately.
- **PR #1304 (`fix(builder): remove ops after internal RPC error`):** removing every UO
  in a bundle on a terminal `-32000: internal error` is superseded by this design. That
  error class should instead follow the ambiguous multi-UO path (mark every UO suspect)
  so innocent UOs survive; the two mechanisms must not both fire on the same error.
