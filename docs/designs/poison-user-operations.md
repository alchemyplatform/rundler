# Poison User Operations

Status: Draft

## Goals

1. **Liveness:** isolate suspected poison UOs and eventually remove UOs that continue to
   fail, preventing them from blocking bundle submission indefinitely.
2. **Fairness:** schedule healthy and suspect UOs so neither work class can starve the
   other.
3. **Provider resilience:** detect provider-health events and prevent their failures from
   causing non-poison UOs to be removed in most cases.

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

Only final outcomes after provider retries and fallbacks affect the provider-event
signal. During a detected event, non-terminal failures do not create suspects, advance
removal counters, or remove UOs. Entering the event clears accumulated non-terminal
failure evidence, while suspect backoff continues to limit repeated isolation attempts.

Detection requires a rolling sample, so failures observed before the signal activates
may still affect UO state. Terminal RPC errors also bypass provider-health gating because
they definitively reject the transaction. These are the principal cases in which a
provider event could still affect a non-poison UO.

## Failure flow

| Failure | Bundle size | Action |
| --- | ---: | --- |
| Attributed execution failure | Any | Remove the attributed UOs immediately. |
| Unattributed mined revert | 1 | Remove the sole UO immediately. |
| Unattributed mined revert | More than 1 | Mark every UO as suspect. |
| Terminal RPC error | 1 | Remove the sole UO immediately. |
| Terminal RPC error | More than 1 | Mark every UO as suspect immediately. |
| Non-terminal provider failure while provider is healthy | Any | Increment each non-suspect UO's RPC-failure count; mark it suspect at the configured threshold. |
| Non-terminal provider failure from an isolated suspect while provider is healthy | 1 | Increment its suspect RPC-failure count and either back off or remove it at the configured threshold. |
| Non-terminal provider failure from an isolated suspect during a provider event | 1 | Apply suspect backoff without incrementing its removal count. |
| Non-terminal provider failure from a normal bundle during a provider event | Any | Do not change UO state. |
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

The builder updates the signal before processing non-terminal UO feedback. While a
provider event is active, non-terminal failures cannot mark suspects, increment removal
counters, or remove UOs. They may still defer an isolated suspect's next attempt.
Entering an event clears all accumulated non-terminal RPC-failure counters. Existing
suspect status remains, including suspicion created by mined reverts or terminal RPC
errors, but its non-terminal removal counter resets.

## Non-terminal RPC evidence

Outside a provider event:

1. A final non-terminal provider failure increments the pre-suspect count of every UO in
   the failed bundle.
2. A successful submission clears the pre-suspect counts of every UO in that bundle.
3. At `--pool.rpc_failures_before_suspect` (default `3`), a UO becomes a suspect and its
   count resets.
4. A final provider failure from its single-UO attempt schedules an exponentially
   increasing retry delay with jitter.
5. If the provider-event signal is healthy, the failure also increments the suspect's
   removal count.
6. At `--pool.max_suspect_rpc_failures` (default `3`), the pool removes the UO and logs
   `RepeatedNonTerminalRpcFailure`.

`--pool.max_suspect_rpc_failures=0` disables RPC-based removal. Provider-event periods do
not contribute to either threshold, but suspect backoff still applies.

Suspect backoff is configured with `--pool.suspect_rpc_backoff_initial_secs` and
`--pool.suspect_rpc_backoff_max_secs`.

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

The submission route owns the provider-event signal. The pool owns pre-suspect counts,
suspect status, suspect removal counts, and suspect retry times so they are shared across
builders and cleared with the UO lifecycle. Backoff progression is separate from removal
evidence: provider-event failures increase the former but not the latter. This state is
in-memory and does not track transaction hashes for deduplication.

## Tradeoffs

- **Liveness versus false removal:** eventual removal protects bundling, but repeated
  non-terminal failures can still remove a healthy UO when the provider-event signal
  does not activate. Higher thresholds reduce false removals but extend poison lifetime.
- **Isolation versus throughput:** singleton attempts identify poison UOs without adding
  innocent fillers, but consume more transactions than normal bundles. The dynamic
  isolation limit preserves normal capacity at the cost of slower suspect draining.
- **Provider protection versus poison detection:** suppressing evidence during provider
  events prevents broad false attribution, but a poison UO encountered during an event
  takes longer to identify. Detection lag can also allow early event failures to count.
- **Backoff versus recovery latency:** per-suspect backoff prevents hot loops and resource
  churn, but delays successful retry after a transient failure.
