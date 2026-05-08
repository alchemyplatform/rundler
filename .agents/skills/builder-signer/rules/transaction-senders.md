# Preserve Transaction Sender Semantics

## Rule

Keep transaction sender errors and fallback behavior distinct.

## Why

Sender kinds are `raw`, `flashbots`, `bloxroute`, and `polygon-private`.
Fallback senders activate only after consecutive `SenderUnavailable` errors and
route cancellations to the sender that submitted the original transaction.

## Examples

- Good: keep underpriced, nonce-low, condition-not-met, rejected, insufficient
  funds, and sender-unavailable errors distinct.
- Bad: treat every provider error as a retryable sender outage.

## Exceptions

Unknown outages may use `SenderUnavailable` when fallback should handle them.
