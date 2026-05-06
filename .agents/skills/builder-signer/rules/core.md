# Builder Signer Core Rules

## Preserve transaction sender semantics

Sender kinds are `raw`, `flashbots`, `bloxroute`, and `polygon-private`.
Fallback senders activate only after consecutive `SenderUnavailable` errors and
route cancellations to the sender that submitted the original transaction.

- Good: keep underpriced, nonce-low, condition-not-met, rejected, insufficient
  funds, and sender-unavailable errors distinct.
- Bad: treat every provider error as retryable sender outage.
- Exception: unknown outages may use `SenderUnavailable` when fallback should
  handle them.

## Keep signer leases balanced

`SignerManager` leases signers and requires `return_lease` to release them.
Funding-aware signers can move between `Available`, `NeedsFunding`, `Leased`,
and `LeasedNeedsFunding`.

- Good: return leases on every success, failure, cancellation, and early-exit
  path.
- Bad: hold a signer across waits that do not need signing.
- Exception: a bundle sender may keep its paired lease during the transaction
  tracking state machine by design.

## Protect secrets with `SecretString`

CLI private keys, mnemonics, Flashbots auth keys, and Bloxroute auth headers use
`SecretString`. Secrets should be exposed only at the immediate signing or
header-construction boundary.

- Good: parse secret CLI/env values with `parse_secret`.
- Bad: derive `Debug` output that prints raw keys, mnemonics, or auth headers.
- Exception: public signer addresses and KMS key IDs may be logged when that is
  already the established operational signal.

## Treat KMS Redis locking as a stateful safety mechanism

`LockingKmsSigner` uses Redis locks with a TTL to avoid nonce collisions across
KMS keys. The lock manager loop extends locks and logs relock failures.

- Good: keep lock IDs scoped by `chain_id:key_id`.
- Bad: allow multiple processes to sign with the same KMS key without a lease
  when locking is enabled.
- Exception: a single KMS key does not need the multi-key selection loop.

## Keep builder affinity and proxies matched

Builder config can define filter-specific virtual entrypoints and submission
proxies. Pool filters must have matching builder affinity or operations can
enter a mempool that no builder mines.

- Good: update builder config docs/tests when changing `EntryPointBuilderConfigs`.
- Bad: add a mempool filter without a corresponding builder path.
- Exception: default builders without filters can handle unfiltered mempools.
