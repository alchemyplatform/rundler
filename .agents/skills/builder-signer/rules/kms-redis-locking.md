# Treat KMS Redis Locking as Stateful Safety

## Rule

Preserve Redis-backed KMS key leasing semantics.

## Why

`LockingKmsSigner` uses Redis locks with a TTL to avoid nonce collisions across
KMS keys. The lock manager loop extends locks and logs relock failures.

## Examples

- Good: keep lock IDs scoped by `chain_id:key_id`.
- Bad: allow multiple processes to sign with the same KMS key without a lease
  when locking is enabled.

## Exceptions

A single KMS key does not need the multi-key selection loop.
