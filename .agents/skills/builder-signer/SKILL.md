---
name: builder-signer
description: |
  Critical when changing bundle building, transaction senders, signer management, KMS/Redis locking, signer funding, proxies, builder affinity, or sponsored delegation.
last_verified: 2026-05-06
---

# Builder Signer

The builder creates bundle transactions, leases signers, submits through raw or
private senders, tracks mining/cancellation state, and can fail over between
senders.

## Rules

| Rule | Read when |
| --- | --- |
| [transaction-senders](rules/transaction-senders.md) | Changing raw, Flashbots, Bloxroute, Polygon private, or fallback senders |
| [signer-leases](rules/signer-leases.md) | Leasing, returning, or tracking signers |
| [secret-handling](rules/secret-handling.md) | Handling private keys, mnemonics, relay auth, or headers |
| [kms-redis-locking](rules/kms-redis-locking.md) | Changing AWS KMS or Redis key leasing |
| [builder-affinity-and-proxies](rules/builder-affinity-and-proxies.md) | Changing filters, virtual entrypoints, or submission proxies |
