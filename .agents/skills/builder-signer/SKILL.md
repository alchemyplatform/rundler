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

| Rule                  | Read when                                                                 |
| --------------------- | ------------------------------------------------------------------------- |
| [core](rules/core.md) | Editing `crates/builder/`, `crates/signer/`, or builder/signer CLI config |
