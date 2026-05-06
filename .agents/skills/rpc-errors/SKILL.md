---
name: rpc-errors
description: |
  Critical when creating or changing JSON-RPC APIs, EntryPoint routing, RPC request handling, or ERC-4337 error mapping.
last_verified: 2026-05-06
---

# RPC Errors

Rundler exposes `eth`, `debug`, `rundler`, and `admin` JSON-RPC namespaces via
jsonrpsee. RPC behavior is version-routed by EntryPoint address and error codes
are part of the client contract.

## Rules

| Rule | Read when |
| --- | --- |
| [core](rules/core.md) | Editing `crates/rpc/`, `crates/types/src/user_operation/`, or RPC-facing errors |

