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
| [safe-handlers](rules/safe-handlers.md) | Adding or changing jsonrpsee method implementations |
| [entry-point-routing](rules/entry-point-routing.md) | Routing user operations by EntryPoint version/address |
| [error-code-mapping](rules/error-code-mapping.md) | Adding client-visible failures or error variants |
| [privileged-endpoints](rules/privileged-endpoints.md) | Adding admin, debug, sponsored, or state-mutating endpoints |
