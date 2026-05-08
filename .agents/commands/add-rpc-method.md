---
name: Add RPC Method
description: Add a Rundler JSON-RPC method with routing, error mapping, tests, and docs.
argument-hint: "[namespace] [method_name]"
---

## How It Works

1. Identify the target namespace and request/response types.
2. Add the jsonrpsee trait method and server implementation.
3. Route through `safe_call_rpc_handler`.
4. Preserve EntryPoint routing and `EthRpcError` mappings.
5. Add focused tests and docs.
6. Run targeted gates.

## Instructions

### Validate Arguments

- `$1` — **namespace**: Required namespace, usually `eth`, `rundler`,
  `debug`, or `admin`.
  - **Suggest:** Inspect `crates/rpc/src/` for existing namespace files.
- `$2` — **method_name**: Required method name without namespace prefix.

### 1. Load Context

Read `.agents/skills/rpc-errors/SKILL.md` and its rules. Also read
`.agents/skills/testing-compliance/SKILL.md` before writing tests.

### 2. Implement the Method

Follow the local namespace pattern:

- Add the method to the `#[rpc(client, server, namespace = "...")]` trait.
- Add the server implementation method with `#[instrument(skip_all, fields(rpc_method = "..."))]`.
- Call `utils::safe_call_rpc_handler`.
- Put logic in an inherent async helper returning `EthResult` or
  `InternalRpcResult`.
- Use `EntryPointRouter` and `ChainSpec` for EntryPoint-specific behavior.

### 3. Preserve Error Contracts

If the method introduces a new client-visible failure, update
`crates/rpc/src/eth/error.rs` so the variant maps to the correct JSON-RPC or
ERC-4337 code. Use `rpc_err_with_data` for structured payloads clients parse.

### 4. Add Tests and Docs

Add co-located Rust tests where possible. If API or CLI behavior changes, update
`docs/cli.md` or the relevant `docs/architecture/` page.

### 5. Verify

Run at least:

```bash
make fmt
make lint
make test-unit
```

Run spec tests when changing EntryPoint, mempool acceptance, simulation, or
builder-facing behavior.
