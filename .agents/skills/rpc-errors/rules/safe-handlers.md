# Wrap JSON-RPC Methods Safely

## Rule

Route public jsonrpsee methods through `utils::safe_call_rpc_handler`.

## Why

`crates/rpc/src/rundler.rs` and `crates/rpc/src/admin.rs` use this wrapper to
keep logging, panic handling, and error conversion consistent.

## Examples

- Good: add the trait method, server impl, `#[instrument(skip_all,
  fields(rpc_method = "..."))]`, and `safe_call_rpc_handler`.
- Bad: return raw internal errors directly from a jsonrpsee method.

## Exceptions

Internal helper methods may return `EthResult` or `InternalRpcResult`.

