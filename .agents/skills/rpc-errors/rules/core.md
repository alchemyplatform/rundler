# RPC Error Core Rules

## Wrap JSON-RPC methods with `safe_call_rpc_handler`

`crates/rpc/src/rundler.rs` and `crates/rpc/src/admin.rs` route public methods
through `utils::safe_call_rpc_handler`. This keeps logging, panic handling, and
error conversion consistent.

- Good: add the trait method, server impl, `#[instrument(skip_all, fields(rpc_method = "..."))]`, and `safe_call_rpc_handler`.
- Bad: return raw internal errors directly from a jsonrpsee method.
- Exception: internal helper methods may return `EthResult` or
  `InternalRpcResult`.

## Route by EntryPoint address and ABI version

`EntryPointVersion::V0_8` and `V0_9` are distinct versions but share the v0.7
ABI. `EntryPointRouter` validates that the user operation variant matches the
route's ABI before simulation or pool insertion.

- Good: use `ChainSpec::entry_point_version`, `EntryPointRouter`, and
  `TryIntoRundlerType` for RPC conversions.
- Bad: infer v0.7/v0.8/v0.9 behavior from the JSON shape alone.
- Exception: endpoints without an EntryPoint argument may query all enabled
  routes, as receipt/status methods do.

## Preserve ERC-4337 error codes and data

`EthRpcError` maps to `ErrorObjectOwned` with stable JSON-RPC and ERC-4337
codes such as `-32500`, `-32501`, and `-32502`. Some errors include structured
data via `rpc_err_with_data`.

- Good: update `impl From<EthRpcError> for ErrorObjectOwned` whenever adding a
  new client-visible variant.
- Good: keep deserializable data payloads for paymaster, time-range, stake, and
  execution-revert errors.
- Bad: map validation or simulation failures to `INTERNAL_ERROR_CODE`.

## Treat privileged endpoints as gated surfaces

`admin_*` is exposed only when the `admin` namespace is enabled. Sponsored
delegation is disabled by default because callers can drain available signers.

- Good: add explicit settings for dangerous endpoints and default them off.
- Bad: add a method that mutates pool/builder/signer state to a default-enabled
  namespace without a gating decision.
- Exception: read-only status methods may remain in the default `eth` or
  `rundler` namespace when they do not mutate state.
