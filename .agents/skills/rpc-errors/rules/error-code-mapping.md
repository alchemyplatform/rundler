# Preserve ERC-4337 Error Codes and Data

## Rule

Map every client-visible `EthRpcError` to the intended JSON-RPC or ERC-4337
error code and structured data.

## Why

`EthRpcError` maps to `ErrorObjectOwned` with stable codes such as `-32500`,
`-32501`, and `-32502`. Some errors include structured data via
`rpc_err_with_data`.

## Examples

- Good: update `impl From<EthRpcError> for ErrorObjectOwned` whenever adding a
  new client-visible variant.
- Good: keep deserializable data payloads for paymaster, time-range, stake, and
  execution-revert errors.
- Bad: map validation or simulation failures to `INTERNAL_ERROR_CODE`.

## Exceptions

Use `INTERNAL_ERROR_CODE` only for failures that are truly internal and not
actionable by RPC clients.
