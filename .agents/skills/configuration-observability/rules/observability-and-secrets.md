# Keep Observability Structured and Bounded

## Rule

Add useful metrics/tracing without exposing secret or high-volume request data.

## Why

Logging uses `RUST_LOG`, optional JSON, target blacklisting for noisy crates,
and optional OTLP gRPC with service name `rundler` plus network attribute.
Metrics use `metrics-derive` scopes such as `op_pool_chain`.

## Examples

- Good: add metrics scopes for new hot paths and avoid logging full request
  payloads at info level.
- Bad: print private keys, mnemonics, auth headers, or raw signatures.

## Exceptions

Addresses, transaction hashes, EntryPoint versions, and non-secret KMS key IDs
are normal operational identifiers.
