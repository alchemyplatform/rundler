# gRPC Protobuf Core Rules

## Regenerate from `.proto`, not generated Rust

`crates/builder/build.rs` and `crates/pool/build.rs` call `tonic_build` and
write descriptor sets in `OUT_DIR`. Runtime modules use `tonic::include_proto!`
and `include_file_descriptor_set!`.

- Good: edit `crates/builder/proto/builder/builder.proto` or
  `crates/pool/proto/op_pool/op_pool.proto`.
- Bad: edit generated Rust under Cargo output directories.
- Exception: conversion code in `protos.rs` is hand-written and should be kept
  in sync with schema changes.

## Run Buf and Cargo checks after schema edits

`buf.work.yaml` includes `crates/builder/proto` and `crates/pool/proto`; CI runs
Buf lint plus a Cargo build that compiles protos.

- Good: run `buf lint` and `cargo build --all --all-features` after proto
  changes.
- Bad: add a proto file without updating the relevant `build.rs`.
- Exception: comment-only proto edits still need Buf lint.

## Keep proto/domain conversions lossless

Pool and builder remote modules convert between proto structs and domain types,
including `UserOperationVariant`, `EntryPointVersion`, `Eip7702Auth`,
`PoolError`, `MempoolError`, and simulation/precheck violations.

- Good: add both `From` and `TryFrom` paths where the existing pattern has both
  directions.
- Bad: collapse distinct domain errors into an internal string unless the
  existing boundary already treats them as internal.
- Exception: truly unexpected remote responses may remain
  `PoolError::UnexpectedResponse`.

## Connect remotes with retry and health semantics

Standalone RPC connects to remote pool and builder services via
`connect_with_retries_shutdown`, and remote services implement `HealthCheck`.

- Good: reuse `rundler_task::server` retry helpers and health checks.
- Bad: make a one-shot remote connection that fails startup on normal service
  ordering races.
- Exception: admin or one-shot tools can fail fast when they do not participate
  in long-running service startup.

