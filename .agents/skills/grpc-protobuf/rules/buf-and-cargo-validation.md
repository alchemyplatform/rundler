# Run Buf and Cargo Checks

## Rule

Validate protobuf edits with Buf and a Cargo build.

## Why

`buf.work.yaml` includes `crates/builder/proto` and `crates/pool/proto`; CI runs
Buf lint plus a Cargo build that compiles protos.

## Examples

- Good: run `buf lint` and `cargo build --all --all-features` after proto
  changes.
- Bad: add a proto file without updating the relevant `build.rs`.

## Exceptions

Comment-only proto edits still need Buf lint.
