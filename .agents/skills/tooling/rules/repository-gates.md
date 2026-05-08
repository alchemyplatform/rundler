# Match Repository Gates

## Rule

Use the Makefile and CI-equivalent commands when validating changes.

## Why

The local entry points are `make fmt`, `make lint`, and `make test-unit`. CI
also runs `cargo build --all --all-features`, `cargo check --all --all-features`,
Buf lint, cargo-sort, cargo-deny, and coverage via `cargo llvm-cov nextest
--locked --all-features --workspace`.

## Examples

- Good: run `make test-unit` for normal Rust behavior changes.
- Good: run spec tests for RPC, EntryPoint, pool, simulation, or builder
  behavior changes.
- Bad: report confidence from raw `cargo test` alone.

## Exceptions

During development, narrow package-level commands are fine before the final gate.
