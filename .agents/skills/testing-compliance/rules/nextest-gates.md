# Match CI's Unit Test Runner

## Rule

Use `make test-unit` as the standard unit-test gate.

## Why

`make test-unit` calls `cargo nextest run --locked --workspace --all-features
--no-fail-fast`. CI coverage uses `cargo llvm-cov nextest`.

## Examples

- Good: run `make test-unit` before PR handoff for code changes.
- Bad: run only `cargo test -p one-crate` and call the workspace tested.

## Exceptions

During development, narrow package tests are fine before the final gate.
