# Testing Compliance Core Rules

## Prefer co-located Rust tests

Most unit tests live in `#[cfg(test)] mod tests` near the module they exercise,
using `#[test]` or `#[tokio::test]`.

- Good: add focused tests next to the changed module.
- Bad: create a distant integration test when a module-local unit test captures
  the behavior.
- Exception: distributed or end-to-end behavior belongs in spec or harness tests.

## Use established mocks

Provider traits expose `test-utils` mock helpers, builder traits use mockall,
and complex chain tests use hand-rolled mocks such as `MockBlock` and
`MockEvmProvider`.

- Good: reuse `crates/provider/src/traits/test_utils.rs` and existing manual
  mock patterns.
- Bad: mock at an unrelated abstraction layer that bypasses the behavior under
  test.
- Exception: small pure functions should use direct inputs without mocks.

## Choose spec tests for EntryPoint behavior

`make test-spec-integrated` runs local/integrated spec tests. `make
test-spec-modular` runs remote/distributed mode. CI compliance runs v0.6, v0.7,
and v0.8 through `alchemyplatform/bundler-test-executor`.

- Good: run targeted spec tests when changing RPC flows, simulation,
  EntryPoint routing, mempool acceptance, or builder submission behavior.
- Bad: claim spec safety from unit tests alone.
- Exception: isolated docs or internal refactors may only need unit/lint gates.

## Match CI's test runner

Local unit tests use `make test-unit`, which calls `cargo nextest run --locked
--workspace --all-features --no-fail-fast`. CI coverage uses
`cargo llvm-cov nextest`.

- Good: run `make test-unit` before PR handoff for code changes.
- Bad: run only `cargo test -p one-crate` and call the workspace tested.
- Exception: during development, narrow package tests are fine before the final
  gate.

