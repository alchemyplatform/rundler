# Rust Async Core Rules

## Spawn through `rundler-task`

Library tasks should use `TaskSpawnerExt` from `crates/task/src/lib.rs` rather
than ad hoc untracked `tokio::spawn`. Critical long-running tasks use Reth's
task manager so the binary can observe failure and shut down cleanly.

- Good: accept `impl TaskSpawnerExt` and call `spawn_critical` for servers or
  loops that must not silently die.
- Bad: start a background loop with `tokio::spawn` from a library crate and
  drop the handle.
- Exception: short test-only tasks may use Tokio directly inside test modules.

## Keep Tokio feature assumptions local

The workspace `tokio` dependency enables only `rt`, `sync`, and `time`; the
binary adds macros, multithreaded runtime, and signal support. Do not assume
all Tokio features are available in library crates.

- Good: add required Tokio features to the crate that needs them.
- Bad: use `#[tokio::main]`, signals, or macros in a library crate without
  checking its `Cargo.toml`.
- Exception: `bin/rundler` owns CLI runtime setup.

## Use `async_trait` consistently for object-safe async traits

Rundler uses `async_trait` on provider, pool, builder, signer, RPC, and task
boundaries that need trait objects or mock support.

- Good: follow existing `#[async_trait::async_trait]` or imported
  `#[async_trait]` style in the surrounding module.
- Bad: introduce a second incompatible trait pattern in the same boundary.
- Exception: concrete helper methods do not need trait abstraction.

## Keep crate lints green

Crates use `#![warn(missing_docs, unreachable_pub, unused_crate_dependencies)]`
and `#![deny(unused_must_use, rust_2018_idioms)]`. Public APIs and unused
dependencies are CI-visible.

- Good: document public APIs added to library crates.
- Bad: ignore `Result` values from async work or add unused crate dependencies.
- Exception: test-only dependency markers such as the existing `cargo_husky as _`
  pattern should remain isolated to tests.
