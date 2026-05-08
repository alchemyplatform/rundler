---
name: rust-async
description: |
  Use when adding async traits, background tasks, long-running loops, Tokio usage, or cross-crate Rust APIs in Rundler.
last_verified: 2026-05-06
---

# Rust Async

Rundler wraps Reth task spawning in `rundler-task`, uses `async_trait` for
object-safe async traits, and keeps Tokio features minimal in workspace crates.

## Rules

| Rule | Read when |
| --- | --- |
| [task-spawning](rules/task-spawning.md) | Adding background tasks or long-running loops |
| [tokio-features](rules/tokio-features.md) | Using Tokio APIs in library crates |
| [async-traits](rules/async-traits.md) | Adding async trait boundaries |
| [crate-lints](rules/crate-lints.md) | Adding public APIs or dependencies |
