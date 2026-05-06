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
| [core](rules/core.md) | Changing async tasks, traits, Tokio features, or crate lint boundaries |

