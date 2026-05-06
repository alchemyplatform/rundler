---
name: tooling
description: |
  Critical when changing Cargo workspace metadata, Makefile targets, CI workflows, dependency policy, submodules, or generated build prerequisites in Rundler.
last_verified: 2026-05-06
---

# Tooling

Rundler is a Rust 1.92 workspace with nightly rustfmt, `cargo nextest`,
Foundry, protobuf, Buf, and recursive submodules in CI.

## Rules

| Rule | Read when |
| --- | --- |
| [core](rules/core.md) | Editing build, lint, dependency, submodule, or CI behavior |

