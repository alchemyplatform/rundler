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
| [rust-toolchain](rules/rust-toolchain.md) | Choosing Rust toolchain or formatter behavior |
| [repository-gates](rules/repository-gates.md) | Choosing local or CI-equivalent validation commands |
| [dependency-policy](rules/dependency-policy.md) | Adding or changing Cargo dependencies |
| [submodules](rules/submodules.md) | Working with contracts, spec tests, or vendored sources |
