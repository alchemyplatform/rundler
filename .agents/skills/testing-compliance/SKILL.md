---
name: testing-compliance
description: |
  Critical when writing tests, changing behavior covered by ERC-4337 spec tests, modifying mocks/fixtures, or choosing verification commands for Rundler.
last_verified: 2026-05-06
---

# Testing Compliance

Rundler uses co-located Rust tests, `cargo nextest`, mockall/manual mocks, and
versioned ERC-4337 spec harnesses in integrated and modular modes.

## Rules

| Rule | Read when |
| --- | --- |
| [co-located-tests](rules/co-located-tests.md) | Adding Rust unit tests |
| [mocking-patterns](rules/mocking-patterns.md) | Mocking providers, builders, or chain state |
| [spec-tests](rules/spec-tests.md) | Changing EntryPoint, simulation, mempool, RPC, or builder behavior |
| [nextest-gates](rules/nextest-gates.md) | Choosing local unit test commands |
