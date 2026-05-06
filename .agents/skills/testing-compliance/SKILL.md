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

| Rule                  | Read when                                                 |
| --------------------- | --------------------------------------------------------- |
| [core](rules/core.md) | Writing tests or choosing validation for behavior changes |
