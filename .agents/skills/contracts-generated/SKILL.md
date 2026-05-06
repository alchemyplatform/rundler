---
name: contracts-generated
description: |
  Use when editing Solidity contracts, account-abstraction submodules, Foundry-generated artifacts, sim tracer TypeScript, or FastLZ bindgen/cc boundaries.
last_verified: 2026-05-06
---

# Contracts Generated

Rundler's build invokes Foundry for contract artifacts, Yarn for the simulation
tracer, tonic for protos, and bindgen/cc for FastLZ.

## Rules

| Rule                  | Read when                                                                  |
| --------------------- | -------------------------------------------------------------------------- |
| [core](rules/core.md) | Editing contracts, generated output, tracer TypeScript, or FastLZ bindings |
