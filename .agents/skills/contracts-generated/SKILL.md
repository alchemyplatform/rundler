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

| Rule | Read when |
| --- | --- |
| [foundry-contracts](rules/foundry-contracts.md) | Editing Solidity or contract artifacts |
| [foundry-submodules](rules/foundry-submodules.md) | Changing account-abstraction, OpenZeppelin, or Foundry assumptions |
| [sim-tracer](rules/sim-tracer.md) | Editing simulation tracer TypeScript |
| [fastlz-bindings](rules/fastlz-bindings.md) | Editing FastLZ C, headers, or generated bindings |
