# Edit Solidity Sources, Not Generated Artifacts

## Rule

Change Solidity sources or build scripts, not generated Foundry output.

## Why

`crates/contracts/build.rs` runs `forge build` for `v0_6`, `v0_7`, `v0_8`,
`v0_9`, and `common`, then writes bytecode sidecars under `contracts/out`.

## Examples

- Good: edit Solidity under `contracts/*/src`.
- Bad: hand-edit `contracts/out/**` JSON or `_deployedBytecode.txt` outputs.

## Exceptions

Generated outputs may be inspected as evidence, but source changes belong in
Solidity or build scripts.

