# Contracts Generated Core Rules

## Edit Solidity sources, not generated artifacts

`crates/contracts/build.rs` runs `forge build` for `v0_6`, `v0_7`, `v0_8`,
`v0_9`, and `common`, then writes bytecode sidecars under `contracts/out`.

- Good: edit Solidity under `contracts/*/src`.
- Bad: hand-edit `contracts/out/**` JSON or `_deployedBytecode.txt` outputs.
- Exception: generated outputs may be inspected as evidence, but source changes
  belong in Solidity or build scripts.

## Keep Foundry and submodules aligned

CI installs Foundry `v1.5.0` and checks out submodules recursively. EntryPoint
versions come from account-abstraction submodules for v0.6 through v0.9.

- Good: update `.gitmodules`, docs, and CI together when changing upstream
  contract sources or Foundry expectations.
- Bad: assume a missing contract is deleted when submodules are not initialized.
- Exception: pure Rust changes need not initialize every submodule unless the
  build path touches contracts.

## Treat the sim tracer as a TypeScript build artifact

`crates/sim/build.rs` runs `yarn` and `yarn build` in `crates/sim/tracer` and
watches `validationTracerV0_6.ts` and `validationTracerV0_7.ts`.

- Good: update tracer TypeScript and run the build path through `cargo build` or
  `yarn build` in the tracer directory.
- Bad: edit compiled JavaScript output without changing the TypeScript source.
- Exception: lockfile-only changes should still be validated with the tracer
  build command.

## Keep FastLZ bindgen source-owned

`crates/bindings/fastlz/build.rs` compiles `fastlz/fastlz.c` and generates Rust
bindings from `fastlz/fastlz.h` into `OUT_DIR`.

- Good: edit C/header sources or the build script.
- Bad: commit generated bindgen output from `OUT_DIR`.
- Exception: generated output can be inspected locally when debugging bindgen.
