---
title: Generated Boundaries
date: 2026-05-06
tags:
  - solutions
  - generated-files
area: tooling
---

# Generated Boundaries

## Problem

Generated artifacts can look like normal repo files, especially contract
bytecode sidecars and tonic-generated protobuf output.

## Root Cause

Rundler has several generators:

- `crates/contracts/build.rs` runs Foundry and writes `contracts/out/**`.
- `crates/pool/build.rs` and `crates/builder/build.rs` run tonic-build into
  Cargo `OUT_DIR`.
- `crates/sim/build.rs` runs Yarn in `crates/sim/tracer`.
- `crates/bindings/fastlz/build.rs` runs bindgen and cc for FastLZ.

## Solution

Edit source inputs: `.proto` files, Solidity under `contracts/*/src`, tracer
TypeScript, FastLZ C/header files, or the build scripts. Regenerate through
`cargo build --all --all-features` or the generator-specific command. Do not
hand-edit `target/`, `OUT_DIR`, generated protobuf Rust, or Foundry output.

