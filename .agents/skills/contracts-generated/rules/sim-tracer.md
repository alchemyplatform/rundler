# Treat the Sim Tracer as a TypeScript Build Artifact

## Rule

Edit tracer TypeScript and validate the Yarn/Cargo build path.

## Why

`crates/sim/build.rs` runs `yarn` and `yarn build` in `crates/sim/tracer` and
watches `validationTracerV0_6.ts` and `validationTracerV0_7.ts`.

## Examples

- Good: update tracer TypeScript and run the build path through `cargo build` or
  `yarn build` in the tracer directory.
- Bad: edit compiled JavaScript output without changing the TypeScript source.

## Exceptions

Lockfile-only changes should still be validated with the tracer build command.
