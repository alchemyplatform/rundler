# Preserve Dependency Policy

## Rule

Keep new dependencies compatible with `deny.toml` and the workspace dependency
pattern.

## Why

`deny.toml` denies direct `openssl`, denies unknown registries and unknown git
sources, and only allows `https://github.com/paradigmxyz/reth.git` as a git
source. Shared crates use workspace dependencies from the root `Cargo.toml`.

## Examples

- Good: add shared dependencies in the workspace root and reference them with
  `workspace = true`.
- Bad: introduce `openssl` or a new git source without updating `deny.toml` and
  explaining why.

## Exceptions

Crate-local dependencies are fine when they are truly local to one crate.

