# Use the Pinned Rust Toolchain

## Rule

Build and lint with Rust `1.92.0`, and use nightly only for rustfmt.

## Why

Rundler pins Rust `1.92.0` in `rust-toolchain.toml` and declares
`rust-version = "1.92"` in the workspace `Cargo.toml`. CI installs the same
toolchain. Formatting is the exception: both `make fmt` and CI use
`cargo +nightly fmt`.

## Examples

- Good: run `make fmt` for formatting and pinned-toolchain Cargo commands for
  build, clippy, and tests.
- Bad: rely on the older `docs/developing.md` Rust minimum when deciding
  compiler behavior.

## Exceptions

Use `+nightly` for rustfmt only, matching the Makefile and CI.
