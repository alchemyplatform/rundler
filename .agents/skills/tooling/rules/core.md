# Tooling Core Rules

## Use the pinned Rust toolchain

Rundler pins Rust `1.92.0` in `rust-toolchain.toml` and declares workspace
`rust-version = "1.92"` in `Cargo.toml`. CI installs the same toolchain.

- Good: run builds and checks with the pinned toolchain.
- Bad: rely on the older `docs/developing.md` Rust minimum when resolving
  compiler behavior.
- Exception: use `+nightly` only for rustfmt, matching `make fmt` and CI.

## Match the repository gates

The Makefile is the local entry point: `make fmt`, `make lint`, and
`make test-unit`. CI additionally runs `cargo build --all --all-features`,
`cargo check --all --all-features`, Buf lint, cargo-sort, cargo-deny, and
coverage via `cargo llvm-cov nextest --locked --all-features --workspace`.

- Good: run `make test-unit` for normal Rust behavior changes.
- Good: run spec tests when RPC, EntryPoint, pool, simulation, or builder
  behavior changes.
- Bad: report confidence from raw `cargo test` alone.

## Preserve dependency policy

`deny.toml` denies direct `openssl`, denies unknown registries and unknown git
sources, and allows only `https://github.com/paradigmxyz/reth.git` as a git
source. Workspace dependencies use `workspace = true` across crates.

- Good: add new dependencies in the workspace root when shared by multiple
  crates.
- Bad: introduce `openssl` or a new git source without updating `deny.toml`
  and explaining why.
- Exception: crate-local dependencies are fine when they are truly local.

## Respect recursive submodules

CI checks out recursive submodules. Contract sources, account-abstraction
versions, OpenZeppelin versions, FastLZ, and spec tests live under submodules.

- Good: run `git submodule update --init --recursive` before contract or spec
  work.
- Bad: assume missing vendored files mean the repo no longer uses them.
- Exception: do not audit vendored submodule internals unless the change is
  explicitly about those sources.

