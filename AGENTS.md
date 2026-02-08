# Repository Guidelines

## Project Structure & Module Organization
Rundler is a Rust workspace.
- `bin/rundler/`: CLI binary entrypoint and chain spec configs (`bin/rundler/chain_specs/*.toml`).
- `crates/*`: core libraries (for example `rundler-pool`, `rundler-rpc`, `rundler-sim`, `rundler-builder`).
- `test/spec-tests/`: ERC-4337 compliance test harnesses (`local/` integrated mode, `remote/` modular mode, plus versioned suites under `v0_6/`, `v0_7/`, `v0_8/`).
- `docs/`: architecture, CLI, Docker, and development documentation.
- `.github/workflows/`: CI checks (lint, unit tests, commit/PR semantics, docs, dependency ordering).

## Build, Test, and Development Commands
- `make build`: build all crates with all features.
- `make test-unit`: run unit tests via `cargo nextest`.
- `make test`: run unit + integrated spec + modular spec tests.
- `make test-spec-integrated` / `make test-spec-modular`: run ERC-4337 spec suites only.
- `make fmt`: format Rust code with nightly `rustfmt`.
- `make lint`: run `clippy` with `-D warnings`.
- `cargo run node`: run a local integrated node (after `.env` setup).

## Coding Style & Naming Conventions
- Rust toolchain targets edition `2024` (workspace `rust-version` is `1.92`).
- Formatting is required: `cargo +nightly fmt --all --check`.
- Lint must be clean: `cargo clippy --all --all-features --tests -- -D warnings`.
- Follow Rust naming defaults: modules/files `snake_case`, types/traits `UpperCamelCase`, constants `SCREAMING_SNAKE_CASE`.
- Keep crate names in the established `rundler-*` pattern.
- Use the `{variable}` shorthand syntax in format strings, logs, and error messages (e.g. `format!("transaction {tx_hash} missing")` instead of `format!("transaction {} missing", tx_hash)`).
- Always import types rather than using inline paths (e.g. `use crate::eth::events::EventProviderError;` then `EventProviderError`, not `crate::eth::events::EventProviderError` inline). Use `as` renames to resolve conflicts.
- Always qualify function calls with their module or type (e.g. `EthRpcError::from(...)`, `Vec::new()`), but do not qualify types/structs/enums unless needed to resolve ambiguity.

## Testing Guidelines
- Add or update tests for every behavior change (`#[test]` / `#[tokio::test]` near the changed module is common here).
- Run at least `make test-unit` before opening a PR; run spec tests for EntryPoint- or RPC-flow changes.
- CI collects coverage with `cargo llvm-cov nextest`; no fixed threshold is enforced, but coverage regressions should be justified.

## Commit & Pull Request Guidelines
- Commits must follow Conventional Commits (for example `fix(rpc): return error on invalid entrypoint`).
- PR titles are semantically validated in CI; use Conventional Commit style there too.
- Use focused commits, squash checkpoint commits, and include tests with code changes.
- Fill the PR template: link issue (`[Closes/Fixes] #...`) and list concrete proposed changes.
- If a change affects API/CLI behavior or architecture, update relevant docs in the same PR (typically `docs/cli.md`, `docs/architecture/*`, and README sections as needed).

## Security & Configuration Tips
- Do not commit secrets; keep local values in `.env`.
- For security disclosures, follow `SECURITY.md` instead of opening a public issue.
