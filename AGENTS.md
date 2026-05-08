# Agent Router

Rundler is a Rust ERC-4337 bundler workspace. Load the repo-local skills in
`.agents/skills/` based on the file area you are changing.

## Quick Reference

```bash
make build                 # Build all crates with all features
make fmt                   # Format with nightly rustfmt
make lint                  # Run clippy with -D warnings
make test-unit             # Run cargo nextest unit tests
make test                  # Run unit, integrated spec, and modular spec tests
make test-spec-integrated  # Run local ERC-4337 spec tests
make test-spec-modular     # Run remote/distributed ERC-4337 spec tests
cargo run node             # Run a local integrated node after .env setup
```

## Available Skills

| Skill                         | Description                                                                                          |
| ----------------------------- | ---------------------------------------------------------------------------------------------------- |
| `tooling`                     | Cargo workspace, Rust 1.92, nightly fmt, nextest, cargo-deny, submodules, and CI parity              |
| `rust-async`                  | `reth_tasks`, `TaskSpawnerExt`, async traits, minimal Tokio features, and crate lint conventions     |
| `rpc-errors`                  | JSON-RPC method shape, EntryPoint routing, `safe_call_rpc_handler`, and ERC-4337 error code mapping  |
| `grpc-protobuf`               | Tonic/Buf protobuf generation, proto/domain conversions, remote health checks, and retry behavior    |
| `builder-signer`              | Bundle sender state, transaction senders, signer leases, KMS/Redis locking, and sender failover      |
| `contracts-generated`         | Foundry contract generation, bytecode sidecars, sim tracer Yarn build, and FastLZ bindgen boundaries |
| `testing-compliance`          | Module-local tests, mockall/manual mocks, nextest coverage, and versioned ERC-4337 spec tests        |
| `configuration-observability` | Chain spec resolution, JSON/S3 configs, provider retry/timeout layers, metrics, tracing, and secrets |

## Skill Loading

| Task                                                                                 | Load skills                                                           |
| ------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| Editing `Cargo.toml`, `Cargo.lock`, `.cargo/`, `Makefile`, or workflows              | `tooling`                                                             |
| Adding async tasks, background loops, or crate APIs                                  | `rust-async`, `testing-compliance`                                    |
| Adding or modifying JSON-RPC methods                                                 | `rpc-errors`, `testing-compliance`                                    |
| Editing `.proto`, remote pool/builder clients, or gRPC servers                       | `grpc-protobuf`, `testing-compliance`                                 |
| Changing bundle building, transaction senders, signer logic, or sponsored delegation | `builder-signer`, `configuration-observability`, `testing-compliance` |
| Editing Solidity, generated contract bindings, sim tracer, or FastLZ bindings        | `contracts-generated`, `tooling`                                      |
| Changing chain specs, CLI config, provider layers, tracing, or metrics               | `configuration-observability`, `tooling`                              |
| Preparing a PR or judging deployment safety                                          | `tooling`, `testing-compliance`, plus area-specific skills            |

## Baseline Coding and PR Conventions

- Follow Rust naming defaults: modules/files `snake_case`, types/traits
  `UpperCamelCase`, constants `SCREAMING_SNAKE_CASE`.
- Use `{variable}` shorthand in format strings, logs, and error messages, for
  example `format!("transaction {tx_hash} missing")`.
- Import types instead of using inline paths. Use `as` renames to resolve
  conflicts.
- Qualify function calls with their module or type, for example
  `EthRpcError::from(...)` or `Vec::new()`, but do not qualify types/structs/enums
  unless needed to resolve ambiguity.
- Commits and PR titles must follow Conventional Commit style; CI validates both.
- Fill the PR template, keep commits focused, include tests with code changes,
  and update docs when API, CLI, or architecture behavior changes.

## Directory Mapping

| Path                                                     | Skills                                                                   |
| -------------------------------------------------------- | ------------------------------------------------------------------------ |
| `bin/rundler/`                                           | `configuration-observability`, `builder-signer`, `rpc-errors`, `tooling` |
| `bin/rundler/chain_specs/`                               | `configuration-observability`                                            |
| `crates/rpc/`                                            | `rpc-errors`, `grpc-protobuf`, `testing-compliance`                      |
| `crates/pool/`                                           | `grpc-protobuf`, `testing-compliance`, `configuration-observability`     |
| `crates/builder/`                                        | `builder-signer`, `grpc-protobuf`, `testing-compliance`                  |
| `crates/signer/`                                         | `builder-signer`, `configuration-observability`                          |
| `crates/provider/`                                       | `configuration-observability`, `rust-async`, `testing-compliance`        |
| `crates/sim/`                                            | `contracts-generated`, `testing-compliance`                              |
| `crates/contracts/`                                      | `contracts-generated`                                                    |
| `crates/aggregators/`                                    | `testing-compliance`, `rust-async`, `builder-signer`                     |
| `crates/types/`                                          | `rpc-errors`, `grpc-protobuf`, `testing-compliance`                      |
| `crates/task/`                                           | `rust-async`, `grpc-protobuf`                                            |
| `test/spec-tests/`                                       | `testing-compliance`, `contracts-generated`                              |
| `.github/workflows/`, `deny.toml`, `Makefile`            | `tooling`, `testing-compliance`                                          |
| `.cursor/rules/`, `.agents/skills/`, `.agents/commands/` | `tooling`                                                                |

## Project Structure

```text
rundler/
├── bin/rundler/                 # CLI, local node wiring, chain specs
├── crates/
│   ├── builder/                 # Bundle building, transaction senders, remote builder gRPC
│   ├── pool/                    # Mempool, chain tracking, remote pool gRPC
│   ├── provider/                # Alloy provider wrappers, DA gas oracles, fee estimation
│   ├── rpc/                     # jsonrpsee eth/debug/rundler/admin APIs
│   ├── signer/                  # Private key, mnemonic, AWS KMS, funding, key leasing
│   ├── sim/                     # Simulation, gas estimation, TypeScript tracer build
│   ├── contracts/               # Solidity submodules, Foundry-generated ABI artifacts
│   ├── aggregators/             # BLS/PBH signature aggregation and proxy helpers
│   ├── task/                    # Reth task spawner and gRPC utilities
│   ├── types/                   # UserOperation, EntryPoint, pool, builder, chain types
│   └── utils/                   # Retry, logging, metrics helpers
├── test/spec-tests/             # Local and remote ERC-4337 spec harnesses
├── docs/                        # Architecture, CLI, Docker, release docs
├── docs/solutions/              # AI-maintained gotchas and historical learnings
└── .github/workflows/           # CI, unit, compliance, release, dependency checks
```

## Slash Commands

| Command            | Description                                                                        |
| ------------------ | ---------------------------------------------------------------------------------- |
| `/run-gates`       | Run the right local verification gates for the current diff                        |
| `/add-rpc-method`  | Add a JSON-RPC method end-to-end with routing, errors, tests, and docs             |
| `/add-proto-field` | Change a proto schema and update all generated/domain conversion boundaries        |
| `/add-chain-spec`  | Add or modify a hardcoded chain spec safely                                        |
| `/run-spec-tests`  | Prepare and run local or remote ERC-4337 spec tests by EntryPoint version          |
| `/prepare-release` | Prepare the release checklist and workflow inputs without dispatching release jobs |

## Documentation Discovery

- Read `README.md` for the public project overview.
- Read `docs/developing.md` for local setup, but trust `Cargo.toml`,
  `rust-toolchain.toml`, and CI workflows for current toolchain versions.
- Read `docs/architecture/` for domain behavior and update it when behavior
  changes.
- Read `docs/solutions/` for gotchas. These docs are reference material, not
  authoritative rules. If a solution doc contradicts current code, trust the code.
- Existing AI instructions can be stale. Derive factual claims from source,
  build files, tests, scripts, and workflow YAML.
