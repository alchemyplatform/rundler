# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rundler is a high-performance, modular Rust implementation of an ERC-4337 bundler for Account Abstraction. It's built by Alchemy and designed for cloud-scale deployments with a focus on reliability and performance.

## Development Commands

### Building and Testing
```bash
# Build the project
make build
cargo build --all --all-features

# Run unit tests
make test-unit
cargo nextest run --locked --workspace --all-features --no-fail-fast

# Run all tests (unit + spec tests)
make test

# Run ERC-4337 spec tests (v0.6 and v0.7)
make test-spec-integrated
make test-spec-integrated-v0_6  # v0.6 only
make test-spec-integrated-v0_7  # v0.7 only

# Run spec tests in modular mode
make test-spec-modular
```

### Code Quality
```bash
# Format code (requires nightly Rust)
make fmt
cargo +nightly fmt

# Lint code
make lint
cargo clippy --all --all-features --tests -- -D warnings

# Clean build artifacts
make clean
cargo clean
```

### Running Locally
```bash
# Run full node (RPC + Pool + Builder in single process)
cargo run node

# Run individual components in distributed mode
cargo run rpc       # RPC server only
cargo run pool      # Pool server only  
cargo run builder   # Builder server only
```

## Architecture

Rundler consists of 3 main modular components:

1. **RPC Server** (`crates/rpc/`): Implements ERC-4337 RPC methods (`eth_*`, `debug_*`, `rundler_*` namespaces)
2. **Pool** (`crates/pool/`): User Operation mempool with validation, simulation, and chain reorg handling
3. **Builder** (`crates/builder/`): Bundle construction, transaction submission, and mining monitoring

### Communication Patterns
- **RPC → Pool**: Submits user operations via `eth_sendUserOperation`
- **RPC → Builder**: Debug namespace for manual bundling control
- **Builder ↔ Pool**: Bundle coordination and operation status updates

### Key Supporting Crates
- `crates/sim/`: Gas estimation and operation simulation
- `crates/provider/`: Ethereum provider abstractions with Alloy
- `crates/types/`: Core type definitions
- `crates/contracts/`: Smart contract bindings and utilities
- `crates/signer/`: Transaction signing (local keys, AWS KMS)

## Configuration

### Environment Variables
Most CLI options can be set via environment variables. Key ones:
- `NODE_HTTP`: Ethereum RPC endpoint (required)
- `NETWORK`: Predefined network (dev, ethereum, optimism, etc.)
- `CHAIN_SPEC`: Path to custom chain specification TOML
- `RUST_LOG`: Log level control

### Chain Specifications
Chain configs are in `bin/rundler/chain_specs/` with network-specific settings for gas estimation, fee calculation, and protocol parameters.

## Entry Point Support

- **v0.6**: ERC-4337 v0.6 specification (can be disabled with `--disable_entry_point_v0_6`)
- **v0.7**: ERC-4337 v0.7 specification (can be disabled with `--disable_entry_point_v0_7`)

Both versions are supported simultaneously by default.

## Prerequisites

- Rust 1.87+ with nightly for formatting
- Docker (for spec tests)
- PDM (Python dependency manager for spec tests)  
- Protobuf compiler (protoc)
- Buf (protobuf linting)
- Foundry ^0.3.0 (contract compilation)

## Testing Setup

For spec tests, first install frameworks:
```bash
cd test/spec-tests/v0_6/bundler-spec-tests && pdm install && pdm run update-deps
cd test/spec-tests/v0_7/bundler-spec-tests && pdm install && pdm run update-deps
```

## Workspace Structure

This is a Cargo workspace with the main binary in `bin/rundler/` and library crates in `crates/`. The architecture is designed for both monolithic and distributed deployment modes.