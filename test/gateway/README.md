# Multi-Chain Gateway Test Setup

This directory contains a Docker Compose setup for testing the multi-chain RPC gateway locally.

## Configuration Pattern

The configuration follows the same pattern as the Helm deployment:

| Layer | Source | Examples |
|-------|--------|----------|
| Global defaults | Environment variables on backends | `PROVIDER_RATE_LIMIT_RETRY_ENABLED`, `BASE_FEE_ACCEPT_PERCENT` |
| Per-chain routing | TOML config file | `chain_id`, `pool_url`, `builder_url` |
| Per-chain overrides | TOML config (optional) | `chain_name`, `enabled_entry_points` |

### Environment Variables (Backend Defaults)

These are passed to backend services (pool + builder) and apply per-chain:

```bash
# Provider settings
PROVIDER_RATE_LIMIT_RETRY_ENABLED=true
PROVIDER_CONSISTENCY_RETRY_ENABLED=true
PROVIDER_CLIENT_TIMEOUT_SECONDS=10

# Gas settings
BASE_FEE_ACCEPT_PERCENT=75
PRE_VERIFICATION_GAS_ACCEPT_PERCENT=75
VERIFICATION_GAS_LIMIT_EFFICIENCY_REJECT_THRESHOLD=0.40

# Entry points
ENABLED_ENTRY_POINTS=v0.7
```

### TOML Config (Per-Chain Routing)

The TOML file (`gateway-config.toml`) specifies per-chain connection info. Each chain
uses a `base` field to inherit from a chain spec (e.g., "dev", "ethereum"), and can
override specific fields like `chain_id` and `chain_name`:

```toml
[[chains]]
chain_id = 1
name = "eth-mainnet"
base = "ethereum"
node_http = "https://eth-mainnet.example.com"
pool_url = "http://mainnet-pool:50051"
builder_url = "http://mainnet-builder:50052"
# Optional: override default entry points
# enabled_entry_points = ["v0.6", "v0.7"]

[[chains]]
chain_id = 42161
name = "arbitrum-one"
base = "arbitrum"
node_http = "https://arb-mainnet.example.com"
pool_url = "http://arbitrum-pool:50051"
builder_url = "http://arbitrum-builder:50052"

# Example: Multiple dev chains with different IDs using same base spec
[[chains]]
chain_id = 1337
name = "dev-1337"
base = "dev"
node_http = "http://geth-1337:8545"
pool_url = "http://backend-1337:50051"
builder_url = "http://backend-1337:50052"

[[chains]]
chain_id = 31337
name = "dev-31337"
base = "dev"
chain_name = "Ethereum Devnet 31337"  # Override the chain spec name
node_http = "http://geth-31337:8545"
pool_url = "http://backend-31337:50051"
builder_url = "http://backend-31337:50052"
```

## Architecture

The gateway is a lightweight RPC proxy that routes requests to per-chain backends
based on the URL path. All chain-specific logic (estimation, events, fees, signatures)
runs in the backend (pool + builder). The gateway only holds gRPC clients.

```
                    ┌─────────────────────────────────────┐
                    │          Gateway (:3000)            │
                    │    Routes: /v1/{chain_id}/          │
                    │    Unified RPC APIs (eth, rundler,  │
                    │    debug, admin, system)            │
                    └────────────────┬────────────────────┘
                                     │
              ┌──────────────────────┴──────────────────────┐
              │                                             │
              ▼                                             ▼
   ┌──────────────────────┐                   ┌──────────────────────┐
   │  backend-1337        │                   │  backend-31337       │
   │  Pool:   :50051      │                   │  Pool:   :50051      │
   │  Builder: :50052     │                   │  Builder: :50052     │
   └──────────┬───────────┘                   └──────────┬───────────┘
              │                                          │
              ▼                                          ▼
   ┌──────────────────────┐                   ┌──────────────────────┐
   │  geth-1337 (:8545)   │                   │  geth-31337 (:8546)  │
   │  Chain ID: 1337      │                   │  Chain ID: 31337     │
   └──────────────────────┘                   └──────────────────────┘
```

## Quick Start

```bash
# Build and start all services
docker compose up --build

# Wait for services to be healthy (check logs)
docker compose logs -f gateway
```

## Testing

### System Health Check

```bash
# Chain 1337 health
curl -s -X POST http://localhost:3000/v1/1337/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' | jq

# Expected: {"jsonrpc":"2.0","id":1,"result":"ok"}

# Chain 31337 health
curl -s -X POST http://localhost:3000/v1/31337/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' | jq
```

### eth_ Namespace

```bash
# Get chain ID for chain 1337
curl -s -X POST http://localhost:3000/v1/1337/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' | jq

# Expected: {"jsonrpc":"2.0","id":1,"result":"0x539"}

# Get supported entry points for chain 31337
curl -s -X POST http://localhost:3000/v1/31337/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_supportedEntryPoints","params":[],"id":1}' | jq
```

### Invalid Chain (Should Return Error)

```bash
curl -s -X POST http://localhost:3000/v1/999/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}'

# Expected: HTTP 404 "Chain 999 not found"
```

## Services & Ports

| Service        | Port(s)              | Description                    |
|----------------|----------------------|--------------------------------|
| gateway        | 3000 (RPC), 8083 (metrics) | Multi-chain RPC gateway   |
| backend-1337   | 50051 (pool), 50052 (builder), 8081 (metrics) | Backend for chain 1337 |
| backend-31337  | 50053 (pool), 50054 (builder), 8082 (metrics) | Backend for chain 31337 |
| geth-1337      | 8545                 | Ethereum dev node (chain 1337) |
| geth-31337     | 8546                 | Ethereum dev node (chain 31337)|

## Comparison with Helm Deployment

| Helm Pattern | Docker Compose Equivalent |
|--------------|---------------------------|
| `global.env` | Gateway `environment` section |
| `rundler-eth-sepolia.env` | Backend-specific `environment` |
| `--network` in `global.args` | `--network` flag or `base` in TOML |
| `CHAIN_ID`, `CHAIN_NAME` env overrides | `chain_id`, `chain_name` in TOML `[[chains]]` |
| Per-network overrides | TOML `[[chains]]` entries |

## Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f gateway
docker compose logs -f backend-1337
```

## Cleanup

```bash
docker compose down -v
```

## Implementation Status

| Feature | Status |
|---------|--------|
| Path-based routing (`/v1/{chain_id}/`) | Implemented |
| Chain routing middleware | Implemented |
| Health aggregation (`system_health`) | Implemented |
| Chain backend infrastructure | Implemented |
| `eth_` namespace methods | Implemented |
| `debug_` namespace methods | Implemented |
| `admin_` namespace methods | Implemented |
| `rundler_` namespace methods | Implemented |

The gateway uses unified RPC API implementations (via `ChainResolver` trait) shared
with the single-chain node mode. All API namespaces are enabled by default.
