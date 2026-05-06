# Configuration Observability Core Rules

## Preserve chain spec precedence

Chain specs resolve from `CHAIN_*` env vars, explicit `--chain_spec` file,
`--network` hardcoded TOML, optional one-level base, then defaults. Chain ID
must be defined and non-zero.

- Good: update `bin/rundler/chain_specs/*.toml`, `chain_spec.rs`, and docs
  together for new networks or fields.
- Bad: add config that bypasses env/file/network precedence.
- Exception: runtime-only CLI flags that are not chain-specific can live in the
  command args structs.

## Keep JSON config loading local/S3 capable

`get_json_config` reads local paths or `s3://bucket/key` using AWS defaults.
Mempool and builder configs can depend on this behavior.

- Good: preserve identical schemas for local and S3 JSON config.
- Bad: add a config mode that only works locally when deployments need S3.
- Exception: developer-only debug commands may use local files.

## Compose provider layers deliberately

Alloy providers can include rate-limit retry, consistency retry, metrics, and
client-side timeout layers. Consistency retry is specifically for block/header
not found style errors.

- Good: make retry and timeout settings explicit in `AlloyNetworkConfig`.
- Bad: retry every RPC error as a consistency issue.
- Exception: sender-specific retry behavior belongs in transaction sender code.

## Keep observability structured and bounded

Logging uses `RUST_LOG`, optional JSON, target blacklisting for noisy crates,
and optional OTLP gRPC with service name `rundler` plus network attribute.
Metrics use `metrics-derive` scopes such as `op_pool_chain`.

- Good: add metrics scopes for new hot paths and avoid logging full request
  payloads at info level.
- Bad: print private keys, mnemonics, auth headers, or raw signatures.
- Exception: addresses, transaction hashes, EntryPoint versions, and non-secret
  KMS key IDs are normal operational identifiers.

