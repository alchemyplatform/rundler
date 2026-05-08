# Preserve Chain Spec Precedence

## Rule

Keep chain spec resolution compatible with the established precedence order.

## Why

Chain specs resolve from `CHAIN_*` env vars, explicit `--chain_spec` file,
`--network` hardcoded TOML, optional one-level base, then defaults. Chain ID
must be defined and non-zero.

## Examples

- Good: update `bin/rundler/chain_specs/*.toml`, `chain_spec.rs`, and docs
  together for new networks or fields.
- Bad: add config that bypasses env/file/network precedence.

## Exceptions

Runtime-only CLI flags that are not chain-specific can live in the command args
structs.

