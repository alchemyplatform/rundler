# Chain Specification

Chain specification is used in Rundler to set chain specific parameters.

You can find the various parameters [here](../../crates/types/src/chain.rs).

Upon startup Rundler uses the following CLI params to gather the chain spec parameters:

* `--network`: Network name to lookup a hardcoded chain spec.
* `--chain_spec`: Path to a chain spec TOML file.
* `CHAIN_*`: Environment variables representing chain spec fields.

The chain specification is derived using the following steps:

### Find a `base` specification, if defined

Using the following config hierarchy:

- `CHAIN_BASE` env var
- `--chain_spec` file `base` key
- `--network` hardcoded spec `base` key

to find a chain spec base. A base is not required. A base must be a hardcoded network.

### Resolve the full chain spec

Using the following config hierarchy:

- `CHAIN_*` env vars
- `--chain_spec` file keys
- `--network` hardcoded spec keys
- base (if defined)
- defaults

to resolve the full chain spec. Only one level of `base` resolution is defined. That is, if a `base` network defined another `base`, the second `base` won't be resolved.

### Hardcoded Chan Specs

See the files [here](../../bin/rundler/chain_specs/) for a list of hardcoded chain specifications.

### Glamsterdam gas schedule

`glamsterdam_enabled` (default `false`) switches pre-verification gas to the Glamsterdam gas schedule (EIP-2780, EIP-7976, EIP-8037, EIP-8038). The values live in separate `glamsterdam_*` fields; existing fields keep their meaning, and with the flag off nothing changes. The `ChainSpec` accessors (`bundle_intrinsic_gas`, `per_user_op_v0_7_gas`, `calldata_floor_*_byte_gas`, `call_data_word_gas`, `authorization_execution_gas`, the `*_state_gas` getters) pick between the old and new values, so code elsewhere never checks the flag.

| Field | Default | Meaning |
| --- | --- | --- |
| `glamsterdam_bundle_intrinsic_gas` | 15,000 | intrinsic gas of a bundle tx (EIP-2780 base + cold EntryPoint) |
| `glamsterdam_per_user_op_v0_7_gas` | 21,900 | per-op unmetered EntryPoint overhead, v0.7 |
| `glamsterdam_per_user_op_v0_6_gas` | 20,700 | per-op overhead, v0.6 (provisional, not yet measured) |
| `glamsterdam_calldata_floor_byte_gas` | 64 | EIP-7976 floor gas per calldata byte |
| `glamsterdam_call_data_word_gas` | 6 | extra gas per 32-byte word of an op's `callData` (the EntryPoint's unmetered copy of it) |
| `glamsterdam_authorization_execution_gas` | 16,816 | per EIP-7702 authorization, always |
| `glamsterdam_authorization_delegation_state_gas` | 35,190 | per authorization whose authority has no code |
| `glamsterdam_new_account_state_gas` | 183,600 | per authorization whose authority does not exist |
| `glamsterdam_zero_deposit_refund_state_gas` | 97,920 | self-paying op whose sender deposit is zero |

The values were measured on glamsterdam-devnet-8 with EntryPoint v0.7 using the calibration harness in [#1345](https://github.com/alchemyplatform/rundler/pull/1345) ([`test/pvg-calibration/README.md`](https://github.com/alchemyplatform/rundler/blob/rado/calibrate-pvg/test/pvg-calibration/README.md)). `ethereum_glamsterdam_devnet` is the hardcoded spec for that devnet. See [Glamsterdam pre-verification gas](./glamsterdam_pvg.md) for how the state-dependent terms are applied.
