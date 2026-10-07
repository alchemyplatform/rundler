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

### Gas schedules and Glamsterdam

The top-level gas fields (`transaction_intrinsic_gas`, the calldata and EIP-7623 floor costs,
`eip7702_authorization_gas`, the `per_user_op_*` overheads and `deposit_transfer_overhead`) are
the gas schedule before Glamsterdam.

`glamsterdam_activation` sets when the Glamsterdam schedule takes effect:

- `"never"` (default): the chain always uses the top-level gas fields.
- `"genesis"`: the chain always uses the Glamsterdam schedule.
- A Unix timestamp in seconds, e.g. `1791294816`: blocks with a timestamp at or after this value
  use the Glamsterdam schedule. `CHAIN_GLAMSTERDAM_ACTIVATION` accepts the same values.

The Glamsterdam schedule is a preset (`GasSchedule::glamsterdam_preset` in
[chain.rs](../../crates/types/src/chain.rs)), with any `glamsterdam_<field>` override applied
on top, for example `glamsterdam_per_user_op_v0_7_gas = 40000`. Only the gas fields above can be
overridden. Rundler rejects a chain spec at startup if either schedule is invalid, including a
zero transaction intrinsic or EIP-7702 authorization gas cost, and logs both schedules when an
activation is configured.

Rundler chooses gas costs from the latest block (for estimation and pool admission, fetched once
per request) or the triggering block (for pool maintenance and bundle building):

- before a timestamp activation, it uses the larger cost of each gas field from the two schedules,
  because a bundle submitted before the activation may be included after it. Estimation, pool
  admission, pool maintenance and bundle building all use this schedule, so the
  preVerificationGas Rundler estimates before the fork is enough for the builder on either side
  of it;
- at or after the activation, or with `"never"` or `"genesis"`, it uses that block's schedule.

The higher pre-fork costs start as soon as a future timestamp is configured, even well before
activation. Required preVerificationGas goes up, particularly for EIP-7702 operations: the
default Glamsterdam preset raises the per-authorization allowance from 25,000 to 235,606 gas.
Large calldata can hit the higher floor. Bundle capacity can also drop, and the delegation sender
uses the larger authorization allowance when setting its batch size. With
`glamsterdam_activation = "never"`, Rundler uses only the existing top-level gas schedule.

The activation doesn't need a restart or config reload, but every Rundler process (RPC, pool,
builder) must run with the same activation before the timestamp is reached.

On chains with an activation configured, pool maintenance rechecks every operation's
preVerificationGas against the triggering block's schedule, and the builder checks it again
when building a bundle. Operations that don't cover it become ineligible for bundling, for
example ones admitted after the activation when a reorg moves the chain back before it. They stay
in the pool until they expire or are replaced, and become eligible again once they cover the
schedule. Signed gas limits are never changed, so a client must re-estimate and re-sign to get
such an operation bundled.

### Hardcoded Chan Specs

See the files [here](../../bin/rundler/chain_specs/) for a list of hardcoded chain specifications.

### Glamsterdam gas schedule values

The Glamsterdam preset adds four gas fields that are 0 before Glamsterdam, so pre-Glamsterdam
pricing is unchanged. Each can be overridden like the others (`glamsterdam_<field>`).

| Field | Preset | Meaning |
| --- | --- | --- |
| `call_data_word_gas` | 6 | extra gas per 32-byte word of an op's `callData` (the EntryPoint's unmetered copy of it) |
| `zero_deposit_refund_gas` | 97,920 | self-paying op whose sender deposit is zero |
| `eip7702_authorization_new_account_gas` | 183,600 | part of `eip7702_authorization_gas` waived when the authority exists |
| `eip7702_authorization_delegation_gas` | 35,190 | part of `eip7702_authorization_gas` also waived when the authority already has code |

The preset also sets measured values for existing fields:

| Field | Preset | Meaning |
| --- | --- | --- |
| `transaction_intrinsic_gas` | 15,000 | intrinsic gas of a bundle tx (EIP-2780 base + cold EntryPoint) |
| `per_user_op_v0_7_gas` | 21,900 | per-op unmetered EntryPoint overhead, v0.7 |
| `per_user_op_v0_6_gas` | 22,100 | per-op overhead, v0.6 (measured on Sepolia) |
| `eip7623_calldata_floor_*_byte_gas` | 64 | EIP-7976 floor gas per calldata byte |
| `eip7702_authorization_gas` | 235,606 | per EIP-7702 authorization whose authority does not exist (52,006 if it exists, 16,816 if it already has code) |

The values were measured on glamsterdam-devnet-8 with EntryPoint v0.7, and `per_user_op_v0_6_gas` on Sepolia with EntryPoint v0.6, using the calibration harness in [#1345](https://github.com/alchemyplatform/rundler/pull/1345) ([`test/pvg-calibration/README.md`](https://github.com/alchemyplatform/rundler/blob/rado/calibrate-pvg/test/pvg-calibration/README.md)). `ethereum_glamsterdam_devnet` is the hardcoded spec for that devnet (`glamsterdam_activation = "genesis"`). See [Glamsterdam pre-verification gas](./glamsterdam_pvg.md) for how the state-dependent terms are applied.
