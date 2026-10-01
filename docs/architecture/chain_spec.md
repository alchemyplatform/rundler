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

Rundler chooses gas costs as follows:
- gas estimation and pool admission use the latest block, fetched once per request;
- bundle building uses a gas schedule that covers both the triggering block and any later
  inclusion block while a timestamp activation is pending. This uses the larger cost for each
  gas field, because a submitted transaction may remain pending across the activation.
  Before activation, the builder also checks each operation's preVerificationGas against that
  inclusion schedule, even on chains without DA gas. An operation admitted under the current
  schedule can therefore remain in the pool but be skipped for a bundle until it is replaced with
  enough preVerificationGas.

This conservative bundle sizing starts as soon as a future timestamp is configured, even well
before activation. It can reduce bundle capacity, particularly for EIP-7702 operations: the
default Glamsterdam preset raises the per-authorization allowance from 25,000 to 235,606 gas.
The delegation sender also uses the larger authorization allowance when setting its batch size.
Large calldata can hit the higher floor. With `glamsterdam_activation = "never"`, the builder uses
only the existing top-level gas schedule and skips this additional PVG check.

An estimation or admission request that spans the activation keeps the schedule of its pinned
block. The activation doesn't need a restart or config reload, but every Rundler process (RPC,
pool, builder) must run with the same activation before the timestamp is reached.

On chains with an activation configured, pool maintenance rechecks every operation's
preVerificationGas against the current block's schedule. Operations that no longer cover it
become ineligible for bundling. They stay in the pool until they expire or are replaced, and
become eligible again if a reorg moves the chain back before the activation. Signed gas limits
are never changed, so a client must re-estimate and re-sign to get such an operation bundled.

### Hardcoded Chan Specs

See the files [here](../../bin/rundler/chain_specs/) for a list of hardcoded chain specifications.
