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
