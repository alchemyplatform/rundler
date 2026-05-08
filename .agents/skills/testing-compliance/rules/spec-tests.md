# Choose Spec Tests for EntryPoint Behavior

## Rule

Run ERC-4337 spec tests when changes affect protocol behavior or distributed
service boundaries.

## Why

`make test-spec-integrated` runs local/integrated spec tests. `make
test-spec-modular` runs remote/distributed mode. CI compliance runs v0.6, v0.7,
and v0.8 through `alchemyplatform/bundler-test-executor`.

## Examples

- Good: run targeted spec tests when changing RPC flows, simulation, EntryPoint
  routing, mempool acceptance, or builder submission behavior.
- Bad: claim spec safety from unit tests alone.

## Exceptions

Isolated docs or internal refactors may only need unit/lint gates.
