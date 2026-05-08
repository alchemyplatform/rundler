# Route by EntryPoint Address and ABI Version

## Rule

Use `EntryPointRouter` and `ChainSpec` for EntryPoint-specific RPC behavior.

## Why

`EntryPointVersion::V0_8` and `V0_9` are distinct versions but share the v0.7
ABI. `EntryPointRouter` validates that the user operation variant matches the
route's ABI before simulation or pool insertion.

## Examples

- Good: use `ChainSpec::entry_point_version`, `EntryPointRouter`, and
  `TryIntoRundlerType` for RPC conversions.
- Bad: infer v0.7/v0.8/v0.9 behavior from the JSON shape alone.

## Exceptions

Endpoints without an EntryPoint argument may query all enabled routes, as
receipt/status methods do.

