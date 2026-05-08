# Keep Foundry and Submodules Aligned

## Rule

Update submodule, docs, and CI assumptions together when changing contract
sources or Foundry behavior.

## Why

CI installs Foundry `v1.5.0` and checks out submodules recursively. EntryPoint
versions come from account-abstraction submodules for v0.6 through v0.9.

## Examples

- Good: update `.gitmodules`, docs, and CI together when changing upstream
  contract sources or Foundry expectations.
- Bad: assume a missing contract is deleted when submodules are not initialized.

## Exceptions

Pure Rust changes need not initialize every submodule unless the build path
touches contracts.

