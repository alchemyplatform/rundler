# Keep Builder Affinity and Proxies Matched

## Rule

Keep mempool filters, builder affinity, and submission proxies consistent.

## Why

Builder config can define filter-specific virtual entrypoints and submission
proxies. Pool filters must have matching builder affinity or operations can
enter a mempool that no builder mines.

## Examples

- Good: update builder config docs/tests when changing
  `EntryPointBuilderConfigs`.
- Bad: add a mempool filter without a corresponding builder path.

## Exceptions

Default builders without filters can handle unfiltered mempools.

