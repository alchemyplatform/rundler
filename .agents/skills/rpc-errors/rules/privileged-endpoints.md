# Gate Privileged Endpoints

## Rule

Default-dangerous or state-mutating RPC endpoints must be explicitly gated.

## Why

`admin_*` is exposed only when the `admin` namespace is enabled. Sponsored
delegation is disabled by default because callers can drain available signers.

## Examples

- Good: add explicit settings for dangerous endpoints and default them off.
- Bad: add a method that mutates pool, builder, or signer state to a
  default-enabled namespace without a gating decision.

## Exceptions

Read-only status methods may remain in the default `eth` or `rundler` namespace
when they do not mutate state.

