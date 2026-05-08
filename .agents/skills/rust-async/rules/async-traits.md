# Use Existing Async Trait Patterns

## Rule

Use `async_trait` consistently for object-safe async trait boundaries.

## Why

Rundler uses `async_trait` on provider, pool, builder, signer, RPC, and task
boundaries that need trait objects or mock support.

## Examples

- Good: follow the surrounding module's `#[async_trait::async_trait]` or
  imported `#[async_trait]` style.
- Bad: introduce a second incompatible trait pattern in the same boundary.

## Exceptions

Concrete helper methods do not need trait abstraction.
