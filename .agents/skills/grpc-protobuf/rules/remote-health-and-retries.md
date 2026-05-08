# Preserve Remote Health and Retry Semantics

## Rule

Use the existing retry and health-check patterns for long-running remote pool
and builder clients.

## Why

Standalone RPC connects to remote pool and builder services via
`connect_with_retries_shutdown`, and remote services implement `HealthCheck`.

## Examples

- Good: reuse `rundler_task::server` retry helpers and health checks.
- Bad: make a one-shot remote connection that fails startup on normal service
  ordering races.

## Exceptions

Admin or one-shot tools can fail fast when they do not participate in
long-running service startup.

