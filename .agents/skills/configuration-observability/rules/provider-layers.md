# Compose Provider Layers Deliberately

## Rule

Keep provider retry, consistency retry, metrics, and timeout behavior explicit.

## Why

Alloy providers can include rate-limit retry, consistency retry, metrics, and
client-side timeout layers. Consistency retry is specifically for block/header
not found style errors.

## Examples

- Good: make retry and timeout settings explicit in `AlloyNetworkConfig`.
- Bad: retry every RPC error as a consistency issue.

## Exceptions

Sender-specific retry behavior belongs in transaction sender code.

