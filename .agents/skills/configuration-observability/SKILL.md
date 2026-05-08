---
name: configuration-observability
description: |
  Use when changing CLI/env config, chain specs, JSON/S3 config loading, provider retry/timeout behavior, metrics, tracing, logs, or secret handling.
last_verified: 2026-05-06
---

# Configuration Observability

Rundler resolves config from CLI/env/files, applies chain specs, wraps Alloy
providers with retry/timeout/metrics layers, and exposes tracing/metrics for
cloud operation.

## Rules

| Rule | Read when |
| --- | --- |
| [chain-spec-resolution](rules/chain-spec-resolution.md) | Adding chain spec fields or hardcoded networks |
| [json-config-loading](rules/json-config-loading.md) | Changing JSON config file loading |
| [provider-layers](rules/provider-layers.md) | Changing Alloy retry, timeout, or metrics layers |
| [observability-and-secrets](rules/observability-and-secrets.md) | Adding logs, metrics, tracing, or secret handling |
