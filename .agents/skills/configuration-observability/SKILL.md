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

| Rule                  | Read when                                                                          |
| --------------------- | ---------------------------------------------------------------------------------- |
| [core](rules/core.md) | Editing config resolution, chain specs, provider layers, logs, metrics, or secrets |
