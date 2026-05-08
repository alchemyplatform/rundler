---
name: grpc-protobuf
description: |
  Use when editing pool or builder protobuf schemas, tonic build files, remote clients/servers, proto conversions, or distributed-mode health/retry behavior.
last_verified: 2026-05-06
---

# gRPC Protobuf

Rundler uses tonic for internal pool and builder gRPC services in distributed
mode. Generated Rust lives in Cargo `OUT_DIR`; source-of-truth schemas live in
`crates/*/proto/`.

## Rules

| Rule | Read when |
| --- | --- |
| [proto-generation](rules/proto-generation.md) | Editing schemas or tonic build files |
| [buf-and-cargo-validation](rules/buf-and-cargo-validation.md) | Validating protobuf changes |
| [domain-conversions](rules/domain-conversions.md) | Updating `protos.rs` conversion code |
| [remote-health-and-retries](rules/remote-health-and-retries.md) | Changing remote service startup or clients |
