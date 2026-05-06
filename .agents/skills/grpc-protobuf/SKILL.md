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

| Rule                  | Read when                                                                |
| --------------------- | ------------------------------------------------------------------------ |
| [core](rules/core.md) | Editing `.proto`, remote server/client code, or proto/domain conversions |
