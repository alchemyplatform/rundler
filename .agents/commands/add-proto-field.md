---
name: Add Proto Field
description: Change a pool or builder protobuf schema and update all conversion and validation boundaries.
argument-hint: [service] [field_name]
---

## How It Works

1. Identify whether the change belongs to pool or builder gRPC.
2. Edit the source `.proto` schema.
3. Update hand-written proto/domain conversions.
4. Validate with Buf and Cargo build.
5. Add tests around conversion behavior.

## Instructions

### Validate Arguments

- `$1` — **service**: Required, `pool` or `builder`.
  - **Suggest:** Use `crates/pool/proto` and `crates/builder/proto`.
- `$2` — **field_name**: Required field or message name being added/changed.

### 1. Load Context

Read `.agents/skills/grpc-protobuf/SKILL.md` and
`.agents/skills/testing-compliance/SKILL.md`.

### 2. Edit Source Schema

Edit only source schemas:

- Pool: `crates/pool/proto/op_pool/op_pool.proto`
- Builder: `crates/builder/proto/builder/builder.proto`

If you add a new proto file, update the matching `build.rs`.

### 3. Update Conversions

Update the corresponding `protos.rs` module. Keep `From` and `TryFrom`
conversions lossless for domain types, error variants, bytes, addresses,
EntryPoint versions, and EIP-7702 auth.

### 4. Verify

Run:

```bash
buf lint
cargo build --all --all-features
make test-unit
```

Report any gates skipped with the reason.
