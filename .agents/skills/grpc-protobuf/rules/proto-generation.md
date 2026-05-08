# Regenerate from `.proto`

## Rule

Edit source `.proto` schemas and hand-written conversion code, not generated
Rust.

## Why

`crates/builder/build.rs` and `crates/pool/build.rs` call `tonic_build` and
write descriptor sets in `OUT_DIR`. Runtime modules use `tonic::include_proto!`
and `include_file_descriptor_set!`.

## Examples

- Good: edit `crates/builder/proto/builder/builder.proto` or
  `crates/pool/proto/op_pool/op_pool.proto`.
- Bad: edit generated Rust under Cargo output directories.

## Exceptions

Conversion code in `protos.rs` is hand-written and should be updated alongside
schema changes.

