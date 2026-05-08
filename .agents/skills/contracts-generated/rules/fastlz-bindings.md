# Keep FastLZ Bindgen Source-Owned

## Rule

Edit FastLZ C/header inputs or the build script, not generated bindgen output.

## Why

`crates/bindings/fastlz/build.rs` compiles `fastlz/fastlz.c` and generates Rust
bindings from `fastlz/fastlz.h` into `OUT_DIR`.

## Examples

- Good: edit C/header sources or `build.rs`.
- Bad: commit generated bindgen output from `OUT_DIR`.

## Exceptions

Generated output can be inspected locally when debugging bindgen.

