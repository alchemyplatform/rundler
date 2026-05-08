# Keep Tokio Feature Assumptions Local

## Rule

Only use Tokio APIs that are enabled for the crate you are editing.

## Why

The workspace `tokio` dependency enables only `rt`, `sync`, and `time`.
`bin/rundler` adds macros, multithreaded runtime, and signal support.

## Examples

- Good: add required Tokio features to the crate that needs them.
- Bad: use `#[tokio::main]`, signals, or macros in a library crate without
  checking its `Cargo.toml`.

## Exceptions

`bin/rundler` owns CLI runtime setup and may use the binary's broader Tokio
feature set.

