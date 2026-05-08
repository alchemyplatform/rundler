# Keep Crate Lints Green

## Rule

Honor crate-level lints when adding public APIs, dependencies, or fallible work.

## Why

Crates use `#![warn(missing_docs, unreachable_pub, unused_crate_dependencies)]`
and `#![deny(unused_must_use, rust_2018_idioms)]`.

## Examples

- Good: document public APIs added to library crates.
- Bad: ignore `Result` values from async work or add unused crate dependencies.

## Exceptions

Test-only dependency markers such as the existing `cargo_husky as _` pattern
should remain isolated to tests.
