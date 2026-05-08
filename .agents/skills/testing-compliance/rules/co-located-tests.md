# Prefer Co-located Rust Tests

## Rule

Add focused Rust tests near the module they exercise.

## Why

Most unit tests live in `#[cfg(test)] mod tests` near the changed module, using
`#[test]` or `#[tokio::test]`.

## Examples

- Good: add focused tests next to the changed module.
- Bad: create a distant integration test when a module-local unit test captures
  the behavior.

## Exceptions

Distributed or end-to-end behavior belongs in spec or harness tests.

