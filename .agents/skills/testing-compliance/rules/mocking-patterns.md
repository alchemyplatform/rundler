# Use Established Mocking Patterns

## Rule

Reuse existing mockall and manual mock patterns.

## Why

Provider traits expose `test-utils` mock helpers, builder traits use mockall,
and complex chain tests use hand-rolled mocks such as `MockBlock` and
`MockEvmProvider`.

## Examples

- Good: reuse `crates/provider/src/traits/test_utils.rs` and existing manual
  mock patterns.
- Bad: mock at an unrelated abstraction layer that bypasses the behavior under
  test.

## Exceptions

Small pure functions should use direct inputs without mocks.
