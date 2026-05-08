# Keep Proto and Domain Conversions Lossless

## Rule

Update both directions of proto/domain conversion when schema changes require
it.

## Why

Pool and builder remote modules convert between proto structs and domain types,
including `UserOperationVariant`, `EntryPointVersion`, `Eip7702Auth`,
`PoolError`, `MempoolError`, and simulation/precheck violations.

## Examples

- Good: add both `From` and `TryFrom` paths where the existing pattern has both
  directions.
- Bad: collapse distinct domain errors into an internal string unless the
  existing boundary already treats them as internal.

## Exceptions

Truly unexpected remote responses may remain `PoolError::UnexpectedResponse`.
