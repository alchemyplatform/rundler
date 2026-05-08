# Protect Secrets with `SecretString`

## Rule

Keep secret-bearing CLI and sender values in `SecretString` and expose them
only at use sites.

## Why

CLI private keys, mnemonics, Flashbots auth keys, and Bloxroute auth headers use
`SecretString`.

## Examples

- Good: parse secret CLI/env values with `parse_secret`.
- Bad: derive `Debug` output that prints raw keys, mnemonics, or auth headers.

## Exceptions

Public signer addresses and KMS key IDs may be logged when that is already the
established operational signal.
