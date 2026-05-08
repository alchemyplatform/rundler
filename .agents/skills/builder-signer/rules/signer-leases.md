# Keep Signer Leases Balanced

## Rule

Return signer leases on every terminal path.

## Why

`SignerManager` leases signers and requires `return_lease` to release them.
Funding-aware signers can move between `Available`, `NeedsFunding`, `Leased`,
and `LeasedNeedsFunding`.

## Examples

- Good: return leases on every success, failure, cancellation, and early-exit
  path.
- Bad: hold a signer across waits that do not need signing.

## Exceptions

A bundle sender may keep its paired lease during the transaction tracking state
machine by design.

