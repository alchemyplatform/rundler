# ChangeLog

## v0.6.0

1. Support Signature Aggregator
1. Instrument with OpenTelemetry Trace.
1. Bump to rust 1.85.

---

## v0.5.0

### Feautres

1. Support 7702
1. Fix Paymaster PostOp validation
1. Update Alloy 0.7
1. Update Foundry 0.3
1. Update Rust 1.83
1. Add a maximum valid time for UOs

---

## v0.4.0

### Feautres

1. Alloy migration
1. PreVerificationGas DOS fix
1. Use Reth task management
1. Switch to metrics-derive
1. Configurable gas limit efficiency requirement to mitigate gas limit DOS attacks
1. Custom tower-based metrics middleware for alloy, jsonrpsee, tonic
1. Configurable base fee overhead requirement
1. Update rust to v1.82

### BREAKING CHANGES

Type changes to chain spec variables. Most integer values now must be configured as integer strings instead of hex strings. Check the diff to see which variables this applies to.

---

## v0.3.0

### Feautres

1.  Bundle builder state machine improvements.

    1.  Rewrite the state machine to support "cancellations."
    1.  Introduce hard and soft cancellations.
    1.  Remove maximum fee increases from bundle submission .
    1.  Remove transaction status polling from the tracker, the state machine runs completely off of a defined trigger - either a new block or a timeout.
    1.  Add time to mine tracking and metrics.

1.  Chain support:
    1. Add support for Avalanche
    1. Ban access to Arbitrum Stylus contracts without whitelist
    1. Remove Goerli networks
1.  Allow for multiple private keys to be configured.
1.  Allow staked senders to have multiple UOs per bundle.
1.  Check for total gas limit exceeded after estimation.
1.  Remove ops from pool if condition is not met when using conditional RPC.
1.  Update to Rust v1.79.0
1.  Fix transaction sender's support of transaction status across various provider types.

### Bug fixes

1. Fix race condition in paymaster tracking.
1. Fix error message for unstaked entity mempool count.
1. Raise Polygon Amoy chain configuration min fee to 30 gwei.
1. Add a timeout of 10s to the tracer calls.

### Breaking changes

1. Removed BUILDER_MAX_FEE_INCREASES replaced with BUILDER_MAX_CANCELLATION_FEE_INCREASES
1. Removed BUILDER_SENDER=conditional replaced with BUILDER_SENDER=raw and BUILDER_USE_CONDITIONAL_RPC=true
1. Deprecated BUILDER_PRIVATE_KEY replaced with BUILDER_PRIVATE_KEYS

---

## v0.2.0

### Features:

1. Entry point v0.7 support
1. Bug fixes

---
