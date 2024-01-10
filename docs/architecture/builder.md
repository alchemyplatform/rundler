# Builder Task

The builder task is responsible for creating bundle transactions, signing them, submitting them, and tracking their status. 

## Bundle Sender

The bundle sender module is the main state machine that runs the bundle building logic. It follows the following steps:

1. Wait for a new block event from the `Pool`.
2. Request a new bundle from the [bundle proposer](#bundle-proposer).
3. Create and [sign](#transaction-signers) the bundle transaction.
4. Submit the transaction through a [transaction sender](#transaction-senders).
5. [Track](#transaction-tracking) the status of the bundle transaction, re-submitting if needed, until either the transaction is minded, or it is abandoned. Then return to 1.

## Bundle Proposer

The bundle proposer module's main responsibility is to construct a valid bundle transaction.

The proposer asks the `Pool` for pending user operations sorted by priority fee, filters them for profitability, re-simulates them and rejects invalid UOs, then optionally calculates any aggregated signatures.

### Required Fees

The proposer first estimates the required fees for the bundle transaction and then calculates the minimum required fees for a user operation. This calculation is based on a configuration option and is one of:

- **Priority Fee Increase Percent**: Require the UO priority fee to be N% higher than the bundle priority fee.
  - Configured via `--priority_fee_mode_kind=priority_fee_increase_percent --priority_fee_mode_value=N`

- **Base Fee Percent**: Require the UO priority fee to be N% of the base fee.
  - Configured via `--priority_fee_mode_kind=base_fee_percent --priority_fee_mode_value=N`

These can be tweaked to modify the bundler's profitability.

### Gas Limit

The proposer limits the amount of UO gas that it will attempt to put into a single bundle to ensure that transactions are below the gas cap of a block. This limit is calculated by summing the maximum gas usage of each UO in the bundle. If a UO puts the bundle over this limit, it (and all following UOs) will be skipped (but not removed from the pool).

The maximum gas usage of each UO is a function of its `preVerificationGas`, `verificationGasLimit`, and `callGasLimit`.

### 2nd Simulation and Rejection

Once a candidate bundle is constructed, each UO is re-simulated and validation rules are re-checked. UOs that fail are removed from the bundle and removed from the pool.

After 2nd simulation the entire bundle is validated via an `eth_call`, and ops that fail validation are again removed from the bundle. This process is repeated until the entire bundle passes validation.

NOTE: This procedure implements an old version of the spec and will be updated to conform soon. See [here](https://github.com/eth-infinitism/account-abstraction/blob/develop/erc/ERCS/erc-4337.md#bundling) for more details on the new implementation.

## Transaction Signers

The bundle builder supports a signer interface used for transaction signing. There are currently 2 implementations:

- **Private Key**: Rundler is configured with a private key via a CLI variable directly.

- [**KMS**](#kms-with-key-leasing): AWS KMS is used for signing.

### KMS with Key Leasing

When using AWS KMS for signing Rundler requires the use of Redis to perform key leasing.

To ensure that no two signers in a bundler system attempt to use the same key, causing nonce collisions, this key leasing system is used to lease a key in a CLI configured list to a single signer at a time.

## Transaction Senders

The builder supports multiple sender implementations to support bundle transaction submission to different types of APIs.

- **Raw**: Send the bundle as an `eth_sendRawTransaction` via a standard ETH JSON-RPC.

- **Conditional**: Send the bundle as an `eth_sendRawTransactionConditional` to an interface that supports the [conditional transaction RPC](https://notes.ethereum.org/@yoav/SkaX2lS9j).

- **Flashbots**: Submit bundles via the [Flashbots Protect](https://docs.flashbots.net/) RPC endpoint, only supported on Ethereum Mainnet.

- **Bloxroute**: Submit bundles via Bloxroute's [Polygon Private Transaction](https://docs.bloxroute.com/apis/frontrunning-protection/polygon_private_tx) endpoint. Only supported on polygon.

## Transaction Tracking

After the bundle transaction is sent, the sender tracks its status via the transaction tracker module. This module tracks to see if a transaction is pending, dropped, or mined.

If after a configured amount of blocks the transaction is still pending, the sender will attempt to re-estimate gas fees and will submit a new bundle that replaces the old bundle.

If dropped or mined, the sender will restart the process.

## N-Senders

Rundler has the ability to run N bundle sender state machines in parallel, each configured with their own distinct signer/account for bundle submission.

In order for bundle proposers to avoid attempting to bundle the same UO, the sender is configured with a mempool shard index that is added to the request to the pool. This shard index is used by the pool to always return a disjoint set of UOs to each sender.

N-senders can be useful to increase bundler gas throughput.
