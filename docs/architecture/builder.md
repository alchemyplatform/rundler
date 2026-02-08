# Builder Task

The builder task is responsible for creating bundle transactions, signing them, submitting them, and tracking their status. 

## Bundle Sender

The bundle sender module is the main state machine that runs the bundle building logic. Each worker runs its own bundle sender instance. The sender follows these steps:

1. Wait for a new block event from the `Pool`.
2. Request work assignment from the [Assigner](#assigner), which selects an entrypoint and assigns eligible operations.
3. Request a new bundle from the [bundle proposer](#bundle-proposer) for the assigned entrypoint.
4. Create and [sign](#transaction-signers) the bundle transaction.
5. Submit the transaction through a [transaction sender](#transaction-senders).
6. [Track](#transaction-tracking) the status of the bundle transaction, re-submitting if needed, until either the transaction is mined, or it is abandoned.
7. Notify the Assigner of bundle completion (success or failure) to release sender assignments. Then return to 1.

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

## Transaction Signers

The bundle builder supports a signer interface used for transaction signing. There are currently 2 implementations:

- **Private Key**: Rundler is configured with a private key via a CLI variable directly.

- [**KMS**](#kms-with-key-leasing): AWS KMS is used for signing.

### KMS with Key Leasing

When using AWS KMS for signing Rundler requires the use of Redis to perform key leasing.

To ensure that no two signers in a bundler system attempt to use the same key, causing nonce collisions, this key leasing system is used to lease a key in a CLI configured list to a single signer at a time.

## Transaction Senders
The builder supports multiple sender implementations to support bundle transaction submission to different types of APIs.

- **Raw**: Send the bundle as an `eth_sendRawTransaction` via a standard ETH JSON-RPC. If conditional RPC is enabled it will send the bundle as an `eth_sendRawTransactionConditional` to an interface that supports the [conditional transaction RPC](https://notes.ethereum.org/@yoav/SkaX2lS9j).

- **Flashbots**: Submit bundles via the [Flashbots Protect](https://docs.flashbots.net/) RPC endpoint, only supported on Ethereum Mainnet.

- **Bloxroute**: Submit bundles via Bloxroute's Polygon Private Transaction endpoint. Only supported on polygon.

## Signer Sharing Architecture

Rundler supports running multiple bundle sender workers with a shared pool of signers. This architecture enables efficient resource utilization across multiple entry points and configurations.

### Workers and Signers

Each worker (bundle sender) is paired 1:1 with a signer. However, each worker handles ALL configured entry points rather than being dedicated to a single one. The Assigner dynamically selects which entrypoint a worker builds for on each cycle based on mempool state. This means:

- Every worker can service any configured entry point or filter configuration
- Work is distributed across workers based on which entrypoints have the most pending operations
- Starvation prevention ensures all entrypoints get serviced even under uneven load

The number of workers is controlled via `--num_signers`.

### Assigner

The Assigner component is responsible for coordinating work distribution among workers:

1. **Entrypoint Selection**: Uses a priority-based strategy with starvation prevention
   - Primary: Select the entrypoint with the most eligible operations (throughput-optimized)
   - Starvation prevention: If any entrypoint hasn't been selected in `num_signers * starvation_ratio` cycles, force-select the most starved one. Here `starvation_ratio` acts as a multiplier on signer count. For example, with 4 signers and the default ratio of 0.50, an entrypoint is force-selected after 2 idle cycles.

2. **Operation Assignment**: Ensures no two workers attempt to bundle operations from the same sender simultaneously
   - Tracks sender-to-worker assignments
   - Filters out operations assigned to other workers
   - Releases assignments when bundles complete

3. **Virtual Entrypoints**: Supports multiple configurations per entry point address via `filter_id`, creating "virtual entrypoints" that workers can build for independently

### Proposers

Proposers are stored in a shared `HashMap<(Address, Option<String>), BundleProposerT>` keyed by `(entrypoint address, filter_id)`. Each proposer handles bundle construction, fee estimation, and revert processing for its entrypoint configuration. Workers look up the appropriate proposer after the Assigner selects an entrypoint.

## Sender State Machine

The bundle sender is implemented as an finite state machine to continuously submit bundle transactions onchain. The state machine runs as long as the builder process is running.

### States

**`Building`**

In the building state the sender is waiting for a trigger. Once triggered, the sender will query the mempool for available user operations. Those user operations are then filtered by the current fees, total gas limit, and simulation results. If before/after the filtering there are no candidate user operations, the sender will wait for another trigger. If there are candidate user operations, a bundle transaction is submitted. If a cancellation is required, the sender will transfer to the cancelling state.

**`Pending`**

In the pending state the builder is waiting for a bundle transaction to be mined. It will wait in this state for up to `max_blocks_to_wait_for_mine` blocks. If mined, dropped, or timed out (abandoned) the sender will transition back to the building state with the appropriate metadata captured.

**`Cancelling`**

In the cancelling state the builder creates a cancellation operation. The shape of this operation depends on the type of transaction sender being used. If a "hard" cancellation operation is submitted the sender will submit a cancellation transaction and transition to the cancel pending state. If a "soft" cancellation operation is submitted it will transition back to the building state immediately. 

**`CancelPending`**

In the cancel pending state the builder is waiting for a cancellation transaction to be mined. It will wait in this state for up to `max_blocks_to_wait_for_mine` blocks. If mined, the sender will transition back to the building state. If dropped or timed out (abandoned), the sender will transition back to the cancelling state. If the sender has already performed `max_cancellation_fee_increases`, and the transaction has been abandoned, it will transition back to the building state and reset internal state.

### Triggers

While in the building state the sender is waiting for a trigger. There are 3 types of triggers:

* New block (building mode: auto): Trigger bundle building when a new block is mined.
* Time (building mode: auto): Trigger bundle building after `bundle_max_send_interval_millis` (chain spec) has elapsed without a bundle attempt.
* Manual call (building mode: manual): Trigger bundle building on a call to `debug_bundler_sendBundleNow`.

### Cancellations

Cancellations occur in a specific scenario: there are user operations available that pay more than the estimated gas price, but when the sender submits the bundle transaction it receives a "replacement underpriced" error. If after increasing the fee the user operations are priced out, we are in an "underpriced" meta-state.

The first time the sender encounters this state it will capture the block number and attempt to create another bundle, resetting the fees. During subsequent encounters the builder will compare that block number to latest, if the difference is more than `max_replacement_underpriced_blocks`, the builder will move to a cancellation state.

The goal of the cancellation state is to remove the pending transaction from the mempool that is blocking the bundle submission, and to do so while spending the least amount of gas. There are two types of cancellations: "hard" and "soft." A "hard" cancellation requires a transaction to be sent onchain. This is typically an empty transaction to minimize costs. A "soft" cancellation does not require a transaction and is simply an RPC interaction.

### Diagram

```mermaid
---
title: Bundle Sender State Machine (Simplified)
---
stateDiagram-v2
  Building: Building
  Pending
  Cancelling
  CancelPending

  [*] --> Building
  Building --> Building : No operations
  Building --> Pending : Bundle submitted
  Pending --> Building : Bundle mined/dropped/abandoned
  Building --> Cancelling : Cancel triggered
  Cancelling --> CancelPending: Hard cancellation submitted
  Cancelling --> Building : Soft cancellation completed
  CancelPending --> Cancelling: Cancellation dropped/abandoned
  CancelPending --> Building: Cancellation mined/aborted
```

## Builders Configuration

Rundler supports running multiple builder workers per node. To configure the number of workers, set `--num_signers` to the desired count. Ensure that you have provisioned enough private or KMS keys for the configured number of workers.

Each worker is paired 1:1 with a leased signer. The Assigner coordinates which entrypoint each worker builds for on each cycle, ensuring no two workers attempt to bundle operations from the same sender simultaneously.

### Custom

Most deployments of Rundler should be able to use the simple `--num_signers` configuration. For advanced use cases requiring per-entrypoint builder configurations, Rundler supports a custom configuration file.

See [`EntryPointBuilderConfigs`](../../bin/rundler/src/cli/builder.rs) for the exact schema. Set the path via `--builders_config_path`. When this file is provided, the normal CLI-based options are ignored.

#### Configuration Schema

```json
{
    "entryPoints": [
        {
            "address": "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
            "builders": [
                {
                    "filterId": "my-mempool-filter",
                    "proxy": "0xA7BD3A9Eb1238842DDB86458aF7dd2a9e166747A",
                    "proxyType": "passthrough"
                }
            ]
        }
    ]
}
```

#### Fields

- **address** (required): The entry point contract address. This is used to match the configuration to the correct entry point.
- **builders**: Array of builder configurations for this entry point
  - **filterId** (optional): Associates this builder with a specific [mempool filter](./pool.md#filtering)
  - **proxy** (optional): Submission proxy contract address
  - **proxyType** (optional): Type of proxy implementation (see [Proxies](#proxies))

#### Affinity

Builders may specify a `filterId` in their custom configuration in order to only receive user operations that match a [mempool filter](./pool.md#filtering). Each mempool filter that is defined must have a matching builder - else the user operations matching that filter will not be mined.

#### Proxies

Set a separate contract address, via the `proxy` config, that the builder should submit bundles through. The contract at this address MUST have the same ABI as `IEntryPoint` for all methods used: `handleOps` and `handleAggregatedOps` if using non-aggregated/aggregated ops respectively.

If the proxy contract has custom errors that need to be handled during bundle simulation, a `SubmissionProxy` implementation must be supported. To associate the `proxy` with its implementation, use the configuration `proxyType`.

Supported types:
* `passthrough` (default): no logic
* `pbh`: support for the PBH entrypoint proxy. Implements special handling for its revert reasons.
