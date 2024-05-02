# Entry Point Support

Rundler currently supports the most recent two entry point versions:

  * [v0.6.0](https://github.com/eth-infinitism/account-abstraction/tree/v0.6.0)
  * [v0.7.0](https://github.com/eth-infinitism/account-abstraction/tree/v0.7.0)

## Configuration

Rundler's entry point support is controlled by the following CLI options:

Enable/disable entry point versions (defaults to both enabled):
- `--entry_point_v0_6_enabled`
- `--entry_point_v0_7_enabled`

Modify the number of builders (and thus keys) associated with each entry point:
- `--num_builders_v0_6`
- `--num_builders_v0_7`

Rundler expects that the entry point contract is deployed at a deterministic address. It defaults to:

- v0.6.0: `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`
- v0.7.0: `0x0000000071727De22E5E9d8BAf0edAc6f37da032`

If a chain has the entry point deployed at a different address, these addresses can be modified using the chain spec configurations: `entry_point_address_v0_6` and `entry_point_address_v0_7`.

Rundler expects that the entry points are unmodified from their canonical versions above. Thus, the only use for overriding the entry point addresses would be due to the lack of a deterministic deployment mechanism on a chain.

## API

Rundler uses the same API interface for both v0.6 and v0.7. It determines which JSON schema to apply to each RPC request based on the provided entry point address.

See the version of the spec associated with the entry point version for the expected schemas.

  * [v0.6.0](https://github.com/eth-infinitism/account-abstraction/blob/v0.6.0/eip/EIPS/eip-4337.md#rpc-methods-eth-namespace)
  * [v0.7.0](https://github.com/eth-infinitism/account-abstraction/blob/v0.7.0/erc/ERCS/erc-4337.md#rpc-methods-eth-namespace)

## Internals

To support multiple entry point versions in the same codebase, Rundler's components are entry point version aware. 

### Types

Versions v0.6 and v0.7 define different User Operation types. Rundler uses the following to represent these different versions:

* `UserOperation` Trait: A common interface for user operation implementations
* `UserOperationVariant`: A container to hold either version of user operation. Implements the trait via passthrough access
* `v0_6::UserOperation`: A v0.6 user operation
* `v0_7::UserOperation`: A v0.7 user operation

Depending on the context a class may elect to access a user operation via any of these interfaces. Only classes that are hyper-specific to a particular version should use the version specific types. We prefer to use the trait as a generic, or the variant, where code sharing between the versions is possible.

### Pool

Rundler will run a separate mempool for each enabled entry point. These pools are still driven by the same tracking logic, but their data structures are completely independent.

### Builder

Rundler will run independent bundle builders for each entry point. Each builder will only interact with the mempool of its same version.

### RPC

Rundler runs a single RPC server to handle both v0.6 and v0.7 requests, and routes requests to their correct version handling based on the provided entry point version.

For endpoints where entry point version is not specified (i.e. `eth_getUserOperationReceipt`) Rundler will apply the request to any enabled entry point. For example, in `eth_getUserOperationReceipt` it will search any enabled entry point's logs for the provided user operation hash.
