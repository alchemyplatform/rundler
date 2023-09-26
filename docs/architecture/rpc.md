# RPC Task

The `RPC` task is the main interface into the Rundler. It consists of 3 namespaces:

- **eth**
- **debug**
- **rundler**

Each of which can be enabled/disabled via configuration.

It also supports a health check endpoint.

## Supported Methods

### `eth_` Namespace

Methods defined by the [ERC-4337 spec](https://github.com/eth-infinitism/account-abstraction/blob/develop/eip/EIPS/eip-4337.md#rpc-methods-eth-namespace).

| Method | Supported |
| ------ | :-----------: |
| `eth_chainId` | ✅ |
| `eth_supportedEntryPoints` | ✅ |
| `eth_estimateUserOperationGas` | ✅ |
| `eth_sendUserOperation` | ✅ |
| `eth_getUserOperationByHash` | ✅ |
| `eth_getUserOperationReceipt` | ✅ |

### `debug_` Namespace

Method defined by the [ERC-4337 spec](https://github.com/eth-infinitism/account-abstraction/blob/develop/eip/EIPS/eip-4337.md#rpc-methods-debug-namespace). Used only for debugging/testing and should be disabled on production APIs.

| Method | Supported |
| ------ | :-----------: |
| `debug_clearState` | ✅ |
| `debug_dumpMempool` | ✅ |
| `debug_sendBundleNow` | ✅ |
| `debug_setBundlingMode` | ✅ |
| `debug_setReputation` | ✅ |
| `debug_dumpReputation` | ✅ |

### `rundler_` Namespace

Rundler specifc methods that are not specified by the ERC-4337 spec.

| Method | Supported |
| ------ | :-----------: |
| [`rundler_maxPriorityFeePerGas`](#rundler_maxpriorityfeepergas) | ✅ |

#### `rundler_maxPriorityFeePerGas`

This method returns the minimum `maxPriorityFeePerGas` that the bundler will accept at the current block height. This is based on the fees of the network as well as the priority fee mode configuration of the bundle builder.

Users of this method should typically increase their priority fee values by a buffer value in order to handle price fluctuations. 

### Health Check

The health check endpoint can be used by infrastructure to ensure that Rundler is up and running.

Currently, it simply queries each the `Pool` and the `Builder` servers to check if they are responding to requests. If yes, Rundler is healthy, else unhealthy.

| Route | Supported |
| ------ | :-----------: |
| `/health` | ✅ |

| Status | Code | Message |
| ------ | :-----------: | ---- |
| Healthy | 200 | `ok` |
| Unhealthy | 500 | JSON-RPC formatted error message | 


## Gas Estimation

To serve `eth_estimateUserOperationGas` Rundler attempts to estimate gas as accurately as possible, while always erroring to over-estimation.

### `preVerificationGas` Estimation

`preVerificationGas` (PVG) is meant to capture any gas that cannot be metred by the entry point during execution. Rundler splits PVG into two separate calculations, static and dynamic.

To run these calculations Rundler currently assumes a bundle size of 1.

#### Static

The static portion of PVG accounts for:

1. Calldata costs associated with the UO.
2. The UOs portion of shared entry point gas usage.

This calculation is static as the result should never change for a given UO.

#### Dynamic

The dynamic portion of PVG is meant to capture any portion that may change based on network conditions. Currently, its only use is to capture the data availability calldata costs on L2 networks that post their data to a separate network.

For example, on Arbitrum One transactions are charged extra gas at the very beginning of transaction processing to pay for L1 Ethereum calldata costs. This value can be estimated by calling a precompiled contract on any Arbitrum One node. This value will change based on the current L1 gas fees as well as the current L2 gas fees. Rundler will estimate this value for a bundle of size 1 and set it to the dynamic portion of pvg.

NOTE: Since the dynamic portion of PVG can change, users on networks that contain dynamic PVG should add a buffer to their PVG estimates in order to ensure that their UOs will be mined when price fluctuates.

### `verificationGasLimit` Estimation

To estimate `verificationGasLimit` Rundler uses a binary search to find the minimum gas value where validation succeeds. The procedure follows:

1. Run an initial attempt at max limit using the gas measurement helper contract. If validation fails here it will never succeed and the UO is rejected.
2. Set the initial guess to the gas used in the initial attempt * 2 to account for the 63/64ths rule.
3. Run the binary search algorithm until the minimum successful gas value and the maximum failure gas value are within 10%.

This approach allows for minimal `eth_call` requests while providing an accurate gas limit.

### `callGasLimit` Estimation

`callGasLimit` estimation is similar to `verificationGasLimit` estimation in that it also uses a binary search. The majority of the binary search, however, is performed in Solidity to limit network calls.

This scheme requires the use of a spoofed entry point contract via `eth_call` state overrides. The original entry point contract is moved and a proxy is loaded in its place. This allows us to write additional logic to support gas estimation into the entry point contract.

More information on gas estimation can be found [here](https://www.alchemy.com/blog/erc-4337-gas-estimation).

## Fee Estimation

Fee estimation is done by applying the configured [priority fee mode](./builder.md#required-fees) to the estimated network fees.
