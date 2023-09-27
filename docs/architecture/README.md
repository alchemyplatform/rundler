# Rundler Architecture

Rundler consists of 3 main "tasks" that work in tandem to implement the ERC-4337 bundler specification.

- [**RPC**](./rpc.md): The `RPC` task implements the defined [ERC-4337 RPC methods](https://eips.ethereum.org/EIPS/eip-4337#rpc-methods-eth-namespace) under both the `eth_` and `debug_` namespaces. It also implements Rundler specific methods under the `rundler_` namespace and a health check endpoint.

- [**Pool**](./pool.md): The `Pool` task implements a User Operation (UO) mempool. The mempool validates and simulates User Operations per the rules in the spec. It maintains the UOs in memory until they are mined onchain. The pool handles chain reorgs up to a defined depth using a cache of mined UOs.

- [**Builder**](./builder.md): The `Builder` task is responsible for constructing bundles of User Operations, submitting them as transactions, and monitoring the status of those transactions.

## Task Communication

The tasks communicate with each other via message passing mechanisms. The `Pool` and `Builder` each run a "server" component responsible for receiving, acting upon, and responding to messages.

**RPC -> Pool**: The `RPC` module submits UOs to the `Pool` during the `eth_sendUserOperation` RPC method. Future RPC method implementations may use this communication path to retrieve UO status.

**RPC -> Builder**: This communication path is only used when the `debug_` namespace is enabled. It is used to set the builder's bundling mode (to `manual` in tests) and trigger bundle submission (in `manual` mode).

**Builder <-> Pool**: The `Builder` and the `Pool` coordinate to create bundles that contain valid, unmined, and profitable user operations. The `Builder` subscribes to a stream up of updates from the `Pool` and is notified after each new block is processed. The builder then queries the `Pool` for its most valuable UOs, re-simulates them and builds bundles. Any operations that fail 2nd simulation are communicated back to the `Pool` for removal.

## Communication Modes

Both the `Builder` and the `Pool` tasks can be configured to run a gRPC server capable of receiving and responding to messages from the network. Thus, Rundler can be configured to run in a distributed mode where its tasks run in separate processes.

The `Builder` and `RPC` modules can be configured to communicate to other tasks via in-memory message passing (if running in the same process) or via gRPC (if running in separate processes).
