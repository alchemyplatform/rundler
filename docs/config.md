# RUNDLER CLI

The Rundler Command Line Interface (CLI) offers a versatile and configurable User Operation Bundler, equipped with a wide array of options and subcommands tailored to your needs.

## Subcommands

- `node`: Runs the Pool, Builder, and RPC servers in a single process.
- `rpc`: Runs the Rpc server.
- `pool`: Runs the Pool server.
- `builder`: Runs the Builder server.

The `pool` and `builder` servers will also start a gRPC endpoint to allow other processes to interact with each service

## General Options

These options are common to all subcommands and can be used globally:

- `--entry_points`: Entry point addresses to target. Provide a comma-separated list. (multiple entry points is currently in beta, we have only tested 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789)
  - env: *ENTRY_POINTS*
- `--chain_id`: Chain ID to target. (default: `1337`).
  - env: *CHAIN_ID*
- `--node_http`: ETH Node HTTP URL to connect to. (REQUIRED)
  - env: *NODE_HTTP*
- `--max_verification_gas`: Maximum verification gas. (default: `5000000`).
  - env: *MAX_VERIFICATION_GAS*
- `--max_bundle_gas`: Maximum bundle gas. (default: `25000000`).
  - env: *MAX_BUNDLE_GAS*
- `--min_stake_value`: Minimum stake value. (default: `1000000000000000000`).
  - env: *MIN_STAKE_VALUE*
- `--min_unstake_delay`: Minimum unstake delay. (default: `84600`).
  - env: *MIN_UNSTAKE_DELAY*
- `--user_operation_event_block_distance`: Number of blocks to search when calling `eth_getUserOperationByHash`. (default: genisis to latest)
  - env: *USER_OPERATION_EVENT_BLOCK_DISTANCE*
- `--max_simulate_handle_ops_gas`: Maximum gas for simulating handle operations. (default: `20000000`).
  - env: *MAX_SIMULATE_HANDLE_OPS_GAS*
- `--use_bundle_priority_fee`: Enable bundle priority fee. (default: `true` on known networks that support EIP-1559, else `false`.)
  - env: *USE_BUNDLE_PRIORITY_FEE*
- `--bundle_priority_fee_overhead_percent`: bundle transaction priority fee overhead over network value. (default: `0`).
  - env: *BUNDLE_PRIORITY_FEE_OVERHEAD_PERCENT*
- `--priority_fee_mode_kind`: Priority fee mode kind. Possible values are `base_fee_percent` and `priority_fee_increase_percent`. (default: `priority_fee_increase_percent`).
  - options: ["base_fee_percent", "priority_fee_increase_percent"]
  - env: *PRIORITY_FEE_MODE_KIND*
  - These options have slightly different outcomes. When a transaction is not landed on chain, we need to increase the fee's to five the operation a higher
    chance of landing. The `base_fee_percent ` field will increase the the base fee (`max_fee_per_gas - max_priority_fee_per_gas`) by the `priority_fee_mode_value` percentage.
    The `priority_fee_increase_percent` field will increase the `max_priority_fee_per_gas` by the `priority_fee_mode_value` percentage.
- `--priority_fee_mode_value`: Priority fee mode value. (default: `0`).
  - env: *PRIORITY_FEE_MODE_VALUE*
- `--aws_region`: AWS region. (default: `us-east-1`).
  - env: *AWS_REGION*
- `--eth_poll_interval_millis`: Interval at which the builder polls an Eth node for new blocks and mined transactions (default: `100`)
  - env: *ETH_POLL_INTERVAL_MILLIS*
- `--mempool_config_path`: Path to the mempool configuration file. (example: `mempool-config.json`, `s3://my-bucket/mempool-config.json`)
  - This path can either be a local file path or an S3 url. If using an S3 url, Make sure your machine has access to this file. 
  - env: *MEMPOOL_CONFIG_PATH*
  - [config example](alt-mempools.md)

## Metrics Options

Options for the metrics server:

- `--metrics.port`: Port to listen on for metrics requests. default: `8080`.
  - env: *METRICS_PORT*
- `--metrics.host`: Host to listen on for metrics requests. default: `0.0.0.0`.
  - env: *METRICS_HOST*
- `--metrics.tags`: Tags for metrics in the format `key1=value1,key2=value2,...`.
  - env: *METRICS_TAGS*

## Logging Options

Options for logging:

- `--log.file`: Log file. If not provided, logs will be written to stdout.
  - env: *LOG_FILE*
- `--log.json`: If set, logs will be written in JSON format.
  - env: *LOG_JSON*

## RPC Options

List of command line options for configuring the RPC API.

- `--rpc.port`:	Port to listen on for JSON-RPC requests (default: `3000`)
  - env: *RPC_PORT*
  - *Only required when running in distributed mode* 
- `--rpc.host`:	Host to listen on for JSON-RPC requests (default: `0.0.0.0`)
  - env: *RPC_HOST*
  - *Only required when running in distributed mode* 
- `--rpc.api`:	Which APIs to expose over the RPC interface (default: `eth,rundler`)
  - env: *RPC_API*
- `--rpc.timeout_seconds`:	Timeout for RPC requests (default: 20)
  - env: *RPC_TIMEOUT_SECONDS*
- `--rpc.max_connections`:	Maximum number of concurrent connections (default: `100`)
  - env: *RPC_MAX_CONNECTIONS*
- `--rpc.pool_url`:	Pool URL for RPC (default: `http://localhost:50051`)
  - env: *RPC_POOL_URL*
- `--rpc.builder_url`:	Builder URL for RPC (default: `http://localhost:50052`)
  - env: *RPC_BUILDER_URL*

## OP Pool Options

List of command line options for configuring the OP Pool.

- `--pool.port`: Port to listen on for gRPC requests (default: `50051`)
  - env: *POOL_PORT*
  - *Only required when running in distributed mode* 
- `--pool.host`: Host to listen on for gRPC requests (default: `127.0.0.1`)
  - env: *POOL_HOST*
  - *Only required when running in distributed mode* 
- `--pool.max_size_in_bytes`: Maximum size in bytes for the pool (default: `500000000`, 0.5 GB)
  - env: *POOL_MAX_SIZE_IN_BYTES*
- `--pool.max_userops_per_sender`: Maximum number of user operations per sender (default: `4`)
  - env: *POOL_MAX_USEROPS_PER_SENDER*
- `--pool.min_replacement_fee_increase_percentage`: Minimum replacement fee increase percentage (default: `10`)
  - env: *POOL_MIN_REPLACEMENT_FEE_INCREASE_PERCENTAGE*
- `--pool.blocklist_path`: Path to a blocklist file (e.g `blocklist.json`, `s3://my-bucket/blocklist.json`)
  - env: *POOL_BLOCKLIST_PATH*
  - This path can either be a local file path or an S3 url. If using an S3 url, Make sure your machine has access to this file. 
- `--pool.allowlist_path`: Path to an allowlist file (e.g `allowlist.json`, `s3://my-bucket/allowlist.json`)
  - env: *POOL_ALLOWLIST_PATH*
  - This path can either be a local file path or an S3 url. If using an S3 url, Make sure your machine has access to this file. 
- `--pool.chain_history_size`: Size of the chain history
  - env: *POOL_CHAIN_HISTORY_SIZE*

## Builder CLI Options

List of command line options for configuring the Builder.

- `--builder.port`: Port to listen on for gRPC requests (default: `50052`)
  - env: *BUILDER_PORT*
  - *Only required when running in distributed mode* 
- `--builder.host`: Host to listen on for gRPC requests (default: `127.0.0.1`)
  - env: *BUILDER_HOST*
  - *Only required when running in distributed mode* 
- `--builder.private_key`: Private key to use for signing transactions
  - env: *BUILDER_PRIVATE_KEY*
  - *Only required if BUILDER_AWS_KMS_KEY_IDS is not provided* 
- `--builder.aws_kms_key_ids`: AWS KMS key IDs to use for signing transactions (comma-separated)
  - env: *BUILDER_AWS_KMS_KEY_IDS*
  - *Only required if BUILDER_PRIVATE_KEY is not provided* 
- `--builder.redis_uri`: Redis URI to use for KMS leasing (default: `""`)
  - env: *BUILDER_REDIS_URI*
  - *Only required when AWS_KMS_KEY_IDS are provided* 
- `--builder.redis_lock_ttl_millis`: Redis lock TTL in milliseconds (default: `60000`)
  - env: *BUILDER_REDIS_LOCK_TTL_MILLIS*
  - *Only required when AWS_KMS_KEY_IDS are provided* 
- `--builder.max_bundle_size`: Maximum number of ops to include in one bundle (default: `128`)
  - env: *BUILDER_MAX_BUNDLE_SIZE*
- `--builder.submit_url`: If present, the URL of the ETH provider that will be used to send transactions. Defaults to the value of `node_http`.
  - env: *BUILDER_SUBMIT_URL*
- `--builder.use_conditional_send_transaction`: If true, will use the provider's `eth_sendRawTransactionConditional` method instead of `eth_sendRawTransaction`, passing in expected storage values determined through simulation. Must not be set on networks which do not support this method (default: `false`)
  - env: *BUILDER_USE_CONDITIONAL_SEND_TRANSACTION*
- `--builder.max_blocks_to_wait_for_mine`: After submitting a bundle transaction, the maximum number of blocks to wait for that transaction to mine before trying to resend with higher gas fees (default: `2`)
  - env: *BUILDER_MAX_BLOCKS_TO_WAIT_FOR_MINE*
- `--builder.replacement_fee_percent_increase`: Percentage amount to increase gas fees when retrying a transaction after it failed to mine (default: `10`)
  - env: *BUILDER_REPLACEMENT_FEE_PERCENT_INCREASE*
- `--builder.max_fee_increases`: Maximum number of fee increases to attempt (Seven increases of 10% is roughly 2x the initial fees) (default: `7`)
  - env: *BUILDER_MAX_FEE_INCREASES*

## Key management

Private keys for the bundler can be provided in a few ways. You can set the `--builder.private_key` flag or the `BUILDER_PRIVATE_KEY` environment variable
within your local or deployed environment. Alternateley, you can provide the application with one or more AWS KMS ids using the `--builder.aws_kms_key_ids` flag or `AWS_KMS_KEY_IDS` environment
variable. Rundler will download the key/s so long as you have `kms:DescribeKey` & `kms:Decrypt` IAM access to the KMS resource.

When using KMS keys, a redis url must be provided to the bundler which will take care of key locking to make sure keys are not accessed at the same time from concurrent processes

## Example configuration files

### Pool allowlist path

```
export POOL_ALLOWLIST_PATH=blocklist.json
```

```
[
  "0x0000000000000000000000000000000000000000000000000000000000000000"
]
```
### Pool blocklist path

```
export POOL_BLOCKLIST_PATH=blocklist.json
```

```
[
  "0x0000000000000000000000000000000000000000000000000000000000000000"
]
```

## Example Usage

Here are some example commands to use the CLI:

```sh
# Run the Node subcommand with custom options
$ ./app --entry_points 0x0000000000000000000000000000000000000000 --chain_id 1337 --max_verification_gas 10000000 node

# Run the Rpc subcommand with custom options and enable JSON logging. The builder and pool will need to be running before this starts.
$ ./app --node_http http://localhost:8545 --log.json rpc

# Run the Pool subcommand with custom options and specify a mempool config file
$ ./app --max_simulate_handle_ops_gas=15000000  --mempool_config_path=mempool.json --node_http http://localhost:8545 --chain_id=8453 pool