# Rundler CLI

The Rundler Command Line Interface (CLI) offers a wide array of options and subcommands. Most options contain reasonable defaults that can be overridden.

## Subcommands

- `node`: Runs the Pool, Builder, and RPC servers in a single process.
- `rpc`: Runs the Rpc server.
- `pool`: Runs the Pool server.
- `builder`: Runs the Builder server.

The `pool` and `builder` commands will also start a gRPC endpoint to allow other processes to interact with each service.

## Common Options

These options are common to all subcommands and can be used globally:

### Chain Specification

See [chain spec](./architecture/chain_spec.md) for a detailed description of chain spec derivation from these options.

- `--network`: Network to look up a hardcoded chain spec. (default: None)
  - env: *NETWORK*
- `--chain_spec`: Path to a chain spec TOML file.
  - env: *CHAIN_SPEC*
- (env only): Chain specification overrides.
  - env: *CHAIN_**

### Rundler Common

- `--node_http`: EVM Node HTTP URL to use. (**REQUIRED**)
  - env: *NODE_HTTP*
- `--max_verification_gas`: Maximum verification gas. (default: `5000000`).
  - env: *MAX_VERIFICATION_GAS*
- `--max_bundle_gas`: Maximum bundle gas. (default: `25000000`).
  - env: *MAX_BUNDLE_GAS*
- `--min_stake_value`: Minimum stake value. (default: `1000000000000000000`).
  - env: *MIN_STAKE_VALUE*
- `--min_unstake_delay`: Minimum unstake delay. (default: `84600`).
  - env: *MIN_UNSTAKE_DELAY*
- `--user_operation_event_block_distance`: Number of blocks to search when calling `eth_getUserOperationByHash`. (default: all blocks)
  - env: *USER_OPERATION_EVENT_BLOCK_DISTANCE*
- `--max_simulate_handle_ops_gas`: Maximum gas for simulating handle operations. (default: `20000000`).
  - env: *MAX_SIMULATE_HANDLE_OPS_GAS*
- `--verification_estimation_gas_fee`: The gas fee to use during verification estimation. (default: `1000000000000` 10K gwei).
  - env: *VERIFICATION_ESTIMATION_GAS_FEE*
  - See [RPC documentation](./architecture/rpc.md#verificationGasLimit-estimation) for details.
- `--bundle_priority_fee_overhead_percent`: bundle transaction priority fee overhead over network value. (default: `0`).
  - env: *BUNDLE_PRIORITY_FEE_OVERHEAD_PERCENT*
- `--priority_fee_mode_kind`: Priority fee mode kind. Possible values are `base_fee_percent` and `priority_fee_increase_percent`. (default: `priority_fee_increase_percent`).
  - options: ["base_fee_percent", "priority_fee_increase_percent"]
  - env: *PRIORITY_FEE_MODE_KIND*
- `--priority_fee_mode_value`: Priority fee mode value. (default: `0`).
  - env: *PRIORITY_FEE_MODE_VALUE*
- `--base_fee_accept_percent`: Percentage of the current network fees a user operation must have in order to be accepted into the mempool. (default: `100`).
  - env: *BASE_FEE_ACCEPT_PERCENT*
- `--aws_region`: AWS region. (default: `us-east-1`).
  - env: *AWS_REGION*
  - (*Only required if using other AWS features*)
- `--unsafe`: Flag for unsafe bundling mode. When set Rundler will skip checking simulation rules (and any `debug_traceCall`). (default: `false`).
  - env: *UNSAFE*
- `--mempool_config_path`: Path to the mempool configuration file. (example: `mempool-config.json`, `s3://my-bucket/mempool-config.json`)
  - This path can either be a local file path or an S3 url. If using an S3 url, Make sure your machine has access to this file. 
  - env: *MEMPOOL_CONFIG_PATH*
  - See [here](./architecture/pool.md#alternative-mempools-in-preview) for details.
- `--disable_entry_point_v0_6`: Disable entry point v0.6 support. (default: `false`).
  - env: *DISABLE_ENTRY_POINT_V0_6*
- `--num_builders_v0_6`: The number of bundle builders to run on entry point v0.6 (default: `1`)
  - env: *NUM_BUILDERS_V0_6*
- `--disable_entry_point_v0_7`: Disable entry point v0.7 support. (default: `false`).
  - env: *DISABLE_ENTRY_POINT_V0_7*
- `--num_builders_v0_7`: The number of bundle builders to run on entry point v0.7 (default: `1`)
  - env: *NUM_BUILDERS_V0_7*
- `--tracer_timeout`: The timeout used for custom javascript tracers, the string must be in a valid parseable format that can be used in the `ParseDuration` function on an ethereum node. See Docs [Here](https://pkg.go.dev/time#ParseDuration). (default: `15s`)
  - env: *TRACER_TIMEOUT*

## Metrics Options

Options for the metrics server:

- `--metrics.port`: Port to listen on for metrics requests. default: `8080`.
  - env: *METRICS_PORT*
- `--metrics.host`: Host to listen on for metrics requests. default: `0.0.0.0`.
  - env: *METRICS_HOST*
- `--metrics.tags`: Tags for metrics in the format `key1=value1,key2=value2,...`.
  - env: *METRICS_TAGS*
- `--metrics.sample_interval_millis`: Sample interval to use for sampling metrics. default: `1000`.
  - env: *METRICS_SAMPLE_INTERVAL_MILLIS*

## Logging Options

Options for logging:

- `RUST_LOG` environment variable is used for controlling log level see: [env_logger](https://docs.rs/env_logger/0.10.1/env_logger/#enabling-logging).
Only `level` is supported.
- `--log.file`: Log file. If not provided, logs will be written to stdout.
  - env: *LOG_FILE*
- `--log.json`: If set, logs will be written in JSON format.
  - env: *LOG_JSON*

## RPC Options

List of command line options for configuring the RPC API.

- `--rpc.port`:	Port to listen on for JSON-RPC requests (default: `3000`)
  - env: *RPC_PORT*
- `--rpc.host`:	Host to listen on for JSON-RPC requests (default: `0.0.0.0`)
  - env: *RPC_HOST*
- `--rpc.api`:	Which APIs to expose over the RPC interface (default: `eth,rundler`)
  - env: *RPC_API*
- `--rpc.timeout_seconds`:	Timeout for RPC requests (default: `20`)
  - env: *RPC_TIMEOUT_SECONDS*
- `--rpc.max_connections`:	Maximum number of concurrent connections (default: `100`)
  - env: *RPC_MAX_CONNECTIONS*
- `--rpc.pool_url`:	Pool URL for RPC (default: `http://localhost:50051`)
  - env: *RPC_POOL_URL*
  - *Only required when running in distributed mode* 
- `--rpc.builder_url`:	Builder URL for RPC (default: `http://localhost:50052`)
  - env: *RPC_BUILDER_URL*
  - *Only required when running in distributed mode* 

## Pool Options

List of command line options for configuring the Pool.

- `--pool.port`: Port to listen on for gRPC requests (default: `50051`)
  - env: *POOL_PORT*
  - *Only required when running in distributed mode* 
- `--pool.host`: Host to listen on for gRPC requests (default: `127.0.0.1`)
  - env: *POOL_HOST*
  - *Only required when running in distributed mode* 
- `--pool.max_size_in_bytes`: Maximum size in bytes for the pool (default: `500000000`, `0.5 GB`)
  - env: *POOL_MAX_SIZE_IN_BYTES*
- `--pool.same_sender_mempool_count`: Maximum number of user operations for an unstaked sender (default: `4`)
  - env: *POOL_SAME_SENDER_MEMPOOL_COUNT*
- `--pool.min_replacement_fee_increase_percentage`: Minimum replacement fee increase percentage (default: `10`)
  - env: *POOL_MIN_REPLACEMENT_FEE_INCREASE_PERCENTAGE*
- `--pool.blocklist_path`: Path to a blocklist file (e.g `blocklist.json`, `s3://my-bucket/blocklist.json`)
  - env: *POOL_BLOCKLIST_PATH*
  - This path can either be a local file path or an S3 url. If using an S3 url, Make sure your machine has access to this file. 
  - See [here](./architecture/pool.md#allowlistblocklist) for details.
- `--pool.allowlist_path`: Path to an allowlist file (e.g `allowlist.json`, `s3://my-bucket/allowlist.json`)
  - env: *POOL_ALLOWLIST_PATH*
  - This path can either be a local file path or an S3 url. If using an S3 url, Make sure your machine has access to this file. 
  - See [here](./architecture/pool.md#allowlistblocklist) for details.
- `--pool.chain_poll_interval_millis`: Interval at which the pool polls an Eth node for new blocks (default: `100`)
  - env: *POOL_CHAIN_POLL_INTERVAL_MILLIS*
- `--pool.chain_sync_max_retries`: The amount of times to retry syncing the chain before giving up and waiting for the next block (default: `5`)
  - env: *POOL_CHAIN_SYNC_MAX_RETRIES*
- `--pool.chain_history_size`: Size of the chain history
  - env: *POOL_CHAIN_HISTORY_SIZE*
- `--pool.paymaster_tracking_enabled`: Boolean field that sets whether the pool server starts with paymaster tracking enabled (default: `true`)
  - env: *POOL_PAYMASTER_TRACKING_ENABLED*
- `--pool.paymaster_cache_length`: Length of the paymaster cache (default: `10_000`)
  - env: *POOL_PAYMASTER_CACHE_LENGTH*
- `--pool.reputation_tracking_enabled`: Boolean field that sets whether the pool server starts with reputation tracking enabled (default: `true`)
  - env: *POOL_REPUTATION_TRACKING_ENABLED*
- `--pool.drop_min_num_blocks`: The minimum number of blocks that a UO must stay in the mempool before it can be requested to be dropped by the user (default: `10`)
  - env: *POOL_DROP_MIN_NUM_BLOCKS*

## Builder Options

List of command line options for configuring the Builder.

- `--builder.port`: Port to listen on for gRPC requests (default: `50052`)
  - env: *BUILDER_PORT*
  - *Only required when running in distributed mode* 
- `--builder.host`: Host to listen on for gRPC requests (default: `127.0.0.1`)
  - env: *BUILDER_HOST*
  - *Only required when running in distributed mode* 
- `--builder.private_key`: Private key to use for signing transactions
  - env: *BUILDER_PRIVATE_KEY*
  - **DEPRECATED**: Use `--builder.private_keys` instead. If both used this is added to the list.
- `--builder.private_keys`: Private keys to use for signing transactions, separated by `,`
  - env: *BUILDER_PRIVATE_KEYS*
- `--builder.aws_kms_key_ids`: AWS KMS key IDs to use for signing transactions (comma-separated)
  - env: *BUILDER_AWS_KMS_KEY_IDS*
  - *Only required if BUILDER_PRIVATE_KEY is not provided* 
  - *Cannot use `builder.private_keys` and `builder.aws_kms_key_ids` at the same time*
- `--builder.redis_uri`: Redis URI to use for KMS leasing (default: `""`)
  - env: *BUILDER_REDIS_URI*
  - *Only required when AWS_KMS_KEY_IDS are provided* 
- `--builder.redis_lock_ttl_millis`: Redis lock TTL in milliseconds (default: `60000`)
  - env: *BUILDER_REDIS_LOCK_TTL_MILLIS*
  - *Only required when AWS_KMS_KEY_IDS are provided* 
- `--builder.max_bundle_size`: Maximum number of ops to include in one bundle (default: `128`)
  - env: *BUILDER_MAX_BUNDLE_SIZE*
- `--builder.max_blocks_to_wait_for_mine`: After submitting a bundle transaction, the maximum number of blocks to wait for that transaction to mine before trying to resend with higher gas fees (default: `2`)
  - env: *BUILDER_MAX_BLOCKS_TO_WAIT_FOR_MINE*
- `--builder.replacement_fee_percent_increase`: Percentage amount to increase gas fees when retrying a transaction after it failed to mine (default: `10`)
  - env: *BUILDER_REPLACEMENT_FEE_PERCENT_INCREASE*
- `--builder.max_cancellation_fee_increases`: Maximum number of cancellation fee increases to attempt (default: `15`)
  - env: *BUILDER_MAX_CANCELLATION_FEE_INCREASES*
- `--builder.max_replacement_underpriced_blocks`: The maximum number of blocks to wait in a replacement underpriced state before issuing a cancellation transaction (default: `20`)
  - env: *BUILDER_MAX_REPLACEMENT_UNDERPRICED_BLOCKS*
- `--builder.sender`: Choice of what sender type to use for transaction submission. (default: `raw`, options: `raw`, `flashbots`, `polygon_bloxroute`)
  - env: *BUILDER_SENDER*
- `--builder.submit_url`: Only used if builder.sender == "raw." If present, the URL of the ETH provider that will be used to send transactions. Defaults to the value of `node_http`.
  - env: *BUILDER_SUBMIT_URL*
- `--builder.use_submit_for_status`: Only used if builder.sender == "raw." Use the submit url to get the status of the bundle transaction. (default: `false`)
  - env: *BUILDER_USE_SUBMIT_FOR_STATUS*
- `--builder.use_conditional_rpc`: Only used if builder.sender == "raw." Use `eth_sendRawTransactionConditional` when submitting. (default: `false`)
  - env: *BUILDER_USE_CONDITIONAL_RPC*
- `--builder.dropped_status_unsupported`: Only used if builder.sender == "raw." If set, the builder will not process a dropped status. Use this if the URL that is being used for status (node_http or submit_url) does not support pending transactions, only those that are mined.  (default: `false`)
  - env: *BUILDER_DROPPED_STATUS_UNSUPPORTED*
- `--builder.flashbots_relay_builders`: Only used if builder.sender == "flashbots." Additional builders to send bundles to through the Flashbots relay RPC (comma-separated). List of builders that the Flashbots RPC supports can be found [here](https://docs.flashbots.net/flashbots-auction/advanced/rpc-endpoint#eth_sendprivatetransaction). (default: `flashbots`)
  - env: *BUILDER_FLASHBOTS_RELAY_BUILDERS*
- `--builder.flashbots_relay_auth_key`: Only used/required if builder.sender == "flashbots." Authorization key to use with the flashbots relay. See [here](https://docs.flashbots.net/flashbots-auction/advanced/rpc-endpoint#authentication) for more info. (default: None)
  - env: *BUILDER_FLASHBOTS_RELAY_AUTH_KEY*
- `--builder.bloxroute_auth_header`: Only used/required if builder.sender == "polygon_bloxroute." If using the bloxroute transaction sender on Polygon, this is the auth header to supply with the requests. (default: None)
  - env: `BUILDER_BLOXROUTE_AUTH_HEADER`
- `--builder.index_offset`: If running multiple builder processes, this is the index offset to assign unique indexes to each bundle sender. (default: 0)
  - env: `BUILDER_INDEX_OFFSET`
- `--builder.pool_url`: If running in distributed mode, the URL of the pool server to use.
  - env: `BUILDER_POOL_URL`
  - *Only required when running in distributed mode*

### Key management

Private keys for the bundler can be provided in a few ways. You can set the `--builder.private_key` flag or the `BUILDER_PRIVATE_KEY` environment variable
within your local or deployed environment. Alternatively, you can provide the application with one or more AWS KMS ids using the `--builder.aws_kms_key_ids` flag or `AWS_KMS_KEY_IDS` environment
variable. Rundler will download the key/s so long as you have `kms:DescribeKey` & `kms:Decrypt` IAM access to the KMS resource.

When using KMS keys, a Redis URL must be provided to Rundler which will take care of key leasing to make sure keys are not accessed at the same time from concurrent processes.

## Example Usage

Here are some example commands to use the CLI:

```sh
# Run the Node subcommand with custom options
$ ./rundler node --network dev --disable_entry_point_v0_6 --node_http http://localhost:8545 --builder.private_keys 0x0000000000000000000000000000000000000000000000000000000000000001

# Run the RPC subcommand with custom options and enable JSON logging. The builder (localhost:50052) and pool (localhost:50051) will need to be running before this starts.
$ ./rundler rpc --network dev --node_http http://localhost:8545 --log.json --disable_entry_point_v0_6

# Run the Pool subcommand with custom options and specify a mempool config file
$ ./target/debug/rundler pool --network dev --max_simulate_handle_ops_gas 15000000 --mempool_config_path mempool.json --node_http http://localhost:8545 --disable_entry_point_v0_6
```
