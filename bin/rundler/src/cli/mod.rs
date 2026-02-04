// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use std::{sync::Arc, time::Duration};

use admin::AdminCliArgs;
use aggregator::AggregatorType;
use alloy_primitives::U256;
use anyhow::{Context, bail};
use clap::{
    Args, Parser, Subcommand,
    builder::{PossibleValuesParser, ValueParser},
};
use strum::EnumCount;
use url::Url;

mod admin;
mod aggregator;
mod backend;
mod builder;
mod chain_spec;
mod json;
mod metrics;
mod node;
mod pool;
mod proxy;
mod rpc;
mod signer;
mod tracing;

use backend::BackendCliArgs;
use builder::{BuilderCliArgs, EntryPointBuilderConfigs};
use json::get_json_config;
use node::NodeCliArgs;
use pool::PoolCliArgs;
use reth_tasks::TaskManager;
use rpc::RpcCliArgs;
use rundler_provider::{
    AlloyEntryPointV0_6, AlloyEntryPointV0_7, AlloyEvmProvider, AlloyNetworkConfig, DAGasOracle,
    DAGasOracleSync, EntryPointProvider, EvmProvider, FeeEstimator, Providers,
};
use rundler_sim::{
    EstimationSettings, MIN_CALL_GAS_LIMIT, MempoolConfigs, PrecheckSettings, SimulationSettings,
};
use rundler_types::{
    EntryPointAbiVersion, EntryPointVersion, PriorityFeeMode,
    chain::{ChainSpec, TryFromWithSpec},
    da::DAGasOracleType,
    v0_6::UserOperation as UserOperationV0_6,
    v0_7::UserOperation as UserOperationV0_7,
};
use secrecy::SecretString;

/// Main entry point for the CLI
///
/// Parses the CLI arguments and runs the appropriate subcommand.
/// Listens for a ctrl-c signal and shuts down all components when received.
pub async fn run() -> anyhow::Result<()> {
    let opt = Cli::parse();
    let _guard = tracing::configure_logging(&opt.common.network, &opt.logs)?;
    tracing::info!("Parsed CLI options: {:#?}", opt);

    let mut task_manager = TaskManager::current();
    let task_spawner = task_manager.executor();

    let metrics_addr = format!("{}:{}", opt.metrics.host, opt.metrics.port).parse()?;
    metrics::initialize(
        &task_spawner,
        opt.metrics.sample_interval_millis,
        metrics_addr,
        &opt.metrics.tags,
        &opt.metrics.buckets,
    )
    .context("metrics server should start")?;

    let mut cs = chain_spec::resolve_chain_spec(&opt.common.network, &opt.common.chain_spec);

    let (mempool_configs, entry_point_builders) = load_configs(&opt.common).await?;
    if let Some(entry_point_builders) = &entry_point_builders {
        entry_point_builders.set_proxies(&mut cs);
    }

    let providers = construct_providers(&opt.common, &cs)?;
    aggregator::instantiate_aggregators(&opt.common, &mut cs, &providers);

    tracing::info!("Chain spec: {:#?}", cs);

    match opt.command {
        Command::Node(args) => {
            node::spawn_tasks(
                task_spawner.clone(),
                cs,
                *args,
                opt.common,
                providers,
                mempool_configs,
                entry_point_builders,
            )
            .await?
        }
        Command::Pool(args) => {
            pool::spawn_tasks(
                task_spawner.clone(),
                cs,
                args,
                opt.common,
                providers,
                mempool_configs,
            )
            .await?
        }
        Command::Rpc(args) => {
            rpc::spawn_tasks(task_spawner.clone(), cs, args, opt.common, providers).await?
        }
        Command::Builder(args) => {
            builder::spawn_tasks(task_spawner.clone(), cs, args, opt.common, providers).await?
        }
        Command::Admin(args) => {
            admin::run(args, cs, providers, task_spawner).await?;
            // admin CLI should not wait for ctrl-c
            return Ok(());
        }
        Command::Backend(args) => {
            backend::spawn_tasks(
                task_spawner.clone(),
                cs,
                args,
                opt.common,
                providers,
                mempool_configs,
                entry_point_builders,
            )
            .await?
        }
    }

    // wait for ctrl-c or the task manager to panic
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received ctrl-c, shutting down");
        },
        e = &mut task_manager => {
            tracing::error!("Task manager panicked, shutting down: {e:?}");
        },
    }

    // wait for the task manager to shutdown
    task_manager.graceful_shutdown_with_timeout(Duration::from_secs(10));

    tracing::info!("Shutdown, goodbye");
    Ok(())
}

/// CLI commands
#[derive(Debug, Subcommand)]
enum Command {
    /// Bundler command
    ///
    /// Runs the Pool, Builder, and RPC servers in a single process.
    #[command(name = "node")]
    Node(Box<NodeCliArgs>),

    /// Rpc command
    ///
    /// Runs the Rpc server
    #[command(name = "rpc")]
    Rpc(RpcCliArgs),

    /// Pool command
    ///
    /// Runs the Pool server
    #[command(name = "pool")]
    Pool(PoolCliArgs),

    /// Builder command
    ///
    /// Runs the Builder server
    #[command(name = "builder")]
    Builder(BuilderCliArgs),

    /// Admin command
    ///
    /// Runs the admin commands
    #[command(name = "admin")]
    Admin(AdminCliArgs),

    /// Backend command
    ///
    /// Runs both Pool and Builder in a single process with gRPC endpoints exposed.
    /// Useful for running a single-chain backend that a gateway can connect to.
    #[command(name = "backend")]
    Backend(BackendCliArgs),
}

/// CLI common options
#[derive(Debug, Args)]
#[command(next_help_heading = "Common")]
pub struct CommonArgs {
    /// Network flag
    #[arg(
        long = "network",
        name = "network",
        env = "NETWORK",
        value_parser = PossibleValuesParser::new(chain_spec::HARDCODED_CHAIN_SPECS),
        global = true)
    ]
    network: Option<String>,

    /// Chain spec file path
    #[arg(
        long = "chain_spec",
        name = "chain_spec",
        env = "CHAIN_SPEC",
        global = true
    )]
    chain_spec: Option<String>,

    /// ETH Node HTTP URL to connect to
    #[arg(
        long = "node_http",
        name = "node_http",
        env = "NODE_HTTP",
        global = true
    )]
    node_http: Option<String>,

    /// Flag for turning unsafe bundling mode on
    #[arg(long = "unsafe", env = "UNSAFE", global = true)]
    unsafe_mode: bool,

    #[arg(
        long = "max_verification_gas",
        name = "max_verification_gas",
        default_value = "5000000",
        env = "MAX_VERIFICATION_GAS",
        global = true
    )]
    max_verification_gas: u64,

    #[arg(
        long = "max_uo_cost",
        name = "max_uo_cost",
        env = "MAX_UO_COST",
        value_parser = alloy_primitives::utils::parse_ether,
        global = true
    )]
    max_uo_cost: Option<U256>,

    #[arg(
        long = "target_bundle_transaction_gas_limit_ratio",
        name = "target_bundle_transaction_gas_limit_ratio",
        default_value = "0.5",
        env = "TARGET_BUNDLE_TRANSACTION_GAS_LIMIT_RATIO",
        value_parser = verify_f64_less_than_one,
        global = true
    )]
    target_bundle_transaction_gas_limit_ratio: f64,

    #[arg(
        long = "max_bundle_transaction_gas_limit_ratio",
        name = "max_bundle_transaction_gas_limit_ratio",
        default_value = "0.9",
        env = "MAX_BUNDLE_TRANSACTION_GAS_LIMIT_RATIO",
        value_parser = verify_f64_less_than_one,
        global = true
    )]
    max_bundle_transaction_gas_limit_ratio: f64,

    #[arg(
        long = "min_stake_value",
        name = "min_stake_value",
        env = "MIN_STAKE_VALUE",
        default_value = "1000000000000000000",
        global = true
    )]
    min_stake_value: u128,

    #[arg(
        long = "min_unstake_delay",
        name = "min_unstake_delay",
        env = "MIN_UNSTAKE_DELAY",
        default_value = "86400",
        global = true
    )]
    min_unstake_delay: u32,

    /// String representation of the timeout of a custom tracer in a format that is parsable by the
    /// `ParseDuration` function on the ethereum node. See Docs: https://pkg.go.dev/time#ParseDuration
    #[arg(
        long = "tracer_timeout",
        name = "tracer_timeout",
        env = "TRACER_TIMEOUT",
        default_value = "10s",
        global = true
    )]
    tracer_timeout: String,

    /// If set, allows the simulator to fallback to unsafe mode if the simulation tracer fails
    #[arg(
        long = "enable_unsafe_fallback",
        name = "enable_unsafe_fallback",
        env = "ENABLE_UNSAFE_FALLBACK"
    )]
    enable_unsafe_fallback: bool,

    /// Amount of blocks to search when calling eth_getUserOperationByHash.
    /// Defaults from 0 to latest block
    #[arg(
        long = "user_operation_event_block_distance",
        name = "user_operation_event_block_distance",
        env = "USER_OPERATION_EVENT_BLOCK_DISTANCE",
        global = true
    )]
    user_operation_event_block_distance: Option<u64>,

    /// Amount of blocks to search when calling eth_getUserOperationByHash during a fallback.
    ///
    /// Defaults to unset. If set, will be used in the case that a first query for events fails.
    #[arg(
        long = "user_operation_event_block_distance_fallback",
        name = "user_operation_event_block_distance_fallback",
        env = "USER_OPERATION_EVENT_BLOCK_DISTANCE_FALLBACK",
        global = true
    )]
    user_operation_event_block_distance_fallback: Option<u64>,

    #[arg(
        long = "verification_estimation_gas_fee",
        name = "verification_estimation_gas_fee",
        env = "VERIFICATION_ESTIMATION_GAS_FEE",
        default_value = "1000000000000", // 10K gwei
        global = true
    )]
    verification_estimation_gas_fee: u128,

    #[arg(
        long = "bundle_base_fee_overhead_percent",
        name = "bundle_base_fee_overhead_percent",
        env = "BUNDLE_BASE_FEE_OVERHEAD_PERCENT",
        default_value = "27", // 2 12.5% EIP-1559 increases
        global = true
    )]
    bundle_base_fee_overhead_percent: u32,

    #[arg(
        long = "bundle_priority_fee_overhead_percent",
        name = "bundle_priority_fee_overhead_percent",
        env = "BUNDLE_PRIORITY_FEE_OVERHEAD_PERCENT",
        default_value = "0",
        global = true
    )]
    bundle_priority_fee_overhead_percent: u32,

    #[arg(
        long = "priority_fee_mode_kind",
        name = "priority_fee_mode_kind",
        env = "PRIORITY_FEE_MODE_KIND",
        value_parser = PossibleValuesParser::new(["base_fee_percent", "priority_fee_increase_percent"]),
        default_value = "priority_fee_increase_percent",
        global = true
    )]
    priority_fee_mode_kind: String,

    #[arg(
        long = "priority_fee_mode_value",
        name = "priority_fee_mode_value",
        env = "PRIORITY_FEE_MODE_VALUE",
        default_value = "0",
        global = true
    )]
    priority_fee_mode_value: u32,

    #[arg(
        long = "base_fee_accept_percent",
        name = "base_fee_accept_percent",
        env = "BASE_FEE_ACCEPT_PERCENT",
        default_value = "50",
        global = true
    )]
    base_fee_accept_percent: u32,

    #[arg(
        long = "pre_verification_gas_accept_percent",
        name = "pre_verification_gas_accept_percent",
        env = "PRE_VERIFICATION_GAS_ACCEPT_PERCENT",
        default_value = "50",
        global = true
    )]
    pre_verification_gas_accept_percent: u32,

    #[arg(
        long = "execution_gas_limit_efficiency_reject_threshold",
        name = "execution_gas_limit_efficiency_reject_threshold",
        env = "EXECUTION_GAS_LIMIT_EFFICIENCY_REJECT_THRESHOLD",
        default_value = "0.0"
    )]
    pub execution_gas_limit_efficiency_reject_threshold: f64,

    #[arg(
        long = "verification_gas_limit_efficiency_reject_threshold",
        name = "verification_gas_limit_efficiency_reject_threshold",
        env = "VERIFICATION_GAS_LIMIT_EFFICIENCY_REJECT_THRESHOLD",
        default_value = "0.0"
    )]
    pub verification_gas_limit_efficiency_reject_threshold: f64,

    #[arg(
        long = "verification_gas_allowed_error_pct",
        name = "verification_gas_allowed_error_pct",
        env = "VERIFICATION_GAS_ALLOWED_ERROR_PCT",
        default_value = "15",
        global = true
    )]
    pub verification_gas_allowed_error_pct: u128,

    #[arg(
        long = "call_gas_allowed_error_pct",
        name = "call_gas_allowed_error_pct",
        env = "CALL_GAS_ALLOWED_ERROR_PCT",
        default_value = "15",
        global = true
    )]
    pub call_gas_allowed_error_pct: u128,

    #[arg(
        long = "max_gas_estimation_gas",
        name = "max_gas_estimation_gas",
        env = "MAX_GAS_ESTIMATION_GAS",
        default_value = "550000000",
        global = true
    )]
    pub max_gas_estimation_gas: u64,

    #[arg(
        long = "max_gas_estimation_rounds",
        name = "max_gas_estimation_rounds",
        env = "MAX_GAS_ESTIMATION_ROUNDS",
        default_value = "3",
        global = true
    )]
    pub max_gas_estimation_rounds: u32,

    #[arg(
        long = "mempool_config_path",
        name = "mempool_config_path",
        env = "MEMPOOL_CONFIG_PATH",
        global = true
    )]
    pub mempool_config_path: Option<String>,

    #[arg(
        long = "builders_config_path",
        name = "builders_config_path",
        env = "BUILDERS_CONFIG_PATH",
        global = true
    )]
    builders_config_path: Option<String>,

    #[arg(
        long = "enabled_entry_points",
        name = "enabled_entry_points",
        env = "ENABLED_ENTRY_POINTS",
        value_delimiter = ',',
        default_value = "v0.7",
        global = true
    )]
    pub enabled_entry_points: Vec<EntryPointVersion>,

    /// Number of signers (and workers) to use for bundle building.
    /// Each signer handles all configured entrypoints.
    #[arg(
        long = "num_signers",
        name = "num_signers",
        env = "NUM_SIGNERS",
        default_value = "1",
        global = true
    )]
    pub num_signers: u64,

    #[arg(
        long = "da_gas_tracking_enabled",
        name = "da_gas_tracking_enabled",
        env = "DA_GAS_TRACKING_ENABLED",
        default_value = "false",
        global = true
    )]
    pub da_gas_tracking_enabled: bool,

    #[arg(
        long = "provider_client_timeout_seconds",
        name = "provider_client_timeout_seconds",
        env = "PROVIDER_CLIENT_TIMEOUT_SECONDS",
        default_value = "10",
        global = true
    )]
    pub provider_client_timeout_seconds: u64,

    #[arg(
        long = "provider_rate_limit_retry_enabled",
        name = "provider_rate_limit_retry_enabled",
        env = "PROVIDER_RATE_LIMIT_RETRY_ENABLED",
        default_value = "false",
        global = true
    )]
    pub provider_rate_limit_retry_enabled: bool,

    #[arg(
        long = "provider_consistency_retry_enabled",
        name = "provider_consistency_retry_enabled",
        env = "PROVIDER_CONSISTENCY_RETRY_ENABLED",
        default_value = "false",
        global = true
    )]
    pub provider_consistency_retry_enabled: bool,

    #[arg(
        long = "max_expected_storage_slots",
        name = "max_expected_storage_slots",
        env = "MAX_EXPECTED_STORAGE_SLOTS",
        global = true
    )]
    pub max_expected_storage_slots: Option<usize>,

    #[arg(
        long = "enabled_aggregators",
        name = "enabled_aggregators",
        env = "ENABLED_AGGREGATORS",
        global = true,
        value_delimiter = ','
    )]
    pub enabled_aggregators: Vec<AggregatorType>,

    #[arg(
        long = "aggregator_options",
        env = "AGGREGATOR_OPTIONS",
        global = true,
        value_delimiter = ',',
        value_parser = ValueParser::new(parse_key_val)
    )]
    pub aggregator_options: Vec<(String, String)>,

    #[arg(
        long = "eip7702_authority_pending_check_enabled",
        name = "eip7702_authority_pending_check_enabled",
        env = "EIP7702_AUTHORITY_PENDING_CHECK_ENABLED",
        default_value = "false",
        global = true
    )]
    pub eip7702_authority_pending_check_enabled: bool,
}

impl CommonArgs {
    pub fn bundle_limits(&self, chain_spec: &ChainSpec) -> BundleLimits {
        BundleLimits {
            target_bundle_execution_gas_limit: chain_spec
                .transaction_gas_limit_mult(self.target_bundle_transaction_gas_limit_ratio),
            max_bundle_execution_gas_limit: chain_spec
                .transaction_gas_limit_mult(self.max_bundle_transaction_gas_limit_ratio),
        }
    }
}

pub struct BundleLimits {
    pub target_bundle_execution_gas_limit: u128,
    pub max_bundle_execution_gas_limit: u128,
}

/// Converts a &str into a SecretString
pub(crate) fn parse_secret(s: &str) -> Result<SecretString, String> {
    Ok(s.into())
}

fn parse_key_val(s: &str) -> Result<(String, String), anyhow::Error> {
    let pos = s
        .find('=')
        .ok_or_else(|| anyhow::anyhow!(format!("invalid KEY=value: no `=` found in `{}`", s)))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

fn verify_f64_less_than_one(v: &str) -> Result<f64, String> {
    let Ok(v) = v.parse() else {
        return Err("invalid float".to_string());
    };
    if v < 1.0 {
        Ok(v)
    } else {
        Err(format!("value {v} is not less than 1.0"))
    }
}

const SIMULATION_GAS_OVERHEAD: u128 = 100_000;

impl TryFromWithSpec<&CommonArgs> for EstimationSettings {
    type Error = anyhow::Error;

    fn try_from_with_spec(value: &CommonArgs, chain_spec: &ChainSpec) -> Result<Self, Self::Error> {
        let bundle_limits = value.bundle_limits(chain_spec);

        if value.max_verification_gas
            > bundle_limits
                .max_bundle_execution_gas_limit
                .saturating_sub(SIMULATION_GAS_OVERHEAD) as u64
        {
            anyhow::bail!(
                "max_verification_gas ({}) must be less than max_bundle_execution_gas ({}) by at least {}",
                value.max_verification_gas,
                bundle_limits.max_bundle_execution_gas_limit,
                SIMULATION_GAS_OVERHEAD
            );
        }

        if bundle_limits.max_bundle_execution_gas_limit < MIN_CALL_GAS_LIMIT {
            anyhow::bail!(
                "max_bundle_execution_gas ({}) must be greater than or equal to {}",
                bundle_limits.max_bundle_execution_gas_limit,
                MIN_CALL_GAS_LIMIT
            );
        }

        Ok(Self {
            max_verification_gas: value.max_verification_gas as u128,
            max_paymaster_verification_gas: value.max_verification_gas as u128,
            max_paymaster_post_op_gas: bundle_limits.max_bundle_execution_gas_limit,
            max_bundle_execution_gas: bundle_limits.max_bundle_execution_gas_limit,
            max_gas_estimation_gas: value.max_gas_estimation_gas,
            verification_estimation_gas_fee: value.verification_estimation_gas_fee,
            verification_gas_limit_efficiency_reject_threshold: value
                .verification_gas_limit_efficiency_reject_threshold,
            verification_gas_allowed_error_pct: value.verification_gas_allowed_error_pct,
            call_gas_allowed_error_pct: value.call_gas_allowed_error_pct,
            max_gas_estimation_rounds: value.max_gas_estimation_rounds,
        })
    }
}

impl TryFromWithSpec<&CommonArgs> for PrecheckSettings {
    type Error = anyhow::Error;

    fn try_from_with_spec(value: &CommonArgs, chain_spec: &ChainSpec) -> Result<Self, Self::Error> {
        let bundle_limits = value.bundle_limits(chain_spec);

        Ok(Self {
            max_verification_gas: value.max_verification_gas as u128,
            max_bundle_execution_gas: bundle_limits.max_bundle_execution_gas_limit,
            max_uo_cost: value.max_uo_cost.unwrap_or(U256::MAX),
            bundle_priority_fee_overhead_percent: value.bundle_priority_fee_overhead_percent,
            priority_fee_mode: PriorityFeeMode::try_from(
                value.priority_fee_mode_kind.as_str(),
                value.priority_fee_mode_value,
            )?,
            base_fee_accept_percent: value.base_fee_accept_percent,
            pre_verification_gas_accept_percent: value.pre_verification_gas_accept_percent,
            verification_gas_limit_efficiency_reject_threshold: value
                .verification_gas_limit_efficiency_reject_threshold,
            eip7702_authority_pending_check_enabled: value.eip7702_authority_pending_check_enabled,
        })
    }
}

impl TryFrom<&CommonArgs> for SimulationSettings {
    type Error = anyhow::Error;

    fn try_from(value: &CommonArgs) -> Result<Self, Self::Error> {
        if go_parse_duration::parse_duration(&value.tracer_timeout).is_err() {
            bail!(
                "Invalid value for tracer_timeout, must be parsable by the ParseDuration function. See docs https://pkg.go.dev/time#ParseDuration"
            )
        }

        Ok(Self {
            min_unstake_delay: value.min_unstake_delay,
            min_stake_value: U256::from(value.min_stake_value),
            tracer_timeout: value.tracer_timeout.clone(),
            enable_unsafe_fallback: value.enable_unsafe_fallback,
        })
    }
}

impl TryFrom<&CommonArgs> for AlloyNetworkConfig {
    type Error = anyhow::Error;

    fn try_from(value: &CommonArgs) -> Result<Self, Self::Error> {
        Ok(Self {
            rpc_url: Url::parse(value.node_http.as_ref().context("must provide node_http")?)?,
            client_timeout_seconds: value.provider_client_timeout_seconds,
            rate_limit_retry_enabled: value.provider_rate_limit_retry_enabled,
            consistency_retry_enabled: value.provider_consistency_retry_enabled,
            ..Default::default()
        })
    }
}

/// CLI options for the metrics server
#[derive(Debug, Args)]
#[command(next_help_heading = "Metrics")]
pub struct MetricsArgs {
    /// Port to listen on for metrics requests
    #[arg(
        long = "metrics.port",
        name = "metrics.port",
        env = "METRICS_PORT",
        default_value = "8080",
        global = true
    )]
    port: u16,

    /// Host to listen on for metrics requests
    #[arg(
        long = "metrics.host",
        name = "metrics.host",
        env = "METRICS_HOST",
        default_value = "0.0.0.0",
        global = true
    )]
    host: String,

    /// Tags for metrics
    ///
    /// Format: key1=value1,key2=value2,...
    #[arg(
        long = "metrics.tags",
        name = "metrics.tags",
        env = "METRICS_TAGS",
        default_values_t = Vec::<String>::new(),
        value_delimiter = ',',
        global = true
    )]
    tags: Vec<String>,

    /// Sample interval for sampling metrics
    #[arg(
        long = "metrics.sample_interval_millis",
        name = "metrics.sample_interval_millis",
        env = "METRICS_SAMPLE_INTERVAL_MILLIS",
        default_value = "1000",
        global = true
    )]
    sample_interval_millis: u64,

    /// Bucket for histogram metric.
    #[arg(
        long = "metrics.histogram_buckets", 
        name = "metrics.histogram_buckets",
        env = "METRICS_HISTOGRAM_BUCKETS",
        default_values_t = vec![
            // Exponential buckets from 0 to 256
            0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0,
            // Fine-grained buckets from 500 to 1000
            500.0, 600.0, 700.0, 800.0, 900.0, 1000.0,
            // Coarser buckets from 1000 to 10,000
            2000.0, 3000.0, 4000.0, 5000.0, 7500.0, 10000.0,
        ],
        global = true
    )]
    buckets: Vec<f64>,
}

/// CLI options for logging
#[derive(Debug, Args)]
#[command(next_help_heading = "Logging")]
pub struct LogsArgs {
    /// Log file
    ///
    /// If not provided, logs will be written to stdout
    #[arg(
        long = "log.file",
        name = "log.file",
        env = "LOG_FILE",
        default_value = None,
        global = true
    )]
    file: Option<String>,

    /// Log JSON
    ///
    /// If set, logs will be written in JSON format
    #[arg(
        long = "log.json",
        name = "log.json",
        env = "LOG_JSON",
        required = false,
        num_args = 0,
        global = true
    )]
    json: bool,

    /// Log OTLP Endpoint
    ///
    /// If set, tracing spans will be forwarded to the provided gRPC OTLP endpoint
    #[arg(
        long = "log.otlp_grpc_endpoint",
        name = "log.otlp_grpc_endpoint",
        env = "LOG_OTLP_GRPC_ENDPOINT",
        default_value = None,
        global = true
    )]
    otlp_grpc_endpoint: Option<String>,
}

/// CLI options
#[derive(Debug, Parser)]
pub struct Cli {
    #[clap(subcommand)]
    command: Command,

    #[clap(flatten)]
    common: CommonArgs,

    #[clap(flatten)]
    metrics: MetricsArgs,

    #[clap(flatten)]
    logs: LogsArgs,
}

#[derive(Clone)]
pub struct RundlerProviders<P, EP06, EP07, D, DS, F> {
    provider: P,
    ep_v0_6: Option<EP06>,
    ep_v0_7_abi: [Option<EP07>; EntryPointVersion::COUNT],
    da_gas_oracle: D,
    da_gas_oracle_sync: Option<DS>,
    fee_estimator: F,
}

impl<P, EP06, EP07, D, DS, F> Providers for RundlerProviders<P, EP06, EP07, D, DS, F>
where
    P: EvmProvider + Clone,
    EP06: EntryPointProvider<UserOperationV0_6> + Clone,
    EP07: EntryPointProvider<UserOperationV0_7> + Clone,
    D: DAGasOracle + Clone,
    DS: DAGasOracleSync + Clone,
    F: FeeEstimator + Clone,
{
    type Evm = P;
    type EntryPointV0_6 = EP06;
    type EntryPointV0_7 = EP07;
    type DAGasOracle = D;
    type DAGasOracleSync = DS;
    type FeeEstimator = F;

    fn evm(&self) -> &Self::Evm {
        &self.provider
    }

    fn ep_v0_6(&self) -> &Option<Self::EntryPointV0_6> {
        &self.ep_v0_6
    }

    fn ep_v0_7(&self, ep_version: EntryPointVersion) -> &Option<Self::EntryPointV0_7> {
        &self.ep_v0_7_abi[ep_version as usize]
    }

    fn da_gas_oracle(&self) -> &Self::DAGasOracle {
        &self.da_gas_oracle
    }

    fn da_gas_oracle_sync(&self) -> &Option<Self::DAGasOracleSync> {
        &self.da_gas_oracle_sync
    }

    fn fee_estimator(&self) -> &Self::FeeEstimator {
        &self.fee_estimator
    }
}

pub fn construct_providers(
    args: &CommonArgs,
    chain_spec: &ChainSpec,
) -> anyhow::Result<impl Providers + 'static> {
    let alloy_network_config = AlloyNetworkConfig::try_from(args)?;
    let provider = Arc::new(rundler_provider::new_alloy_provider(&alloy_network_config)?);

    let (da_gas_oracle, da_gas_oracle_sync) =
        rundler_provider::new_alloy_da_gas_oracle(chain_spec, provider.clone());
    let bundle_limits = args.bundle_limits(chain_spec);
    let max_bundle_execution_gas = bundle_limits
        .max_bundle_execution_gas_limit
        .try_into()
        .expect("max_bundle_execution_gas is too large for u64");

    let evm = AlloyEvmProvider::new(provider.clone());

    let mut ep_v0_7_abi = [const { None }; EntryPointVersion::COUNT];
    let mut ep_v0_6 = None;

    for ep_version in &args.enabled_entry_points {
        match ep_version.abi_version() {
            EntryPointAbiVersion::V0_6 => {
                ep_v0_6 = Some(AlloyEntryPointV0_6::new(
                    chain_spec.clone(),
                    args.max_verification_gas,
                    max_bundle_execution_gas,
                    args.max_gas_estimation_gas,
                    max_bundle_execution_gas,
                    provider.clone(),
                    da_gas_oracle.clone(),
                ))
            }
            EntryPointAbiVersion::V0_7 => {
                ep_v0_7_abi[*ep_version as usize] = Some(AlloyEntryPointV0_7::new(
                    chain_spec.clone(),
                    *ep_version,
                    args.max_verification_gas,
                    max_bundle_execution_gas,
                    args.max_gas_estimation_gas,
                    max_bundle_execution_gas,
                    provider.clone(),
                    da_gas_oracle.clone(),
                ))
            }
        }
    }

    let priority_fee_mode = PriorityFeeMode::try_from(
        args.priority_fee_mode_kind.as_str(),
        args.priority_fee_mode_value,
    )?;
    let fee_estimator = Arc::new(rundler_provider::new_fee_estimator(
        chain_spec,
        evm.clone(),
        priority_fee_mode,
        args.bundle_base_fee_overhead_percent,
        args.bundle_priority_fee_overhead_percent,
    ));

    Ok(RundlerProviders {
        provider: evm,
        ep_v0_6,
        ep_v0_7_abi,
        da_gas_oracle,
        da_gas_oracle_sync,
        fee_estimator,
    })
}

fn lint_da_gas_tracking(da_gas_tracking_enabled: bool, chain_spec: &ChainSpec) -> bool {
    if !da_gas_tracking_enabled {
        return false;
    }

    if !chain_spec.da_pre_verification_gas {
        tracing::warn!("DA tracking is disabled because DA pre-verification gas is not enabled");
        false
    } else if !(chain_spec.da_gas_oracle_type == DAGasOracleType::CachedNitro
        || chain_spec.da_gas_oracle_type == DAGasOracleType::LocalBedrock)
    {
        tracing::warn!(
            "DA tracking is disabled because DA gas oracle contract type {:?} does not support caching",
            chain_spec.da_gas_oracle_type
        );
        false
    } else {
        true
    }
}

async fn load_configs(
    args: &CommonArgs,
) -> anyhow::Result<(Option<MempoolConfigs>, Option<EntryPointBuilderConfigs>)> {
    let mempool_configs = if let Some(mempool_config_path) = &args.mempool_config_path {
        let mempool_configs = get_json_config::<MempoolConfigs>(mempool_config_path)
            .await
            .with_context(|| format!("should load mempool config from {mempool_config_path}"))?;

        tracing::info!("Mempool configs: {:?}", mempool_configs);

        // For now only allow one mempool defined per entry point
        let mut entry_points = vec![];
        for mempool_config in mempool_configs.0.values() {
            let ep = mempool_config.entry_point();
            if entry_points.contains(&ep) {
                bail!("multiple mempool configs defined for entry point {:?}", ep);
            }
            entry_points.push(ep);
        }

        Some(mempool_configs)
    } else {
        None
    };

    let builders_config = if let Some(builders_config_path) = &args.builders_config_path {
        let builders_config = get_json_config::<EntryPointBuilderConfigs>(builders_config_path)
            .await
            .with_context(|| format!("should load builders config from {builders_config_path}"))?;

        tracing::info!("Entry point builders: {:?}", builders_config);

        Some(builders_config)
    } else {
        None
    };

    Ok((mempool_configs, builders_config))
}
