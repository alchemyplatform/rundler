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

use alloy_primitives::U256;
use anyhow::{bail, Context};
use clap::{builder::PossibleValuesParser, Args, Parser, Subcommand};

mod builder;
mod chain_spec;
mod json;
mod metrics;
mod node;
mod pool;
mod rpc;
mod tracing;

use builder::BuilderCliArgs;
use node::NodeCliArgs;
use pool::PoolCliArgs;
use reth_tasks::TaskManager;
use rpc::RpcCliArgs;
use rundler_provider::{
    AlloyEntryPointV0_6, AlloyEntryPointV0_7, AlloyEvmProvider, DAGasOracleSync,
    EntryPointProvider, EvmProvider, Providers,
};
use rundler_rpc::{EthApiSettings, RundlerApiSettings};
use rundler_sim::{
    EstimationSettings, PrecheckSettings, PriorityFeeMode, SimulationSettings, MIN_CALL_GAS_LIMIT,
};
use rundler_types::{
    chain::ChainSpec, da::DAGasOracleType, v0_6::UserOperation as UserOperationV0_6,
    v0_7::UserOperation as UserOperationV0_7,
};

/// Main entry point for the CLI
///
/// Parses the CLI arguments and runs the appropriate subcommand.
/// Listens for a ctrl-c signal and shuts down all components when received.
pub async fn run() -> anyhow::Result<()> {
    let opt = Cli::parse();
    let _guard = tracing::configure_logging(&opt.logs)?;
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

    let cs = chain_spec::resolve_chain_spec(&opt.common.network, &opt.common.chain_spec);
    tracing::info!("Chain spec: {:#?}", cs);

    match opt.command {
        Command::Node(args) => {
            node::spawn_tasks(task_spawner.clone(), cs, *args, opt.common).await?
        }
        Command::Pool(args) => {
            pool::spawn_tasks(task_spawner.clone(), cs, args, opt.common).await?
        }
        Command::Rpc(args) => rpc::spawn_tasks(task_spawner.clone(), cs, args, opt.common).await?,
        Command::Builder(args) => {
            builder::spawn_tasks(task_spawner.clone(), cs, args, opt.common).await?
        }
    }

    // wait for ctrl-c or the task manager to panic
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received ctrl-c, shutting down");
        },
        e = &mut task_manager => {
            tracing::error!("Task manager panicked, shutting down: {e}");
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
        long = "max_bundle_gas",
        name = "max_bundle_gas",
        default_value = "25000000",
        env = "MAX_BUNDLE_GAS",
        global = true
    )]
    max_bundle_gas: u128,

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
        default_value = "84600",
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

    /// Amount of blocks to search when calling eth_getUserOperationByHash.
    /// Defaults from 0 to latest block
    #[arg(
        long = "user_operation_event_block_distance",
        name = "user_operation_event_block_distance",
        env = "USER_OPERATION_EVENT_BLOCK_DISTANCE",
        global = true
    )]
    user_operation_event_block_distance: Option<u64>,

    #[arg(
        long = "max_simulate_handle_ops_gas",
        name = "max_simulate_handle_ops_gas",
        env = "MAX_SIMULATE_HANDLE_OPS_GAS",
        default_value = "20000000",
        global = true
    )]
    max_simulate_handle_ops_gas: u64,

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
        long = "mempool_config_path",
        name = "mempool_config_path",
        env = "MEMPOOL_CONFIG_PATH",
        global = true
    )]
    pub mempool_config_path: Option<String>,

    #[arg(
        long = "disable_entry_point_v0_6",
        name = "disable_entry_point_v0_6",
        env = "DISABLE_ENTRY_POINT_V0_6",
        default_value = "false",
        global = true
    )]
    pub disable_entry_point_v0_6: bool,

    // Ignored if entry_point_v0_6_enabled is false
    #[arg(
        long = "num_builders_v0_6",
        name = "num_builders_v0_6",
        env = "NUM_BUILDERS_V0_6",
        default_value = "1",
        global = true
    )]
    pub num_builders_v0_6: u64,

    #[arg(
        long = "disable_entry_point_v0_7",
        name = "disable_entry_point_v0_7",
        env = "DISABLE_ENTRY_POINT_V0_7",
        default_value = "false",
        global = true
    )]
    pub disable_entry_point_v0_7: bool,

    // Ignored if entry_point_v0_7_enabled is false
    #[arg(
        long = "num_builders_v0_7",
        name = "num_builders_v0_7",
        env = "NUM_BUILDERS_V0_7",
        default_value = "1",
        global = true
    )]
    pub num_builders_v0_7: u64,

    #[arg(
        long = "da_gas_tracking_enabled",
        name = "da_gas_tracking_enabled",
        env = "DA_GAS_TRACKING_ENABLED",
        default_value = "false"
    )]
    pub da_gas_tracking_enabled: bool,

    #[arg(
        long = "provider_client_timeout_seconds",
        name = "provider_client_timeout_seconds",
        env = "PROVIDER_CLIENT_TIMEOUT_SECONDS",
        default_value = "10"
    )]
    pub provider_client_timeout_seconds: u64,
}

const SIMULATION_GAS_OVERHEAD: u64 = 100_000;

impl TryFrom<&CommonArgs> for EstimationSettings {
    type Error = anyhow::Error;

    fn try_from(value: &CommonArgs) -> Result<Self, Self::Error> {
        if value.max_verification_gas
            > (value.max_simulate_handle_ops_gas - SIMULATION_GAS_OVERHEAD)
        {
            anyhow::bail!(
                "max_verification_gas ({}) must be less than max_simulate_handle_ops_gas ({}) by at least {}",
                value.max_verification_gas,
                value.max_simulate_handle_ops_gas,
                SIMULATION_GAS_OVERHEAD
            );
        }
        let max_call_gas: u128 =
            (value.max_simulate_handle_ops_gas - value.max_verification_gas) as u128;
        if max_call_gas < MIN_CALL_GAS_LIMIT {
            anyhow::bail!(
                "max_simulate_handle_ops_gas ({}) must be greater than max_verification_gas ({}) by at least {MIN_CALL_GAS_LIMIT}",
                value.max_verification_gas,
                value.max_simulate_handle_ops_gas,
            );
        }
        Ok(Self {
            max_verification_gas: value.max_verification_gas as u128,
            max_call_gas,
            max_paymaster_verification_gas: value.max_verification_gas as u128,
            max_paymaster_post_op_gas: max_call_gas,
            max_total_execution_gas: value.max_bundle_gas,
            max_simulate_handle_ops_gas: value.max_simulate_handle_ops_gas,
            verification_estimation_gas_fee: value.verification_estimation_gas_fee,
        })
    }
}

impl TryFrom<&CommonArgs> for PrecheckSettings {
    type Error = anyhow::Error;

    fn try_from(value: &CommonArgs) -> Result<Self, Self::Error> {
        Ok(Self {
            max_verification_gas: value.max_verification_gas as u128,
            max_total_execution_gas: value.max_bundle_gas,
            bundle_base_fee_overhead_percent: value.bundle_base_fee_overhead_percent,
            bundle_priority_fee_overhead_percent: value.bundle_priority_fee_overhead_percent,
            priority_fee_mode: PriorityFeeMode::try_from(
                value.priority_fee_mode_kind.as_str(),
                value.priority_fee_mode_value,
            )?,
            base_fee_accept_percent: value.base_fee_accept_percent,
            pre_verification_gas_accept_percent: value.pre_verification_gas_accept_percent,
        })
    }
}

impl TryFrom<&CommonArgs> for SimulationSettings {
    type Error = anyhow::Error;

    fn try_from(value: &CommonArgs) -> Result<Self, Self::Error> {
        if go_parse_duration::parse_duration(&value.tracer_timeout).is_err() {
            bail!("Invalid value for tracer_timeout, must be parsable by the ParseDuration function. See docs https://pkg.go.dev/time#ParseDuration")
        }

        Ok(Self::new(
            value.min_unstake_delay,
            U256::from(value.min_stake_value),
            value.tracer_timeout.clone(),
        ))
    }
}

impl From<&CommonArgs> for EthApiSettings {
    fn from(value: &CommonArgs) -> Self {
        Self::new(value.user_operation_event_block_distance)
    }
}

impl TryFrom<&CommonArgs> for RundlerApiSettings {
    type Error = anyhow::Error;

    fn try_from(value: &CommonArgs) -> Result<Self, Self::Error> {
        Ok(Self {
            priority_fee_mode: PriorityFeeMode::try_from(
                value.priority_fee_mode_kind.as_str(),
                value.priority_fee_mode_value,
            )?,
            bundle_priority_fee_overhead_percent: value.bundle_priority_fee_overhead_percent,
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
pub struct RundlerProviders<P, EP06, EP07, D> {
    provider: P,
    ep_v0_6: Option<EP06>,
    ep_v0_7: Option<EP07>,
    da_gas_oracle_sync: Option<D>,
}

impl<P, EP06, EP07, D> Providers for RundlerProviders<P, EP06, EP07, D>
where
    P: EvmProvider + Clone,
    EP06: EntryPointProvider<UserOperationV0_6> + Clone,
    EP07: EntryPointProvider<UserOperationV0_7> + Clone,
    D: DAGasOracleSync + Clone,
{
    type Evm = P;
    type EntryPointV0_6 = EP06;
    type EntryPointV0_7 = EP07;
    type DAGasOracleSync = D;

    fn evm(&self) -> &Self::Evm {
        &self.provider
    }

    fn ep_v0_6(&self) -> &Option<Self::EntryPointV0_6> {
        &self.ep_v0_6
    }

    fn ep_v0_7(&self) -> &Option<Self::EntryPointV0_7> {
        &self.ep_v0_7
    }

    fn da_gas_oracle_sync(&self) -> &Option<Self::DAGasOracleSync> {
        &self.da_gas_oracle_sync
    }
}

pub fn construct_providers(
    args: &CommonArgs,
    chain_spec: &ChainSpec,
) -> anyhow::Result<impl Providers> {
    let provider = Arc::new(rundler_provider::new_alloy_provider(
        args.node_http.as_ref().context("must provide node_http")?,
        args.provider_client_timeout_seconds,
    )?);
    let (da_gas_oracle, da_gas_oracle_sync) =
        rundler_provider::new_alloy_da_gas_oracle(chain_spec, provider.clone());

    let ep_v0_6 = if args.disable_entry_point_v0_6 {
        None
    } else {
        Some(AlloyEntryPointV0_6::new(
            chain_spec.clone(),
            args.max_verification_gas,
            args.max_simulate_handle_ops_gas,
            args.max_simulate_handle_ops_gas,
            provider.clone(),
            da_gas_oracle.clone(),
        ))
    };

    let ep_v0_7 = if args.disable_entry_point_v0_7 {
        None
    } else {
        Some(AlloyEntryPointV0_7::new(
            chain_spec.clone(),
            args.max_verification_gas,
            args.max_simulate_handle_ops_gas,
            args.max_simulate_handle_ops_gas,
            provider.clone(),
            da_gas_oracle.clone(),
        ))
    };

    Ok(RundlerProviders {
        provider: AlloyEvmProvider::new(provider),
        ep_v0_6,
        ep_v0_7,
        da_gas_oracle_sync,
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
        tracing::warn!("DA tracking is disabled because DA gas oracle contract type {:?} does not support caching", chain_spec.da_gas_oracle_type);
        false
    } else {
        true
    }
}
