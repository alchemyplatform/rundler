use std::io;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod builder;
mod node;
mod pool;
mod prometheus_exporter;
mod rpc;

use builder::BuilderCliArgs;
use node::NodeCliArgs;
use pool::PoolCliArgs;
use rpc::RpcCliArgs;

use crate::common::{precheck, simulation};

/// Main entry point for the CLI
///
/// Parses the CLI arguments and runs the appropriate subcommand.
/// Listens for a ctrl-c signal and shuts down all components when received.
pub async fn run() -> anyhow::Result<()> {
    let opt = Cli::parse();

    let (appender, _guard) = if let Some(log_file) = &opt.logs.file {
        tracing_appender::non_blocking(tracing_appender::rolling::never(".", log_file))
    } else {
        tracing_appender::non_blocking(io::stdout())
    };

    let subscriber_builder = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(appender);
    if opt.logs.json {
        tracing::subscriber::set_global_default(subscriber_builder.json().finish())?;
    } else {
        tracing::subscriber::set_global_default(subscriber_builder.pretty().finish())?;
    }

    tracing::info!("Parsed CLI options: {:#?}", opt);

    let metrics_addr = format!("{}:{}", opt.metrics.host, opt.metrics.port).parse()?;
    prometheus_exporter::initialize(metrics_addr, &opt.metrics.tags)
        .context("metrics server should start")?;

    match opt.command {
        Command::Node(args) => node::run(args, opt.common).await?,
        Command::Pool(args) => pool::run(args, opt.common).await?,
        Command::Rpc(args) => rpc::run(args, opt.common).await?,
        Command::Builder(args) => builder::run(args, opt.common).await?,
    }

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
    Node(NodeCliArgs),

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
    /// Entry point address to target
    #[arg(
        long = "entry_points",
        name = "entry_points",
        env = "ENTRY_POINTS",
        default_values_t = Vec::<String>::new(), // required or will error
        value_delimiter = ',',
        global = true
    )]
    entry_points: Vec<String>,

    /// Chain ID to target
    #[arg(
        long = "chain_id",
        name = "chain_id",
        env = "CHAIN_ID",
        default_value = "1337",
        global = true
    )]
    chain_id: u64,

    /// ETH Node websocket URL to connect to
    #[arg(long = "node_ws", name = "node_ws", env = "NODE_WS", global = true)]
    node_ws: Option<String>,

    /// ETH Node HTTP URL to connect to
    #[arg(
        long = "node_http",
        name = "node_http",
        env = "NODE_HTTP",
        global = true
    )]
    node_http: Option<String>,

    #[arg(
        long = "min_priority_fee_per_gas",
        name = "min_priority_fee_per_gas",
        default_value = "100000000",
        env = "MIN_PRIORITY_FEE_PER_GAS",
        global = true
    )]
    min_priority_fee_per_gas: u64,

    #[arg(
        long = "max_verification_gas",
        name = "max_verification_gas",
        default_value = "5000000",
        env = "MAX_VERIFICATION_GAS",
        global = true
    )]
    max_verification_gas: u64,

    #[arg(
        long = "min_stake_value",
        name = "min_stake_value",
        env = "MIN_STAKE_VALUE",
        default_value = "1000000000000000000",
        global = true
    )]
    min_stake_value: u64,

    #[arg(
        long = "min_unstake_delay",
        name = "min_unstake_delay",
        env = "MIN_UNSTAKE_DELAY",
        default_value = "84600",
        global = true
    )]
    min_unstake_delay: u32,

    #[arg(
        long = "max_simulate_handle_ops_gas",
        name = "max_simulate_handle_ops_gas",
        env = "MAX_SIMULATE_HANDLE_OPS_GAS",
        default_value = "550000000",
        global = true
    )]
    max_simulate_handle_ops_gas: u64,
}

impl From<&CommonArgs> for precheck::Settings {
    fn from(value: &CommonArgs) -> Self {
        Self {
            min_priority_fee_per_gas: value.min_priority_fee_per_gas.into(),
            max_verification_gas: value.max_verification_gas.into(),
        }
    }
}

impl From<&CommonArgs> for simulation::Settings {
    fn from(value: &CommonArgs) -> Self {
        Self::new(
            value.min_unstake_delay,
            value.min_stake_value,
            value.max_simulate_handle_ops_gas,
        )
    }
}

/// CLI options for the metrics server
#[derive(Debug, Args)]
#[command(next_help_heading = "Metrics")]
struct MetricsArgs {
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
}

/// CLI options for logging
#[derive(Debug, Args)]
#[command(next_help_heading = "Logging")]
struct LogsArgs {
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
struct Cli {
    #[clap(subcommand)]
    command: Command,

    #[clap(flatten)]
    common: CommonArgs,

    #[clap(flatten)]
    metrics: MetricsArgs,

    #[clap(flatten)]
    logs: LogsArgs,
}
