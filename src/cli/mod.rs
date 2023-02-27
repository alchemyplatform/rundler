use std::io;
use std::time::Duration;

use super::bundler;
use super::op_pool;
use super::rpc;
use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use tokio::signal;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

mod prometheus_exporter;

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

    let subscriber = FmtSubscriber::builder()
        .with_max_level(opt.logs.level.parse::<Level>()?)
        .with_writer(appender)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    tracing::info!("Parsed CLI options: {:#?}", opt);

    let metrics_addr = format!("{}:{}", opt.metrics.host, opt.metrics.port).parse()?;
    prometheus_exporter::initialize(metrics_addr)?;

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let (shutdown_scope, mut shutdown_wait) = mpsc::channel(1);

    match opt.command {
        Command::Run(args) => {
            let RunArgs {
                op_pool: op_pool_args,
                bundler: bundler_args,
                rpc: rpc_args,
            } = args;

            tokio::spawn(op_pool::run(
                op_pool_args.to_args(&opt.common)?,
                shutdown_tx.subscribe(),
                shutdown_scope.clone(),
            ));
            tokio::time::sleep(Duration::from_millis(100)).await;

            tokio::spawn(bundler::run(
                bundler_args.to_args(&opt.common)?,
                shutdown_tx.subscribe(),
                shutdown_scope.clone(),
            ));
            tokio::time::sleep(Duration::from_millis(100)).await;

            tokio::spawn(rpc::run(
                rpc_args.to_args(&opt.common)?,
                shutdown_rx,
                shutdown_scope,
            ));
        }
    }

    match signal::ctrl_c().await {
        Ok(_) => {
            tracing::info!("Received SIGINT, shutting down");
            shutdown_tx.send(())?;
        }
        Err(err) => {
            tracing::error!("Error while waiting for SIGINT: {err:?}");
        }
    }

    let _ = shutdown_wait.recv().await;
    tracing::info!("All components shutdown, goodbye");

    Ok(())
}

/// CLI options for the OP Pool
#[derive(Args, Debug)]
#[command(next_help_heading = "OP POOL")]
struct OpPoolArgs {
    /// Port to listen on for gRPC requests
    #[arg(
        long = "oppool.port",
        name = "oppool.port",
        env = "OPPOOL_PORT",
        default_value = "50051"
    )]
    port: u16,

    /// Host to listen on for gRPC requests
    #[arg(
        long = "oppool.host",
        name = "oppool.host",
        env = "OPPOOL_HOST",
        default_value = "127.0.0.1"
    )]
    host: String,
}

impl OpPoolArgs {
    /// Convert the CLI arguments into the arguments for the OP Pool combining
    /// common and op pool specific arguments.
    pub fn to_args(&self, common: &Common) -> anyhow::Result<op_pool::Args> {
        Ok(op_pool::Args {
            port: self.port,
            host: self.host.clone(),
            entry_point: common
                .entry_point
                .parse()
                .context("Invalid entry_point argument")?,
            chain_id: common.chain_id.into(),
            ws_url: common.ws_url.clone(),
        })
    }
}

/// CLI options for the bundler
#[derive(Args, Debug)]
#[command(next_help_heading = "BUNDLER")]
struct BundlerArgs {
    /// Port to listen on for gRPC requests
    #[arg(
        long = "bundler.port",
        name = "bundler.port",
        env = "BUNDLER_PORT",
        default_value = "50052"
    )]
    port: u16,

    /// Host to listen on for gRPC requests
    #[arg(
        long = "bundler.host",
        name = "bundler.host",
        env = "BUNDLER_HOST",
        default_value = "127.0.0.1"
    )]
    host: String,
}

impl BundlerArgs {
    /// Convert the CLI arguments into the arguments for the Bundler combining
    /// common and bundler specific arguments.
    pub fn to_args(&self, common: &Common) -> anyhow::Result<bundler::Args> {
        Ok(bundler::Args {
            port: self.port,
            host: self.host.clone(),
            entry_point: common
                .entry_point
                .parse()
                .context("Invalid entry_point argument")?,
            chain_id: common.chain_id.into(),
        })
    }
}

/// CLI options for the RPC server
#[derive(Args, Debug)]
#[command(next_help_heading = "RPC")]
struct RpcArgs {
    /// Port to listen on for JSON-RPC requests
    #[arg(
        long = "rpc.port",
        name = "rpc.port",
        env = "RPC_PORT",
        default_value = "8545"
    )]
    port: u16,

    /// Host to listen on for JSON-RPC requests
    #[arg(
        long = "rpc.host",
        name = "rpc.host",
        env = "RPC_HOST",
        default_value = "0.0.0.0"
    )]
    host: String,
}

impl RpcArgs {
    /// Convert the CLI arguments into the arguments for the RPC server combining
    /// common and rpc specific arguments.
    pub fn to_args(&self, common: &Common) -> anyhow::Result<rpc::Args> {
        Ok(rpc::Args {
            port: self.port,
            host: self.host.clone(),
            entry_point: common
                .entry_point
                .parse()
                .context("Invalid entry_point argument")?,
            chain_id: common.chain_id.into(),
        })
    }
}

/// CLI options for the run command
///
/// Combines the options for each component into a single struct
#[derive(Debug, Parser)]
struct RunArgs {
    #[command(flatten)]
    op_pool: OpPoolArgs,

    #[command(flatten)]
    bundler: BundlerArgs,

    #[command(flatten)]
    rpc: RpcArgs,
}

/// CLI commands
#[derive(Debug, Subcommand)]
enum Command {
    /// Run command
    ///
    /// Runs the OP Pool, Bundler, and RPC server
    /// in a single process.
    #[command(name = "run")]
    Run(RunArgs),
}

/// CLI common options
#[derive(Debug, Args)]
#[command(next_help_heading = "Common")]
struct Common {
    /// Entry point address to target
    #[arg(
        long = "entry_point",
        name = "entry_point",
        env = "ENTRY_POINT",
        default_value = "0x0", // required or will error
        global = true
    )]
    entry_point: String,

    /// Chain ID to target
    #[arg(
        long = "chain_id",
        name = "chain_id",
        env = "CHAIN_ID",
        default_value = "1337",
        global = true
    )]
    chain_id: u128,

    /// Websocket URL to connect to
    #[arg(
        long = "ws_url",
        name = "ws_url",
        env = "WS_URL",
        default_value = "ws://localhost:8546",
        global = true
    )]
    ws_url: String,
}

/// CLI options for the metrics server
#[derive(Debug, Args)]
#[command(next_help_heading = "Metrics")]
struct Metrics {
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
}

/// CLI options for logging
#[derive(Debug, Args)]
#[command(next_help_heading = "Logging")]
struct Logs {
    /// Log level
    ///
    /// Valid values are: trace, debug, info, warn, error
    #[arg(
        long = "log.level",
        name = "log.level",
        env = "LOG_LEVEL",
        default_value = "info",
        global = true
    )]
    level: String,

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
}

/// CLI options
#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,

    #[clap(flatten)]
    common: Common,

    #[clap(flatten)]
    metrics: Metrics,

    #[clap(flatten)]
    logs: Logs,
}
