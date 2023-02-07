use std::io;
use std::time::Duration;

use super::bundler;
use super::op_pool;
use super::rpc;
use clap::{Args, Parser, Subcommand};
use tokio::signal;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

mod prometheus_exporter;

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
                op_pool_args.into(),
                shutdown_tx.subscribe(),
                shutdown_scope.clone(),
            ));
            tokio::time::sleep(Duration::from_millis(100)).await;

            tokio::spawn(bundler::run(
                bundler_args.into(),
                shutdown_tx.subscribe(),
                shutdown_scope.clone(),
            ));
            tokio::time::sleep(Duration::from_millis(100)).await;

            tokio::spawn(rpc::run(rpc_args.into(), shutdown_rx, shutdown_scope));
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

#[derive(Args, Debug)]
#[command(next_help_heading = "OP POOL")]
struct OpPoolArgs {
    #[arg(
        long = "oppool.port",
        name = "oppool.port",
        env = "OPPOOL_PORT",
        default_value = "50051"
    )]
    port: u16,

    #[arg(
        long = "oppool.host",
        name = "oppool.host",
        env = "OPPOOL_HOST",
        default_value = "127.0.0.1"
    )]
    host: String,
}

impl From<OpPoolArgs> for op_pool::Args {
    fn from(value: OpPoolArgs) -> Self {
        let OpPoolArgs { port, host } = value;
        op_pool::Args { port, host }
    }
}

#[derive(Args, Debug)]
#[command(next_help_heading = "BUNDLER")]
struct BundlerArgs {
    #[arg(
        long = "bundler.port",
        name = "bundler.port",
        env = "BUNDLER_PORT",
        default_value = "50052"
    )]
    port: u16,

    #[arg(
        long = "bundler.host",
        name = "bundler.host",
        env = "BUNDLER_HOST",
        default_value = "127.0.0.1"
    )]
    host: String,
}

impl From<BundlerArgs> for bundler::Args {
    fn from(args: BundlerArgs) -> Self {
        let BundlerArgs { port, host } = args;
        bundler::Args { port, host }
    }
}

#[derive(Args, Debug)]
#[command(next_help_heading = "RPC")]
struct RpcArgs {
    #[arg(
        long = "rpc.port",
        name = "rpc.port",
        env = "RPC_PORT",
        default_value = "8545"
    )]
    port: u16,

    #[arg(
        long = "rpc.host",
        name = "rpc.host",
        env = "RPC_HOST",
        default_value = "0.0.0.0"
    )]
    host: String,
}

impl From<RpcArgs> for rpc::Args {
    fn from(args: RpcArgs) -> Self {
        let RpcArgs { port, host } = args;
        rpc::Args { port, host }
    }
}

#[derive(Debug, Parser)]
struct RunArgs {
    #[command(flatten)]
    op_pool: OpPoolArgs,

    #[command(flatten)]
    bundler: BundlerArgs,

    #[command(flatten)]
    rpc: RpcArgs,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(name = "run")]
    Run(RunArgs),
}

#[derive(Debug, Args)]
#[command(next_help_heading = "Metrics")]
struct Metrics {
    #[arg(
        long = "metrics.port",
        name = "metrics.port",
        env = "METRICS_PORT",
        default_value = "8080",
        global = true
    )]
    port: u16,

    #[arg(
        long = "metrics.host",
        name = "metrics.host",
        env = "METRICS_HOST",
        default_value = "0.0.0.0",
        global = true
    )]
    host: String,
}

#[derive(Debug, Args)]
#[command(next_help_heading = "Logging")]
struct Logs {
    #[arg(
        long = "log.level",
        name = "log.level",
        env = "LOG_LEVEL",
        default_value = "info",
        global = true
    )]
    level: String,

    #[arg(
        long = "log.file",
        name = "log.file",
        env = "LOG_FILE",
        default_value = None,
        global = true
    )]
    file: Option<String>,
}

#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,

    #[clap(flatten)]
    metrics: Metrics,

    #[clap(flatten)]
    logs: Logs,
}
