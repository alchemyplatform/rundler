use super::bundler;
use super::op_pool;
use super::rpc;
use clap::{Args, Parser, Subcommand};
use tokio::signal;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing;

pub async fn run() -> Result<(), anyhow::Error> {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber)?;

    let opt = Cli::parse();
    tracing::info!("Parsed CLI options: {:#?}", opt);

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let (shutdown_scope, mut shutdown_wait) = mpsc::channel(1);

    match opt.command {
        Command::Run(args) => {
            let op_pool_args = args.op_pool.parse()?;
            let bundler_args = args.bundler.parse()?;
            let rpc_args = args.rpc.parse()?;

            tokio::spawn(op_pool::run(
                op_pool_args,
                shutdown_tx.subscribe(),
                shutdown_scope.clone(),
            ));
            // TODO wait for op pool to be ready

            tokio::spawn(bundler::run(
                bundler_args,
                shutdown_tx.subscribe(),
                shutdown_scope.clone(),
            ));
            // TODO wait for bundler to be ready

            tokio::spawn(rpc::run(rpc_args, shutdown_rx, shutdown_scope));
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

impl OpPoolArgs {
    pub fn parse(&self) -> anyhow::Result<op_pool::Args> {
        Ok(op_pool::Args {
            port: self.port,
            host: self.host.clone(),
        })
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

impl BundlerArgs {
    pub fn parse(&self) -> Result<bundler::Args, anyhow::Error> {
        Ok(bundler::Args {
            port: self.port,
            host: self.host.clone(),
        })
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

impl RpcArgs {
    pub fn parse(&self) -> Result<rpc::Args, anyhow::Error> {
        Ok(rpc::Args {
            port: self.port,
            host: self.host.clone(),
        })
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

#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}
