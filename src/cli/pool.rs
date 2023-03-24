use anyhow::{bail, Context};
use clap::Args;
use tokio::{
    signal,
    sync::{broadcast, mpsc},
};
use tracing::{error, info};

use super::CommonArgs;
use crate::op_pool;

/// CLI options for the OP Pool
#[derive(Args, Debug)]
#[command(next_help_heading = "POOL")]
pub struct PoolArgs {
    /// Port to listen on for gRPC requests
    #[arg(
        long = "pool.port",
        name = "pool.port",
        env = "POOL_PORT",
        default_value = "50051"
    )]
    pub port: u16,

    /// Host to listen on for gRPC requests
    #[arg(
        long = "pool.host",
        name = "pool.host",
        env = "POOL_HOST",
        default_value = "127.0.0.1"
    )]
    pub host: String,
}

impl PoolArgs {
    /// Convert the CLI arguments into the arguments for the OP Pool combining
    /// common and op pool specific arguments.
    pub fn to_args(&self, common: &CommonArgs) -> anyhow::Result<op_pool::Args> {
        Ok(op_pool::Args {
            port: self.port,
            host: self.host.clone(),
            entry_point: common
                .entry_point
                .parse()
                .context("Invalid entry_point argument")?,
            chain_id: common.chain_id,
            ws_url: common
                .node_ws
                .clone()
                .context("pool requires node_ws arg")?,
        })
    }
}

/// CLI options for the Pool server standalone
#[derive(Args, Debug)]
pub struct PoolCliArgs {
    #[command(flatten)]
    pool: PoolArgs,
}

pub async fn run(pool_args: PoolCliArgs, common_args: CommonArgs) -> anyhow::Result<()> {
    let PoolCliArgs { pool: pool_args } = pool_args;

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let (shutdown_scope, mut shutdown_wait) = mpsc::channel(1);

    let handle = tokio::spawn(op_pool::run(
        pool_args.to_args(&common_args)?,
        shutdown_rx,
        shutdown_scope,
    ));

    tokio::select! {
        res = handle => {
            error!("Pool server exited unexpectedly: {res:?}");
        }
        res = signal::ctrl_c() => {
            match res {
                Ok(_) => {
                    info!("Received SIGINT, shutting down");
                    shutdown_tx.send(())?;
                    shutdown_wait.recv().await;
                }
                Err(err) => {
                    bail!("Error while waiting for SIGINT: {err:?}");
                }
            }
        }
    }

    Ok(())
}
