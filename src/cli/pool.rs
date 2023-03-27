use anyhow::{bail, Context};
use clap::Args;
use tokio::{
    signal,
    sync::{broadcast, mpsc},
};
use tracing::{error, info};

use super::CommonArgs;
use crate::op_pool::{self, PoolConfig};

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

    #[arg(
        long = "pool.max_size_in_bytes",
        name = "pool.max_size_in_bytes",
        env = "POOL_MAX_SIZE_IN_BYTES",
        default_value = "500000000" // .5gigs
    )]
    pub max_size_in_bytes: usize,

    #[arg(
        long = "pool.max_userops_per_sender",
        name = "pool.max_userops_per_sender",
        env = "POOL_MAX_USEROPS_PER_SENDER",
        default_value = "4"
    )]
    pub max_userops_per_sender: usize,

    #[arg(
        long = "pool.min_replacement_fee_increase_percentage",
        name = "pool.min_replacement_fee_increase_percentage",
        env = "POOL_MIN_REPLACEMENT_FEE_INCREASE_PERCENTAGE",
        default_value = "10"
    )]
    pub min_replacement_fee_increase_percentage: usize,
}

impl PoolArgs {
    /// Convert the CLI arguments into the arguments for the OP Pool combining
    /// common and op pool specific arguments.
    pub fn to_args(&self, common: &CommonArgs) -> anyhow::Result<op_pool::Args> {
        let pool_config = PoolConfig {
            entry_point: common
                .entry_point
                .parse()
                .context("Invalid entry_point argument")?,
            chain_id: common.chain_id,
            max_userops_per_sender: self.max_userops_per_sender,
            min_replacement_fee_increase_percentage: self.min_replacement_fee_increase_percentage,
            max_size_of_pool_bytes: self.max_size_in_bytes,
        };

        Ok(op_pool::Args {
            port: self.port,
            host: self.host.clone(),
            ws_url: common
                .node_ws
                .clone()
                .context("pool requires node_ws arg")?,
            pool_config,
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
