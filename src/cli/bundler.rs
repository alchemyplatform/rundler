use std::time::Duration;

use anyhow::bail;
use clap::Args;
use tokio::signal;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};

use crate::builder;
use crate::common::server::format_server_addr;
use crate::common::types::CheapClone;
use crate::op_pool;
use crate::rpc;

use super::{builder::BuilderArgs, pool::PoolArgs, rpc::RpcArgs, CommonArgs};

#[derive(Debug, Args)]
pub struct BundlerCliArgs {
    #[command(flatten)]
    pool: PoolArgs,

    #[command(flatten)]
    builder: BuilderArgs,

    #[command(flatten)]
    rpc: RpcArgs,
}

pub async fn run(bundler_args: BundlerCliArgs, common_args: CommonArgs) -> anyhow::Result<()> {
    let BundlerCliArgs {
        pool: pool_args,
        builder: builder_args,
        rpc: rpc_args,
    } = bundler_args;

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let (shutdown_scope, mut shutdown_wait) = mpsc::channel(1);

    let pool_url = format_server_addr(&pool_args.host, pool_args.port, false);
    let builder_url = builder_args.url(false);
    if builder_url.is_none() {
        info!("Builder server is missing port or host, disabled");
    }

    let pool_handle = tokio::spawn(op_pool::run(
        pool_args.to_args(&common_args)?,
        shutdown_tx.subscribe(),
        shutdown_scope.cheap_clone(),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let builder_handle = tokio::spawn(builder::run(
        builder_args.to_args(&common_args, pool_url.clone())?,
        shutdown_tx.subscribe(),
        shutdown_scope.cheap_clone(),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let rpc_handle = tokio::spawn(rpc::run(
        rpc_args.to_args(&common_args, pool_url, builder_url)?,
        shutdown_rx,
        shutdown_scope,
    ));

    tokio::select! {
        res = pool_handle => {
            error!("Pool server exited unexpectedly: {res:?}");
        }
        res = builder_handle => {
            error!("Builder server exited unexpectedly: {res:?}");
        }
        res = rpc_handle => {
            error!("RPC server exited unexpectedly: {res:?}");
        }
        res = signal::ctrl_c() => {
            match res {
                Ok(_) => {
                    info!("Received SIGINT, shutting down");
                }
                Err(err) => {
                    bail!("Error while waiting for SIGINT: {err:?}");
                }
            }
        }
    }

    shutdown_tx.send(())?;
    shutdown_wait.recv().await;
    Ok(())
}
