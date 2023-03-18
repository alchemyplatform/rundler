use std::time::Duration;

use clap::Args;
use tokio::signal;
use tokio::sync::{broadcast, mpsc};

use crate::builder;
use crate::common::server::format_server_addr;
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

    let pool_url = format_server_addr(&pool_args.host, pool_args.port);
    let builder_url = None; // TODO(builder): add builder url

    tokio::spawn(op_pool::run(
        pool_args.to_args(&common_args)?,
        shutdown_tx.subscribe(),
        shutdown_scope.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(builder::run(
        builder_args.to_args(&common_args, pool_url.clone())?,
        shutdown_tx.subscribe(),
        shutdown_scope.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    tokio::spawn(rpc::run(
        rpc_args.to_args(&common_args, pool_url, builder_url)?,
        shutdown_rx,
        shutdown_scope,
    ));

    match signal::ctrl_c().await {
        Ok(_) => {
            tracing::info!("Received SIGINT, shutting down");
            shutdown_tx.send(())?;
        }
        Err(err) => {
            tracing::error!("Error while waiting for SIGINT: {err:?}");
        }
    }

    shutdown_wait.recv().await;
    Ok(())
}
