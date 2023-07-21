use clap::Args;
use tokio::sync::mpsc;

use super::{builder::BuilderArgs, pool::PoolArgs, rpc::RpcArgs, CommonArgs};
use crate::{
    builder::BuilderTask,
    common::handle,
    op_pool::{PoolClientMode, PoolServerMode, PoolTask},
    rpc::RpcTask,
};

#[derive(Debug, Args)]
pub struct NodeCliArgs {
    #[command(flatten)]
    pool: PoolArgs,

    #[command(flatten)]
    builder: BuilderArgs,

    #[command(flatten)]
    rpc: RpcArgs,
}

pub async fn run(bundler_args: NodeCliArgs, common_args: CommonArgs) -> anyhow::Result<()> {
    let NodeCliArgs {
        pool: pool_args,
        builder: builder_args,
        rpc: rpc_args,
    } = bundler_args;

    let builder_url = builder_args.url(false);

    let (tx, rx) = mpsc::channel(1024);

    let pool_task_args = pool_args
        .to_args(&common_args, PoolServerMode::Local { receiver: Some(rx) })
        .await?;
    let builder_task_args = builder_args
        .to_args(&common_args, PoolClientMode::Local { sender: tx.clone() })
        .await?;
    let rpc_task_args = rpc_args
        .to_args(
            &common_args,
            builder_url,
            (&common_args).try_into()?,
            PoolClientMode::Local { sender: tx.clone() },
        )
        .await?;

    handle::spawn_tasks_with_shutdown(
        [
            PoolTask::new(pool_task_args).boxed(),
            BuilderTask::new(builder_task_args).boxed(),
            RpcTask::new(rpc_task_args).boxed(),
        ],
        tokio::signal::ctrl_c(),
    )
    .await;

    Ok(())
}
