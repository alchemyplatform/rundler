use clap::Args;
use tokio::sync::{broadcast, mpsc};

use super::{builder::BuilderArgs, pool::PoolArgs, rpc::RpcArgs, CommonArgs};
use crate::{
    builder::{BuilderServerMode, BuilderTask},
    common::handle,
    op_pool::{PoolClientMode, PoolServerMode, PoolTask},
    rpc::{ClientMode, RpcTask},
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

    let (pool_sender, pool_rx) = mpsc::channel(1024);
    let (pool_block_sender, pool_block_receiver) = broadcast::channel(1024);
    let (builder_sender, builder_rx) = mpsc::channel(1024);

    let pool_task_args = pool_args
        .to_args(
            &common_args,
            PoolServerMode::Local {
                req_receiver: Some(pool_rx),
                block_sender: Some(pool_block_sender),
            },
        )
        .await?;
    let builder_task_args = builder_args
        .to_args(
            &common_args,
            PoolClientMode::Local {
                sender: pool_sender.clone(),
                block_receiver: pool_block_receiver.resubscribe(),
            },
            BuilderServerMode::Local {
                req_receiver: Some(builder_rx),
            },
        )
        .await?;
    let rpc_task_args = rpc_args
        .to_args(
            &common_args,
            (&common_args).try_into()?,
            ClientMode::Local {
                pool_sender,
                pool_block_receiver,
                builder_sender,
            },
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
