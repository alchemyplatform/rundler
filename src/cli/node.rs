use clap::Args;

use super::{builder::BuilderArgs, pool::PoolArgs, rpc::RpcArgs, CommonArgs};
use crate::{
    builder::BuilderTask,
    common::{handle, server::format_server_addr},
    op_pool::PoolTask,
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

    let pool_url = format_server_addr(&pool_args.host, pool_args.port, false);
    let builder_url = builder_args.url(false);

    let pool_task_args = pool_args.to_args(&common_args).await?;
    let builder_task_args = builder_args.to_args(&common_args, pool_url.clone()).await?;
    let rpc_task_args = rpc_args
        .to_args(
            &common_args,
            pool_url,
            builder_url,
            (&common_args).try_into()?,
            (&common_args).into(),
            (&common_args).try_into()?,
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
