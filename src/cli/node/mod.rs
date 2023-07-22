use clap::Args;
use tokio::sync::{broadcast, mpsc};

use self::events::Event;
use crate::{
    builder::{emit::BuilderEvent, BuilderTask},
    cli::{
        builder::{self, BuilderArgs},
        pool::PoolArgs,
        rpc::RpcArgs,
        CommonArgs,
    },
    common::{
        emit::{self, WithEntryPoint, EVENT_CHANNEL_CAPACITY},
        handle,
    },
    op_pool::{emit::OpPoolEvent, PoolClientMode, PoolServerMode, PoolTask},
    rpc::RpcTask,
};
mod events;

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
    let (new_heads_sender, _) = broadcast::channel(1024);

    let pool_task_args = pool_args
        .to_args(
            &common_args,
            PoolServerMode::Local {
                req_receiver: Some(rx),
                new_heads_sender: Some(new_heads_sender.clone()),
            },
        )
        .await?;
    let builder_task_args = builder_args
        .to_args(
            &common_args,
            PoolClientMode::Local {
                req_sender: tx.clone(),
                new_heads_receiver: new_heads_sender.subscribe(),
            },
        )
        .await?;
    let rpc_task_args = rpc_args
        .to_args(
            &common_args,
            builder_url,
            (&common_args).try_into()?,
            (&common_args).try_into()?,
            PoolClientMode::Local {
                req_sender: tx,
                new_heads_receiver: new_heads_sender.subscribe(),
            },
        )
        .await?;

    let (event_sender, event_rx) =
        broadcast::channel::<WithEntryPoint<Event>>(EVENT_CHANNEL_CAPACITY);
    let (op_pool_event_sender, op_pool_event_rx) =
        broadcast::channel::<WithEntryPoint<OpPoolEvent>>(EVENT_CHANNEL_CAPACITY);
    let (builder_event_sender, builder_event_rx) =
        broadcast::channel::<WithEntryPoint<BuilderEvent>>(EVENT_CHANNEL_CAPACITY);

    emit::receive_and_log_events_with_filter(event_rx, |_| true);
    emit::receive_events("op pool", op_pool_event_rx, {
        let event_sender = event_sender.clone();
        move |event| {
            let _ = event_sender.send(WithEntryPoint::of(event));
        }
    });
    emit::receive_events("builder", builder_event_rx, {
        let event_sender = event_sender.clone();
        move |event| {
            if builder::is_nonspammy_event(&event) {
                let _ = event_sender.send(WithEntryPoint::of(event));
            }
        }
    });

    handle::spawn_tasks_with_shutdown(
        [
            PoolTask::new(pool_task_args, op_pool_event_sender).boxed(),
            BuilderTask::new(builder_task_args, builder_event_sender).boxed(),
            RpcTask::new(rpc_task_args).boxed(),
        ],
        tokio::signal::ctrl_c(),
    )
    .await;

    Ok(())
}
