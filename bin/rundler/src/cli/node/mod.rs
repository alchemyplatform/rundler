// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use std::sync::Arc;

use clap::Args;
use rundler_builder::{BuilderEvent, BuilderTask, LocalBuilderBuilder};
use rundler_pool::{LocalPoolBuilder, PoolEvent, PoolTask};
use rundler_provider::Providers;
use rundler_rpc::RpcTask;
use rundler_sim::MempoolConfigs;
use rundler_task::TaskSpawnerExt;
use rundler_types::chain::ChainSpec;
use rundler_utils::emit::{self, WithEntryPoint, EVENT_CHANNEL_CAPACITY};
use tokio::sync::broadcast;

use self::events::Event;
use super::EntryPointBuilderConfigs;
use crate::cli::{
    builder::{self, BuilderArgs},
    pool::PoolArgs,
    rpc::RpcArgs,
    CommonArgs,
};
mod events;

const REQUEST_CHANNEL_CAPACITY: usize = 1024;
const BLOCK_CHANNEL_CAPACITY: usize = 1024;

#[derive(Debug, Args)]
pub struct NodeCliArgs {
    #[command(flatten)]
    pool: PoolArgs,

    #[command(flatten)]
    builder: BuilderArgs,

    #[command(flatten)]
    rpc: RpcArgs,
}

pub async fn spawn_tasks<T: TaskSpawnerExt + 'static>(
    task_spawner: T,
    chain_spec: ChainSpec,
    bundler_args: NodeCliArgs,
    common_args: CommonArgs,
    providers: impl Providers + 'static,
    mempool_configs: Option<MempoolConfigs>,
    entry_point_builders: Option<EntryPointBuilderConfigs>,
) -> anyhow::Result<()> {
    let _ = mempool_configs;
    let NodeCliArgs {
        pool: pool_args,
        builder: builder_args,
        rpc: rpc_args,
    } = bundler_args;

    let pool_task_args = pool_args
        .to_args(
            chain_spec.clone(),
            &common_args,
            None,
            mempool_configs.clone(),
        )
        .await?;
    let builder_task_args = builder_args
        .to_args(
            chain_spec.clone(),
            &common_args,
            None,
            mempool_configs,
            entry_point_builders,
        )
        .await?;
    let rpc_task_args = rpc_args.to_args(chain_spec.clone(), &common_args)?;

    let (event_sender, event_rx) =
        broadcast::channel::<WithEntryPoint<Event>>(EVENT_CHANNEL_CAPACITY);
    let (op_pool_event_sender, op_pool_event_rx) =
        broadcast::channel::<WithEntryPoint<PoolEvent>>(EVENT_CHANNEL_CAPACITY);
    let (builder_event_sender, builder_event_rx) =
        broadcast::channel::<WithEntryPoint<BuilderEvent>>(EVENT_CHANNEL_CAPACITY);

    task_spawner.spawn_critical(
        "recv and log events",
        Box::pin(emit::receive_and_log_events_with_filter(event_rx, |_| true)),
    );
    task_spawner.spawn_critical(
        "recv op pool events",
        Box::pin(emit::receive_events("op pool", op_pool_event_rx, {
            let event_sender = event_sender.clone();
            move |event| {
                let _ = event_sender.send(WithEntryPoint::of(event));
            }
        })),
    );
    task_spawner.spawn_critical(
        "recv builder events",
        Box::pin(emit::receive_events("builder", builder_event_rx, {
            let event_sender = event_sender.clone();
            move |event| {
                if builder::is_nonspammy_event(&event) {
                    let _ = event_sender.send(WithEntryPoint::of(event));
                }
            }
        })),
    );

    let pool_builder = LocalPoolBuilder::new(BLOCK_CHANNEL_CAPACITY);
    let pool_handle = pool_builder.get_handle();

    let signer_manager = rundler_signer::new_signer_manager(
        &builder_task_args.signing_scheme,
        builder_task_args.auto_fund,
        &chain_spec,
        providers.evm().clone(),
        providers.da_gas_oracle().clone(),
        &task_spawner,
    )
    .await?;

    let builder_builder = LocalBuilderBuilder::new(
        REQUEST_CHANNEL_CAPACITY,
        signer_manager.clone(),
        Arc::new(pool_handle.clone()),
    );
    let builder_handle = builder_builder.get_handle();

    PoolTask::new(
        pool_task_args,
        op_pool_event_sender,
        pool_builder,
        providers.clone(),
    )
    .spawn(task_spawner.clone())
    .await?;

    BuilderTask::new(
        builder_task_args,
        builder_event_sender,
        builder_builder,
        pool_handle.clone(),
        providers.clone(),
        signer_manager,
    )
    .spawn(task_spawner.clone())
    .await?;

    RpcTask::new(rpc_task_args, pool_handle, builder_handle, providers)
        .spawn(task_spawner)
        .await?;

    Ok(())
}
