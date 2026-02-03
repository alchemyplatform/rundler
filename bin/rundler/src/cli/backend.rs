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

//! Backend command that runs both pool and builder together with gRPC endpoints exposed.
//!
//! This is useful for running a single-chain backend that the gateway can connect to.

use std::sync::Arc;

use clap::Args;
use rundler_builder::{BuilderEvent, BuilderEventKind, BuilderTask, LocalBuilderBuilder};
use rundler_pool::{LocalPoolBuilder, PoolEvent, PoolTask};
use rundler_provider::Providers;
use rundler_sim::MempoolConfigs;
use rundler_task::{TaskSpawnerExt, server::format_socket_addr};
use rundler_types::chain::ChainSpec;
use rundler_utils::emit::{self, EVENT_CHANNEL_CAPACITY, WithEntryPoint};
use tokio::sync::broadcast;

use super::{CommonArgs, EntryPointBuilderConfigs, builder::BuilderArgs, pool::PoolArgs};

const REQUEST_CHANNEL_CAPACITY: usize = 1024;
const BLOCK_CHANNEL_CAPACITY: usize = 1024;

/// CLI options for the Backend command (pool + builder with gRPC)
#[derive(Debug, Args)]
pub struct BackendCliArgs {
    #[command(flatten)]
    pool: PoolArgs,

    #[command(flatten)]
    builder: BuilderArgs,
}

/// Spawn backend tasks (pool + builder with gRPC endpoints exposed).
///
/// This runs both the pool and builder in the same process, with:
/// - Pool exposing gRPC on pool.host:pool.port
/// - Builder exposing gRPC on builder.host:builder.port
/// - Builder using local pool handle internally (not gRPC)
///
/// Note: Pool and builder must use different ports. By default both use 50051,
/// so you must specify different ports, e.g.:
///   --pool.port 50051 --builder.port 50052
pub async fn spawn_tasks<T: TaskSpawnerExt + 'static>(
    task_spawner: T,
    chain_spec: ChainSpec,
    backend_args: BackendCliArgs,
    common_args: CommonArgs,
    providers: impl Providers + 'static,
    mempool_configs: Option<MempoolConfigs>,
    entry_point_builders: Option<EntryPointBuilderConfigs>,
) -> anyhow::Result<()> {
    let BackendCliArgs {
        pool: pool_args,
        builder: builder_args,
    } = backend_args;

    if pool_args.host == builder_args.host && pool_args.port == builder_args.port {
        anyhow::bail!(
            "Pool and builder cannot use the same address ({}:{}). \
             Please specify different ports, e.g.: --pool.port 50051 --builder.port 50052",
            pool_args.host,
            pool_args.port
        );
    }

    let pool_remote_address = format_socket_addr(&pool_args.host, pool_args.port).parse()?;
    let pool_task_args = pool_args
        .to_args(
            chain_spec.clone(),
            &common_args,
            Some(pool_remote_address),
            mempool_configs.clone(),
        )
        .await?;

    let builder_remote_address =
        format_socket_addr(&builder_args.host, builder_args.port).parse()?;
    let builder_task_args = builder_args
        .to_args(
            chain_spec.clone(),
            &common_args,
            Some(builder_remote_address),
            mempool_configs,
            entry_point_builders,
        )
        .await?;

    let (pool_event_sender, pool_event_rx) =
        broadcast::channel::<WithEntryPoint<PoolEvent>>(EVENT_CHANNEL_CAPACITY);
    let (builder_event_sender, builder_event_rx) =
        broadcast::channel::<WithEntryPoint<BuilderEvent>>(EVENT_CHANNEL_CAPACITY);

    task_spawner.spawn_critical(
        "recv and log pool events",
        Box::pin(emit::receive_and_log_events_with_filter(
            pool_event_rx,
            |_| true,
        )),
    );
    task_spawner.spawn_critical(
        "recv and log builder events",
        Box::pin(emit::receive_and_log_events_with_filter(
            builder_event_rx,
            is_nonspammy_event,
        )),
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

    tracing::info!(
        "Starting pool with gRPC on {}:{}",
        pool_args.host,
        pool_args.port
    );
    PoolTask::new(
        pool_task_args,
        pool_event_sender,
        pool_builder,
        providers.clone(),
    )
    .spawn(task_spawner.clone())
    .await?;

    tracing::info!(
        "Starting builder with gRPC on {}:{}",
        builder_args.host,
        builder_args.port
    );
    BuilderTask::new(
        builder_task_args,
        builder_event_sender,
        builder_builder,
        pool_handle,
        providers,
        signer_manager,
    )
    .spawn(task_spawner)
    .await?;

    tracing::info!("Backend started with pool and builder gRPC endpoints exposed");

    Ok(())
}

fn is_nonspammy_event(event: &WithEntryPoint<BuilderEvent>) -> bool {
    if let BuilderEventKind::FormedBundle {
        tx_details,
        fee_increase_count,
        ..
    } = &event.event.kind
        && tx_details.is_none()
        && *fee_increase_count == 0
    {
        return false;
    }
    true
}
