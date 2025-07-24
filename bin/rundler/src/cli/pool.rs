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

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use alloy_primitives::Address;
use anyhow::Context;
use clap::Args;
use rundler_pool::{LocalPoolBuilder, PoolConfig, PoolTask, PoolTaskArgs};
use rundler_provider::Providers;
use rundler_sim::MempoolConfigs;
use rundler_task::TaskSpawnerExt;
use rundler_types::{
    chain::{ChainSpec, TryIntoWithSpec},
    EntryPointVersion,
};
use rundler_utils::emit::{self, EVENT_CHANNEL_CAPACITY};
use tokio::sync::broadcast;

use super::CommonArgs;
use crate::cli::json::get_json_config;

const BLOCK_CHANNEL_CAPACITY: usize = 1024;

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
        long = "pool.same_sender_mempool_count",
        name = "pool.same_sender_mempool_count",
        env = "SAME_SENDER_MEMPOOL_COUNT",
        default_value = "4"
    )]
    pub same_sender_mempool_count: usize,

    #[arg(
        long = "pool.min_replacement_fee_increase_percentage",
        name = "pool.min_replacement_fee_increase_percentage",
        env = "POOL_MIN_REPLACEMENT_FEE_INCREASE_PERCENTAGE",
        default_value = "10"
    )]
    pub min_replacement_fee_increase_percentage: u32,

    #[arg(
        long = "pool.blocklist_path",
        name = "pool.blocklist_path",
        env = "POOL_BLOCKLIST_PATH"
    )]
    pub blocklist_path: Option<String>,

    #[arg(
        long = "pool.allowlist_path",
        name = "pool.allowlist_path",
        env = "POOL_ALLOWLIST_PATH"
    )]
    pub allowlist_path: Option<String>,

    /// Interval at which the pool polls an Eth node for new blocks
    #[arg(
        long = "pool.chain_poll_interval_millis",
        name = "pool.chain_poll_interval_millis",
        env = "POOL_CHAIN_POLL_INTERVAL_MILLIS",
        default_value = "100",
        global = true
    )]
    pub chain_poll_interval_millis: u64,

    /// The amount of times to retry syncing the chain before giving up and
    /// waiting for the next block.
    #[arg(
        long = "pool.chain_sync_max_retries",
        name = "pool.chain_sync_max_retries",
        env = "POOL_CHAIN_SYNC_MAX_RETRIES",
        default_value = "5",
        global = true
    )]
    pub chain_sync_max_retries: u64,

    #[arg(
        long = "pool.chain_update_channel_capacity",
        name = "pool.chain_update_channel_capacity",
        env = "POOL_CHAIN_UPDATE_CHANNEL_CAPACITY"
    )]
    pub chain_update_channel_capacity: Option<usize>,

    #[arg(
        long = "pool.throttled_entity_mempool_count",
        name = "pool.throttled_entity_mempool_count",
        env = "POOL_THROTTLED_ENTITY_MEMPOOL_COUNT",
        default_value = "4"
    )]
    pub throttled_entity_mempool_count: u64,

    #[arg(
        long = "pool.throttled_entity_live_blocks",
        name = "pool.throttled_entity_live_blocks",
        env = "POOL_THROTTLED_ENTITY_LIVE_BLOCKS",
        default_value = "10"
    )]
    pub throttled_entity_live_blocks: u64,

    #[arg(
        long = "pool.paymaster_tracking_enabled",
        name = "pool.paymaster_tracking_enabled",
        env = "POOL_PAYMASTER_TRACKING_ENABLED",
        default_value = "true"
    )]
    pub paymaster_tracking_enabled: bool,

    #[arg(
        long = "pool.paymaster_cache_length",
        name = "pool.paymaster_cache_length",
        env = "POOL_PAYMASTER_CACHE_LENGTH",
        default_value = "10000"
    )]
    pub paymaster_cache_length: u32,

    #[arg(
        long = "pool.reputation_tracking_enabled",
        name = "pool.reputation_tracking_enabled",
        env = "POOL_REPUTATION_TRACKING_ENABLED",
        default_value = "true"
    )]
    pub reputation_tracking_enabled: bool,

    #[arg(
        long = "pool.drop_min_num_blocks",
        name = "pool.drop_min_num_blocks",
        env = "POOL_DROP_MIN_NUM_BLOCKS",
        default_value = "10"
    )]
    pub drop_min_num_blocks: u64,

    #[arg(
        long = "pool.max_time_in_pool_secs",
        name = "pool.max_time_in_pool_secs",
        env = "POOL_MAX_TIME_IN_POOL_SECS"
    )]
    pub max_time_in_pool_secs: Option<u64>,
}

impl PoolArgs {
    /// Convert the CLI arguments into the arguments for the OP Pool combining
    /// common and op pool specific arguments.
    pub async fn to_args(
        &self,
        chain_spec: ChainSpec,
        common: &CommonArgs,
        remote_address: Option<SocketAddr>,
        mempool_configs: Option<MempoolConfigs>,
    ) -> anyhow::Result<PoolTaskArgs> {
        let blocklist = match &self.blocklist_path {
            Some(blocklist) => Some(get_json_config(blocklist).await?),
            None => None,
        };
        let allowlist = match &self.allowlist_path {
            Some(allowlist) => Some(get_json_config(allowlist).await?),
            None => None,
        };
        tracing::info!("blocklist: {:?}", blocklist);
        tracing::info!("allowlist: {:?}", allowlist);

        let mempool_channel_configs = mempool_configs.unwrap_or_default();

        let da_gas_tracking_enabled =
            super::lint_da_gas_tracking(common.da_gas_tracking_enabled, &chain_spec);

        let pool_config_base = PoolConfig {
            // update per entry point
            entry_point: Address::ZERO,
            entry_point_version: EntryPointVersion::Unspecified,
            mempool_channel_configs: HashMap::new(),
            // Base config
            chain_spec: chain_spec.clone(),
            same_sender_mempool_count: self.same_sender_mempool_count,
            min_replacement_fee_increase_percentage: self.min_replacement_fee_increase_percentage,
            max_size_of_pool_bytes: self.max_size_in_bytes,
            blocklist: blocklist.clone(),
            allowlist: allowlist.clone(),
            precheck_settings: common.try_into_with_spec(&chain_spec)?,
            sim_settings: common.try_into()?,
            throttled_entity_mempool_count: self.throttled_entity_mempool_count,
            throttled_entity_live_blocks: self.throttled_entity_live_blocks,
            paymaster_tracking_enabled: self.paymaster_tracking_enabled,
            paymaster_cache_length: self.paymaster_cache_length,
            reputation_tracking_enabled: self.reputation_tracking_enabled,
            drop_min_num_blocks: self.drop_min_num_blocks,
            da_gas_tracking_enabled,
            execution_gas_limit_efficiency_reject_threshold: common
                .execution_gas_limit_efficiency_reject_threshold,
            verification_gas_limit_efficiency_reject_threshold: common
                .verification_gas_limit_efficiency_reject_threshold,
            max_time_in_pool: self.max_time_in_pool_secs.map(Duration::from_secs),
            max_expected_storage_slots: common.max_expected_storage_slots.unwrap_or(usize::MAX),
        };

        let mut pool_configs = vec![];

        if !common.disable_entry_point_v0_6 {
            pool_configs.push(PoolConfig {
                entry_point: chain_spec.entry_point_address_v0_6,
                entry_point_version: EntryPointVersion::V0_6,
                mempool_channel_configs: mempool_channel_configs
                    .get_for_entry_point(chain_spec.entry_point_address_v0_6),
                ..pool_config_base.clone()
            });
        }
        if !common.disable_entry_point_v0_7 {
            pool_configs.push(PoolConfig {
                entry_point: chain_spec.entry_point_address_v0_7,
                entry_point_version: EntryPointVersion::V0_7,
                mempool_channel_configs: mempool_channel_configs
                    .get_for_entry_point(chain_spec.entry_point_address_v0_7),
                ..pool_config_base.clone()
            });
        }

        Ok(PoolTaskArgs {
            chain_spec,
            unsafe_mode: common.unsafe_mode,
            http_url: common.node_http.clone().context("must provide node_http")?,
            chain_poll_interval: Duration::from_millis(self.chain_poll_interval_millis),
            chain_max_sync_retries: self.chain_sync_max_retries,
            pool_configs,
            remote_address,
            chain_update_channel_capacity: self.chain_update_channel_capacity.unwrap_or(1024),
        })
    }
}

/// CLI options for the Pool server standalone
#[derive(Args, Debug)]
pub struct PoolCliArgs {
    #[command(flatten)]
    pool: PoolArgs,
}

pub async fn spawn_tasks<T: TaskSpawnerExt + 'static>(
    task_spawner: T,
    chain_spec: ChainSpec,
    pool_args: PoolCliArgs,
    common_args: CommonArgs,
    providers: impl Providers + 'static,
    mempool_configs: Option<MempoolConfigs>,
) -> anyhow::Result<()> {
    let PoolCliArgs { pool: pool_args } = pool_args;
    let (event_sender, event_rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
    let task_args = pool_args
        .to_args(
            chain_spec.clone(),
            &common_args,
            Some(format!("{}:{}", pool_args.host, pool_args.port).parse()?),
            mempool_configs,
        )
        .await?;

    task_spawner.spawn_critical(
        "recv and log events",
        Box::pin(emit::receive_and_log_events_with_filter(event_rx, |_| true)),
    );

    PoolTask::new(
        task_args,
        event_sender,
        LocalPoolBuilder::new(BLOCK_CHANNEL_CAPACITY),
        providers,
    )
    .spawn(task_spawner)
    .await?;

    Ok(())
}
