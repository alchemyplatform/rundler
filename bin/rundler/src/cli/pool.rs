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

use anyhow::Context;
use clap::Args;
use ethers::types::{Chain, H256};
use rundler_pool::{LocalPoolBuilder, PoolConfig, PoolTask, PoolTaskArgs};
use rundler_sim::MempoolConfig;
use rundler_task::spawn_tasks_with_shutdown;
use rundler_utils::emit::{self, EVENT_CHANNEL_CAPACITY};
use tokio::sync::broadcast;

use super::CommonArgs;
use crate::cli::json::get_json_config;

const REQUEST_CHANNEL_CAPACITY: usize = 1024;
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
    pub min_replacement_fee_increase_percentage: u64,

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

    #[arg(
        long = "pool.chain_history_size",
        name = "pool.chain_history_size",
        env = "POOL_CHAIN_HISTORY_SIZE"
    )]
    pub chain_history_size: Option<u64>,

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
}

impl PoolArgs {
    /// Convert the CLI arguments into the arguments for the OP Pool combining
    /// common and op pool specific arguments.
    pub async fn to_args(
        &self,
        common: &CommonArgs,
        remote_address: Option<SocketAddr>,
    ) -> anyhow::Result<PoolTaskArgs> {
        let blocklist = match &self.blocklist_path {
            Some(blocklist) => Some(get_json_config(blocklist, &common.aws_region).await?),
            None => None,
        };
        let allowlist = match &self.allowlist_path {
            Some(allowlist) => Some(get_json_config(allowlist, &common.aws_region).await?),
            None => None,
        };
        tracing::info!("blocklist: {:?}", blocklist);
        tracing::info!("allowlist: {:?}", allowlist);

        let mempool_channel_configs = match &common.mempool_config_path {
            Some(path) => {
                get_json_config::<HashMap<H256, MempoolConfig>>(path, &common.aws_region).await?
            }
            None => HashMap::from([(H256::zero(), MempoolConfig::default())]),
        };
        tracing::info!("Mempool channel configs: {:?}", mempool_channel_configs);

        let pool_configs = common
            .entry_points
            .iter()
            .map(|ep| {
                let entry_point = ep.parse().context("Invalid entry_points argument")?;
                Ok(PoolConfig {
                    entry_point,
                    chain_id: common.chain_id,
                    // Currently use the same shard count as the number of builders
                    num_shards: common.num_builders,
                    same_sender_mempool_count: self.same_sender_mempool_count,
                    min_replacement_fee_increase_percentage: self
                        .min_replacement_fee_increase_percentage,
                    max_size_of_pool_bytes: self.max_size_in_bytes,
                    blocklist: blocklist.clone(),
                    allowlist: allowlist.clone(),
                    precheck_settings: common.try_into()?,
                    sim_settings: common.into(),
                    mempool_channel_configs: mempool_channel_configs.clone(),
                    throttled_entity_mempool_count: self.throttled_entity_mempool_count,
                    throttled_entity_live_blocks: self.throttled_entity_live_blocks,
                })
            })
            .collect::<anyhow::Result<Vec<PoolConfig>>>()?;

        Ok(PoolTaskArgs {
            chain_id: common.chain_id,
            chain_history_size: self
                .chain_history_size
                .unwrap_or_else(|| default_chain_history_size(common.chain_id)),
            http_url: common
                .node_http
                .clone()
                .context("pool requires node_http arg")?,
            http_poll_interval: Duration::from_millis(common.eth_poll_interval_millis),
            pool_configs,
            remote_address,
            chain_update_channel_capacity: self.chain_update_channel_capacity.unwrap_or(1024),
        })
    }
}

const SMALL_HISTORY_SIZE: u64 = 16;
const LARGE_HISTORY_SIZE: u64 = 128;

// Mainnets that are known to not have large reorgs can use the small history
// size. Use the large history size for all testnets because I don't trust them.
const SMALL_HISTORY_CHAIN_IDS: &[u64] = &[
    Chain::Mainnet as u64,
    Chain::Arbitrum as u64,
    Chain::Optimism as u64,
];

fn default_chain_history_size(chain_id: u64) -> u64 {
    if SMALL_HISTORY_CHAIN_IDS.contains(&chain_id) {
        SMALL_HISTORY_SIZE
    } else {
        LARGE_HISTORY_SIZE
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
    let (event_sender, event_rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
    let task_args = pool_args
        .to_args(
            &common_args,
            Some(format!("{}:{}", pool_args.host, pool_args.port).parse()?),
        )
        .await?;

    emit::receive_and_log_events_with_filter(event_rx, |_| true);

    spawn_tasks_with_shutdown(
        [PoolTask::new(
            task_args,
            event_sender,
            LocalPoolBuilder::new(REQUEST_CHANNEL_CAPACITY, BLOCK_CHANNEL_CAPACITY),
        )
        .boxed()],
        tokio::signal::ctrl_c(),
    )
    .await;
    Ok(())
}
