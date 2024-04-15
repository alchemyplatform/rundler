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
use ethers::types::H256;
use rundler_builder::{
    self, BuilderEvent, BuilderEventKind, BuilderTask, BuilderTaskArgs, LocalBuilderBuilder,
    TransactionSenderType,
};
use rundler_pool::RemotePoolClient;
use rundler_sim::{MempoolConfig, PriorityFeeMode};
use rundler_task::{
    server::{connect_with_retries_shutdown, format_socket_addr},
    spawn_tasks_with_shutdown,
};
use rundler_types::chain::ChainSpec;
use rundler_utils::emit::{self, WithEntryPoint, EVENT_CHANNEL_CAPACITY};
use tokio::sync::broadcast;

use super::{json::get_json_config, CommonArgs};

const REQUEST_CHANNEL_CAPACITY: usize = 1024;

/// CLI options for the builder
#[derive(Args, Debug)]
#[command(next_help_heading = "BUILDER")]
pub struct BuilderArgs {
    /// Port to listen on for gRPC requests
    #[arg(
        long = "builder.port",
        name = "builder.port",
        env = "BUILDER_PORT",
        default_value = "50051"
    )]
    port: u16,

    /// Host to listen on for gRPC requests
    #[arg(
        long = "builder.host",
        name = "builder.host",
        env = "BUILDER_HOST",
        default_value = "127.0.0.1"
    )]
    host: String,

    /// Private key to use for signing transactions
    #[arg(
        long = "builder.private_key",
        name = "builder.private_key",
        env = "BUILDER_PRIVATE_KEY"
    )]
    private_key: Option<String>,

    /// AWS KMS key IDs to use for signing transactions
    #[arg(
        long = "builder.aws_kms_key_ids",
        name = "builder.aws_kms_key_ids",
        env = "BUILDER_AWS_KMS_KEY_IDS",
        value_delimiter = ','
    )]
    aws_kms_key_ids: Vec<String>,

    /// Redis URI to use for KMS leasing
    #[arg(
        long = "builder.redis_uri",
        name = "builder.redis_uri",
        env = "BUILDER_REDIS_URI",
        default_value = ""
    )]
    redis_uri: String,

    /// Redis lock TTL in milliseconds
    #[arg(
        long = "builder.redis_lock_ttl_millis",
        name = "builder.redis_lock_ttl_millis",
        env = "BUILDER_REDIS_LOCK_TTL_MILLIS",
        default_value = "60000"
    )]
    redis_lock_ttl_millis: u64,

    /// Maximum number of ops to include in one bundle.
    #[arg(
        long = "builder.max_bundle_size",
        name = "builder.max_bundle_size",
        env = "BUILDER_MAX_BUNDLE_SIZE",
        default_value = "128"
    )]
    max_bundle_size: u64,

    /// If present, the url of the ETH provider that will be used to send
    /// transactions. Defaults to the value of `node_http`.
    #[arg(
        long = "builder.submit_url",
        name = "builder.submit_url",
        env = "BUILDER_SUBMIT_URL"
    )]
    pub submit_url: Option<String>,

    /// Choice of what sender type to use for transaction submission.
    /// Defaults to the value of `raw`. Other options inclue `flashbots`,
    /// `conditional` and `polygon_bloxroute`
    #[arg(
        long = "builder.sender",
        name = "builder.sender",
        env = "BUILDER_SENDER",
        value_enum,
        default_value = "raw"
    )]
    pub sender_type: TransactionSenderType,

    /// After submitting a bundle transaction, the maximum number of blocks to
    /// wait for that transaction to mine before we try resending with higher
    /// gas fees.
    #[arg(
        long = "builder.max_blocks_to_wait_for_mine",
        name = "builder.max_blocks_to_wait_for_mine",
        env = "BUILDER_MAX_BLOCKS_TO_WAIT_FOR_MINE",
        default_value = "2"
    )]
    max_blocks_to_wait_for_mine: u64,

    /// Percentage amount to increase gas fees when retrying a transaction after
    /// it failed to mine.
    #[arg(
        long = "builder.replacement_fee_percent_increase",
        name = "builder.replacement_fee_percent_increase",
        env = "BUILDER_REPLACEMENT_FEE_PERCENT_INCREASE",
        default_value = "10"
    )]
    replacement_fee_percent_increase: u64,

    /// Maximum number of times to increase gas fees when retrying a transaction
    /// before giving up.
    #[arg(
        long = "builder.max_fee_increases",
        name = "builder.max_fee_increases",
        env = "BUILDER_MAX_FEE_INCREASES",
        // Seven increases of 10% is roughly 2x the initial fees.
        default_value = "7"
    )]
    max_fee_increases: u64,

    /// If using Polygon Mainnet, the auth header to use
    /// for Bloxroute polygon_private_tx sender
    #[arg(
        long = "builder.bloxroute_auth_header",
        name = "builder.bloxroute_auth_header",
        env = "BUILDER_BLOXROUTE_AUTH_HEADER"
    )]
    bloxroute_auth_header: Option<String>,
    /// The index offset to apply to the builder index
    #[arg(
        long = "builder_index_offset",
        name = "builder_index_offset",
        env = "BUILDER_INDEX_OFFSET",
        default_value = "0"
    )]
    pub builder_index_offset: u64,
}

impl BuilderArgs {
    /// Convert the CLI arguments into the arguments for the builder combining
    /// common and builder specific arguments.
    pub async fn to_args(
        &self,
        chain_spec: ChainSpec,
        common: &CommonArgs,
        remote_address: Option<SocketAddr>,
    ) -> anyhow::Result<BuilderTaskArgs> {
        let priority_fee_mode = PriorityFeeMode::try_from(
            common.priority_fee_mode_kind.as_str(),
            common.priority_fee_mode_value,
        )?;

        let rpc_url = common
            .node_http
            .clone()
            .context("should have a node HTTP URL")?;
        let submit_url = self.submit_url.clone().unwrap_or_else(|| rpc_url.clone());

        let mempool_configs = match &common.mempool_config_path {
            Some(path) => {
                get_json_config::<HashMap<H256, MempoolConfig>>(path, &common.aws_region).await?
            }
            None => HashMap::from([(H256::zero(), MempoolConfig::default())]),
        };

        Ok(BuilderTaskArgs {
            chain_spec,
            rpc_url,
            private_key: self.private_key.clone(),
            aws_kms_key_ids: self.aws_kms_key_ids.clone(),
            aws_kms_region: common
                .aws_region
                .parse()
                .context("should be a valid aws region")?,
            redis_uri: self.redis_uri.clone(),
            redis_lock_ttl_millis: self.redis_lock_ttl_millis,
            max_bundle_size: self.max_bundle_size,
            max_bundle_gas: common.max_bundle_gas,
            submit_url,
            bundle_priority_fee_overhead_percent: common.bundle_priority_fee_overhead_percent,
            priority_fee_mode,
            sender_type: self.sender_type,
            eth_poll_interval: Duration::from_millis(common.eth_poll_interval_millis),
            sim_settings: common.into(),
            mempool_configs,
            max_blocks_to_wait_for_mine: self.max_blocks_to_wait_for_mine,
            replacement_fee_percent_increase: self.replacement_fee_percent_increase,
            max_fee_increases: self.max_fee_increases,
            remote_address,
            bloxroute_auth_header: self.bloxroute_auth_header.clone(),
            num_bundle_builders: common.num_builders,
            bundle_builder_index_offset: self.builder_index_offset,
        })
    }
}

/// CLI options for the Builder server standalone
#[derive(Args, Debug)]
pub struct BuilderCliArgs {
    #[command(flatten)]
    builder: BuilderArgs,

    #[arg(
        long = "builder.pool_url",
        name = "builder.pool_url",
        env = "BUILDER_POOL_URL",
        default_value = "http://localhost:50051",
        global = true
    )]
    pool_url: String,
}

pub async fn run(
    chain_spec: ChainSpec,
    builder_args: BuilderCliArgs,
    common_args: CommonArgs,
) -> anyhow::Result<()> {
    let BuilderCliArgs {
        builder: builder_args,
        pool_url,
    } = builder_args;

    let (event_sender, event_rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
    emit::receive_and_log_events_with_filter(event_rx, is_nonspammy_event);

    let task_args = builder_args
        .to_args(
            chain_spec,
            &common_args,
            Some(format_socket_addr(&builder_args.host, builder_args.port).parse()?),
        )
        .await?;

    let pool = connect_with_retries_shutdown(
        "op pool from builder",
        &pool_url,
        RemotePoolClient::connect,
        tokio::signal::ctrl_c(),
    )
    .await?;

    spawn_tasks_with_shutdown(
        [BuilderTask::new(
            task_args,
            event_sender,
            LocalBuilderBuilder::new(REQUEST_CHANNEL_CAPACITY),
            pool,
        )
        .boxed()],
        tokio::signal::ctrl_c(),
    )
    .await;
    Ok(())
}

pub fn is_nonspammy_event(event: &WithEntryPoint<BuilderEvent>) -> bool {
    if let BuilderEventKind::FormedBundle {
        tx_details,
        fee_increase_count,
        ..
    } = &event.event.kind
    {
        if tx_details.is_none() && *fee_increase_count == 0 {
            return false;
        }
    }
    true
}
