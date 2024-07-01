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

use std::net::SocketAddr;

use anyhow::{bail, Context};
use clap::Args;
use rundler_builder::{
    self, BloxrouteSenderArgs, BuilderEvent, BuilderEventKind, BuilderTask, BuilderTaskArgs,
    EntryPointBuilderSettings, FlashbotsSenderArgs, LocalBuilderBuilder, RawSenderArgs,
    TransactionSenderArgs, TransactionSenderKind,
};
use rundler_pool::RemotePoolClient;
use rundler_sim::{MempoolConfigs, PriorityFeeMode};
use rundler_task::{
    server::{connect_with_retries_shutdown, format_socket_addr},
    spawn_tasks_with_shutdown,
};
use rundler_types::{chain::ChainSpec, EntryPointVersion};
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
    /// DEPRECATED: Use `builder.private_keys` instead
    ///
    /// If both `builder.private_key` and `builder.private_keys` are set, `builder.private_key` is appended
    /// to `builder.private_keys`. Keys must be unique.
    #[arg(
        long = "builder.private_key",
        name = "builder.private_key",
        env = "BUILDER_PRIVATE_KEY"
    )]
    private_key: Option<String>,

    /// Private keys to use for signing transactions
    ///
    /// Cannot use both `builder.private_keys` and `builder.aws_kms_key_ids` at the same time.
    #[arg(
        long = "builder.private_keys",
        name = "builder.private_keys",
        env = "BUILDER_PRIVATE_KEYS",
        value_delimiter = ','
    )]
    private_keys: Vec<String>,

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

    /// Choice of what sender type to to use for transaction submission.
    /// Defaults to the value of `raw`. Other options include `flashbots`,
    /// `conditional` and `bloxroute`
    #[arg(
        long = "builder.sender",
        name = "builder.sender",
        env = "BUILDER_SENDER",
        value_enum,
        default_value = "raw"
    )]
    pub sender_type: TransactionSenderKind,

    /// If present, the url of the ETH provider that will be used to send
    /// transactions. Defaults to the value of `node_http`.
    ///
    /// Only used when BUILDER_SENDER is "raw"
    #[arg(
        long = "builder.submit_url",
        name = "builder.submit_url",
        env = "BUILDER_SUBMIT_URL"
    )]
    pub submit_url: Option<String>,

    /// If true, use the submit endpoint for transaction status checks.
    ///
    /// Only used when BUILDER_SENDER is "raw"
    #[arg(
        long = "builder.use_submit_for_status",
        name = "builder.use_submit_for_status",
        env = "BUILDER_USE_SUBMIT_FOR_STATUS",
        default_value = "false"
    )]
    pub use_submit_for_status: bool,

    /// Use the conditional RPC endpoint for transaction submission.
    ///
    /// Only used when BUILDER_SENDER is "raw"
    #[arg(
        long = "builder.use_conditional_rpc",
        name = "builder.use_conditional_rpc",
        env = "BUILDER_USE_CONDITIONAL_RPC",
        default_value = "false"
    )]
    pub use_conditional_rpc: bool,

    /// If the "dropped" status is unsupported by the status provider.
    ///
    /// Only used when BUILDER_SENDER is "raw"
    #[arg(
        long = "builder.dropped_status_unsupported",
        name = "builder.dropped_status_unsupported",
        env = "BUILDER_DROPPED_STATUS_UNSUPPORTED",
        default_value = "false"
    )]
    pub dropped_status_unsupported: bool,

    /// A list of builders to pass into the Flashbots Relay RPC.
    ///
    /// Only used when BUILDER_SENDER is "flashbots"
    #[arg(
        long = "builder.flashbots_relay_builders",
        name = "builder.flashbots_relay_builders",
        env = "BUILDER_FLASHBOTS_RELAY_BUILDERS",
        value_delimiter = ',',
        default_value = "flashbots"
    )]
    flashbots_relay_builders: Vec<String>,

    /// A private key used to authenticate with the Flashbots relay.
    ///
    /// Only used when BUILDER_SENDER is "flashbots"
    #[arg(
        long = "builder.flashbots_relay_auth_key",
        name = "builder.flashbots_relay_auth_key",
        env = "BUILDER_FLASHBOTS_RELAY_AUTH_KEY",
        value_delimiter = ','
    )]
    flashbots_relay_auth_key: Option<String>,

    /// Auth header to use for Bloxroute polygon_private_tx sender
    ///
    /// Only used when BUILDER_SENDER is "bloxroute"
    #[arg(
        long = "builder.bloxroute_auth_header",
        name = "builder.bloxroute_auth_header",
        env = "BUILDER_BLOXROUTE_AUTH_HEADER"
    )]
    bloxroute_auth_header: Option<String>,

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

    /// Maximum number of times to increase gas fees when retrying a cancellation transaction
    /// before giving up.
    #[arg(
        long = "builder.max_cancellation_fee_increases",
        name = "builder.max_cancellation_fee_increases",
        env = "BUILDER_MAX_CANCELLATION_FEE_INCREASES",
        default_value = "15"
    )]
    max_cancellation_fee_increases: u64,

    /// The maximum number of blocks to wait in a replacement underpriced state before issuing
    /// a cancellation transaction.
    #[arg(
        long = "builder.max_replacement_underpriced_blocks",
        name = "builder.max_replacement_underpriced_blocks",
        env = "BUILDER_MAX_REPLACEMENT_UNDERPRICED_BLOCKS",
        default_value = "20"
    )]
    max_replacement_underpriced_blocks: u64,

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

        let mempool_configs = match &common.mempool_config_path {
            Some(path) => get_json_config::<MempoolConfigs>(path, &common.aws_region)
                .await
                .with_context(|| format!("should load mempool configurations from {path}"))?,
            None => MempoolConfigs::default(),
        };

        let mut entry_points = vec![];
        let mut num_builders = 0;

        if !common.disable_entry_point_v0_6 {
            entry_points.push(EntryPointBuilderSettings {
                address: chain_spec.entry_point_address_v0_6,
                version: EntryPointVersion::V0_6,
                num_bundle_builders: common.num_builders_v0_6,
                bundle_builder_index_offset: self.builder_index_offset,
                mempool_configs: mempool_configs
                    .get_for_entry_point(chain_spec.entry_point_address_v0_6),
            });
            num_builders += common.num_builders_v0_6;
        }
        if !common.disable_entry_point_v0_7 {
            entry_points.push(EntryPointBuilderSettings {
                address: chain_spec.entry_point_address_v0_7,
                version: EntryPointVersion::V0_7,
                num_bundle_builders: common.num_builders_v0_7,
                bundle_builder_index_offset: self.builder_index_offset,
                mempool_configs: mempool_configs
                    .get_for_entry_point(chain_spec.entry_point_address_v0_7),
            });
            num_builders += common.num_builders_v0_7;
        }

        if (self.private_key.is_some() || !self.private_keys.is_empty())
            && !self.aws_kms_key_ids.is_empty()
        {
            bail!(
                "Cannot use both builder.private_key(s) and builder.aws_kms_key_ids at the same time."
            );
        }

        let mut private_keys = self.private_keys.clone();
        if self.private_key.is_some() || !self.private_keys.is_empty() {
            if let Some(pk) = &self.private_key {
                private_keys.push(pk.clone());
            }

            if num_builders > private_keys.len() as u64 {
                bail!(
                    "Found {} private keys, but need {} keys for the number of builders. You may need to disable one of the entry points.",
                    private_keys.len(), num_builders
                );
            }
        } else if self.aws_kms_key_ids.len() < num_builders as usize {
            bail!(
                "Not enough AWS KMS key IDs for the number of builders. Need {} keys, found {}. You may need to disable one of the entry points.",
                num_builders, self.aws_kms_key_ids.len()
            );
        }

        let sender_args = self.sender_args(&chain_spec, &rpc_url)?;

        Ok(BuilderTaskArgs {
            entry_points,
            chain_spec,
            unsafe_mode: common.unsafe_mode,
            rpc_url,
            private_keys,
            aws_kms_key_ids: self.aws_kms_key_ids.clone(),
            aws_kms_region: common
                .aws_region
                .parse()
                .context("should be a valid aws region")?,
            redis_uri: self.redis_uri.clone(),
            redis_lock_ttl_millis: self.redis_lock_ttl_millis,
            max_bundle_size: self.max_bundle_size,
            max_bundle_gas: common.max_bundle_gas,
            bundle_priority_fee_overhead_percent: common.bundle_priority_fee_overhead_percent,
            priority_fee_mode,
            sender_args,
            sim_settings: common.try_into()?,
            max_blocks_to_wait_for_mine: self.max_blocks_to_wait_for_mine,
            replacement_fee_percent_increase: self.replacement_fee_percent_increase,
            max_cancellation_fee_increases: self.max_cancellation_fee_increases,
            max_replacement_underpriced_blocks: self.max_replacement_underpriced_blocks,
            remote_address,
        })
    }

    fn sender_args(
        &self,
        chain_spec: &ChainSpec,
        rpc_url: &str,
    ) -> anyhow::Result<TransactionSenderArgs> {
        match self.sender_type {
            TransactionSenderKind::Raw => Ok(TransactionSenderArgs::Raw(RawSenderArgs {
                submit_url: self.submit_url.clone().unwrap_or_else(|| rpc_url.into()),
                use_submit_for_status: self.use_submit_for_status,
                dropped_status_supported: !self.dropped_status_unsupported,
                use_conditional_rpc: self.use_conditional_rpc,
            })),
            TransactionSenderKind::Flashbots => {
                if !chain_spec.flashbots_enabled {
                    return Err(anyhow::anyhow!("Flashbots sender is not enabled for chain"));
                }

                Ok(TransactionSenderArgs::Flashbots(FlashbotsSenderArgs {
                    builders: self.flashbots_relay_builders.clone(),
                    relay_url: chain_spec
                        .flashbots_relay_url
                        .clone()
                        .context("should have a relay URL (chain spec: flashbots_relay_url)")?,
                    status_url: chain_spec.flashbots_status_url.clone().context(
                        "should have a flashbots status URL (chain spec: flashbots_status_url)",
                    )?,
                    auth_key: self.flashbots_relay_auth_key.clone().context(
                        "should have a flashbots relay auth key (cli: flashbots_relay_auth_key)",
                    )?,
                }))
            }
            TransactionSenderKind::Bloxroute => {
                if !chain_spec.bloxroute_enabled {
                    return Err(anyhow::anyhow!("Flashbots sender is not enabled for chain"));
                }

                Ok(TransactionSenderArgs::Bloxroute(BloxrouteSenderArgs {
                    header: self
                        .bloxroute_auth_header
                        .clone()
                        .context("should have a bloxroute auth header")?,
                }))
            }
        }
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
            chain_spec.clone(),
            &common_args,
            Some(format_socket_addr(&builder_args.host, builder_args.port).parse()?),
        )
        .await?;

    let pool = connect_with_retries_shutdown(
        "op pool from builder",
        &pool_url,
        |url| RemotePoolClient::connect(url, chain_spec.clone()),
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
