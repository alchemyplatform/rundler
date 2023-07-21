use std::{collections::HashMap, time::Duration};

use anyhow::Context;
use clap::Args;
use ethers::types::H256;

use super::{json::get_json_config, CommonArgs};
use crate::{
    builder::{self, BuilderTask},
    common::{
        gas::PriorityFeeMode, handle::spawn_tasks_with_shutdown, mempool::MempoolConfig,
        server::format_server_addr,
    },
    op_pool::PoolClientMode,
};

/// CLI options for the builder
#[derive(Args, Debug)]
#[command(next_help_heading = "BUILDER")]
pub struct BuilderArgs {
    /// Port to listen on for gRPC requests
    #[arg(
        long = "builder.port",
        name = "builder.port",
        env = "BUILDER_PORT",
        default_value = "50052"
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
        default_value = "10"
    )]
    max_bundle_size: u64,

    /// Interval at which the builder polls an Eth node for new blocks and
    /// mined transactions.
    #[arg(
        long = "builder.eth_poll_interval_millis",
        name = "builder.eth_poll_interval_millis",
        env = "BUILDER_ETH_POLL_INTERVAL_MILLIS",
        default_value = "250"
    )]
    pub eth_poll_interval_millis: u64,

    /// If present, the url of the ETH provider that will be used to send
    /// transactions. Defaults to the value of `node_http`.
    #[arg(
        long = "builder.submit_url",
        name = "builder.submit_url",
        env = "BUILDER_SUBMIT_URL"
    )]
    pub submit_url: Option<String>,

    /// If true, will use the provider's `eth_sendRawTransactionConditional`
    /// method instead `eth_sendRawTransaction`, passing in expected storage
    /// values determined through simulation. Must not be set on networks
    /// which do not support this method.
    #[arg(
        long = "builder.use_conditional_send_transaction",
        name = "builder.use_conditional_send_transaction",
        env = "BUILDER_USE_CONDITIONAL_SEND_TRANSACTION",
        default_value = "false"
    )]
    use_conditional_send_transaction: bool,

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

    ///
    #[arg(
        long = "builder.max_fee_increases",
        name = "builder.max_fee_increases",
        env = "BUILDER_MAX_FEE_INCREASES",
        // Seven increases of 10% is roughly 2x the initial fees.
        default_value = "7"
    )]
    max_fee_increases: u64,
}

impl BuilderArgs {
    /// Convert the CLI arguments into the arguments for the builder combining
    /// common and builder specific arguments.
    pub async fn to_args(
        &self,
        common: &CommonArgs,
        pool_client_mode: PoolClientMode,
    ) -> anyhow::Result<builder::Args> {
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

        Ok(builder::Args {
            port: self.port,
            host: self.host.clone(),
            rpc_url,
            entry_point_address: common
                .entry_points
                .get(0)
                .context("should have at least one entry point")?
                .parse()
                .context("should parse entry point address")?,
            private_key: self.private_key.clone(),
            aws_kms_key_ids: self.aws_kms_key_ids.clone(),
            aws_kms_region: common
                .aws_region
                .parse()
                .context("should be a valid aws region")?,
            redis_uri: self.redis_uri.clone(),
            redis_lock_ttl_millis: self.redis_lock_ttl_millis,
            chain_id: common.chain_id,
            max_bundle_size: self.max_bundle_size,
            submit_url,
            use_bundle_priority_fee: common.use_bundle_priority_fee,
            bundle_priority_fee_overhead_percent: common.bundle_priority_fee_overhead_percent,
            priority_fee_mode,
            use_conditional_send_transaction: self.use_conditional_send_transaction,
            eth_poll_interval: Duration::from_millis(self.eth_poll_interval_millis),
            sim_settings: common.try_into()?,
            mempool_configs,
            max_blocks_to_wait_for_mine: self.max_blocks_to_wait_for_mine,
            replacement_fee_percent_increase: self.replacement_fee_percent_increase,
            max_fee_increases: self.max_fee_increases,
            pool_client_mode,
        })
    }

    pub fn url(&self, secure: bool) -> String {
        format_server_addr(&self.host, self.port, secure)
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

pub async fn run(builder_args: BuilderCliArgs, common_args: CommonArgs) -> anyhow::Result<()> {
    let BuilderCliArgs {
        builder: builder_args,
        pool_url,
    } = builder_args;
    let task_args = builder_args
        .to_args(&common_args, PoolClientMode::Remote { url: pool_url })
        .await?;

    spawn_tasks_with_shutdown(
        [BuilderTask::new(task_args).boxed()],
        tokio::signal::ctrl_c(),
    )
    .await;
    Ok(())
}
