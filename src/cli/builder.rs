use std::time::Duration;

use anyhow::{bail, Context};
use clap::Args;
use tokio::{
    signal,
    sync::{broadcast, mpsc},
};
use tracing::{error, info};

use super::CommonArgs;
use crate::{builder, common::server::format_server_addr};

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

    /// AWS KMS region to use for KMS
    #[arg(
        long = "builder.aws_region",
        name = "builder.aws_region",
        env = "BUILDER_AWS_REGION",
        default_value = "us-east-1"
    )]
    aws_kms_region: String,

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
}

impl BuilderArgs {
    /// Convert the CLI arguments into the arguments for the builder combining
    /// common and builder specific arguments.
    pub fn to_args(&self, common: &CommonArgs, pool_url: String) -> anyhow::Result<builder::Args> {
        Ok(builder::Args {
            port: self.port,
            host: self.host.clone(),
            rpc_url: common
                .node_http
                .clone()
                .context("should have a node HTTP URL")?,
            pool_url,
            entry_point_address: common
                .entry_points
                .get(0)
                .context("should have at least one entry point")?
                .parse()
                .context("should parse entry point address")?,
            private_key: self.private_key.clone(),
            aws_kms_key_ids: self.aws_kms_key_ids.clone(),
            aws_kms_region: self
                .aws_kms_region
                .parse()
                .context("should be a valid aws region")?,
            redis_uri: self.redis_uri.clone(),
            redis_lock_ttl_millis: self.redis_lock_ttl_millis,
            chain_id: common.chain_id,
            max_bundle_size: self.max_bundle_size,
            eth_poll_interval: Duration::from_millis(self.eth_poll_interval_millis),
            sim_settings: common.try_into()?,
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

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let (shutdown_scope, mut shutdown_wait) = mpsc::channel(1);

    let handle = tokio::spawn(builder::run(
        builder_args.to_args(&common_args, pool_url)?,
        shutdown_rx,
        shutdown_scope,
    ));

    tokio::select! {
        res = handle => {
            error!("Builder server exited unexpectedly: {res:?}");
        }
        res = signal::ctrl_c() => {
            match res {
                Ok(_) => {
                    info!("Received SIGINT, shutting down");
                    shutdown_tx.send(())?;
                    shutdown_wait.recv().await;
                }
                Err(err) => {
                    bail!("Error while waiting for SIGINT: {err:?}");
                }
            }
        }
    }

    shutdown_wait.recv().await;
    Ok(())
}
