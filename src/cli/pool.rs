use std::{collections::HashSet, fs::File, io::BufReader, pin::Pin, time::Duration};

use anyhow::{bail, Context};
use clap::Args;
use ethers::types::Address;
use rusoto_core::Region;
use rusoto_s3::{GetObjectRequest, S3Client, S3};
use tokio::{
    io::AsyncReadExt,
    signal,
    sync::{broadcast, mpsc},
};
use tracing::{error, info};

use super::CommonArgs;
use crate::op_pool::{self, PoolConfig};

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
        long = "pool.max_userops_per_sender",
        name = "pool.max_userops_per_sender",
        env = "POOL_MAX_USEROPS_PER_SENDER",
        default_value = "4"
    )]
    pub max_userops_per_sender: usize,

    #[arg(
        long = "pool.min_replacement_fee_increase_percentage",
        name = "pool.min_replacement_fee_increase_percentage",
        env = "POOL_MIN_REPLACEMENT_FEE_INCREASE_PERCENTAGE",
        default_value = "10"
    )]
    pub min_replacement_fee_increase_percentage: usize,

    /// ETH Node HTTP polling interval in milliseconds
    /// (only used if node_http is set)
    #[arg(
        long = "pool.http_poll_interval_millis",
        name = "pool.http_poll_interval_millis",
        env = "POOL_HTTP_POLL_INTERVAL_MILLIS",
        default_value = "100"
    )]
    pub http_poll_interval_millis: u64,

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
}

impl PoolArgs {
    /// Convert the CLI arguments into the arguments for the OP Pool combining
    /// common and op pool specific arguments.
    pub async fn to_args(&self, common: &CommonArgs) -> anyhow::Result<op_pool::Args> {
        let aws_region: Region = common.aws_region.parse().context("invalid AWS region")?;
        let blocklist = match &self.blocklist_path {
            Some(blocklist) => Some(Self::get_list(blocklist, &aws_region).await?),
            None => None,
        };
        let allowlist = match &self.allowlist_path {
            Some(allowlist) => Some(Self::get_list(allowlist, &aws_region).await?),
            None => None,
        };
        tracing::info!("blocklist: {:?}", blocklist);
        tracing::info!("allowlist: {:?}", allowlist);

        let pool_configs = common
            .entry_points
            .iter()
            .map(|ep| {
                let entry_point = ep.parse().context("Invalid entry_points argument")?;
                Ok(PoolConfig {
                    entry_point,
                    chain_id: common.chain_id,
                    max_userops_per_sender: self.max_userops_per_sender,
                    min_replacement_fee_increase_percentage: self
                        .min_replacement_fee_increase_percentage,
                    max_size_of_pool_bytes: self.max_size_in_bytes,
                    blocklist: blocklist.clone(),
                    allowlist: allowlist.clone(),
                })
            })
            .collect::<anyhow::Result<Vec<PoolConfig>>>()?;

        Ok(op_pool::Args {
            port: self.port,
            host: self.host.clone(),
            chain_id: common.chain_id,
            ws_url: common.node_ws.clone(),
            http_url: common.node_http.clone(),
            http_poll_interval: Duration::from_millis(self.http_poll_interval_millis),
            pool_configs,
        })
    }

    async fn get_list(path: &str, aws_s3_region: &Region) -> anyhow::Result<HashSet<Address>> {
        if path.starts_with("s3://") {
            Self::get_s3_list(path, aws_s3_region).await
        } else {
            Self::get_local_list(path)
        }
    }

    fn get_local_list(path: &str) -> anyhow::Result<HashSet<Address>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }

    async fn get_s3_list(path: &str, aws_s3_region: &Region) -> anyhow::Result<HashSet<Address>> {
        let (bucket, key) = sscanf::sscanf!(path, "s3://{}/{}", String, String)
            .map_err(|e| anyhow::anyhow!("invalid s3 uri: {e:?}"))?;
        let request = GetObjectRequest {
            bucket,
            key,
            ..Default::default()
        };
        let client = S3Client::new(aws_s3_region.clone());
        let resp = client.get_object(request).await?;
        let body = resp.body.context("object should have body")?;
        let mut buf = String::new();
        Pin::new(&mut body.into_async_read())
            .read_to_string(&mut buf)
            .await?;
        Ok(serde_json::from_str(&buf)?)
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

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let (shutdown_scope, mut shutdown_wait) = mpsc::channel(1);

    let handle = tokio::spawn(op_pool::run(
        pool_args.to_args(&common_args).await?,
        shutdown_rx,
        shutdown_scope,
    ));

    tokio::select! {
        res = handle => {
            error!("Pool server exited unexpectedly: {res:?}");
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

    Ok(())
}
