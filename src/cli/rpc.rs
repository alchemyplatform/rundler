use std::time::Duration;

use anyhow::Context;
use clap::Args;

use super::CommonArgs;
use crate::{
    builder::RemoteBuilderClient,
    common::{
        eth, handle::spawn_tasks_with_shutdown, precheck, server::connect_with_retries_shutdown,
    },
    op_pool::RemotePoolClient,
    rpc::{self, estimation, RpcTask},
};

/// CLI options for the RPC server
#[derive(Args, Debug)]
#[command(next_help_heading = "RPC")]
pub struct RpcArgs {
    /// Port to listen on for JSON-RPC requests
    #[arg(
        long = "rpc.port",
        name = "rpc.port",
        env = "RPC_PORT",
        default_value = "3000"
    )]
    port: u16,

    /// Host to listen on for JSON-RPC requests
    #[arg(
        long = "rpc.host",
        name = "rpc.host",
        env = "RPC_HOST",
        default_value = "0.0.0.0"
    )]
    host: String,

    /// Which APIs to expose over the RPC interface
    #[arg(
        long = "rpc.api",
        name = "rpc.api",
        env = "RPC_API",
        default_value = "eth,rundler",
        value_delimiter = ',',
        value_parser = ["eth", "debug", "rundler"]
    )]
    api: Vec<String>,

    /// Timeout for RPC requests
    #[arg(
        long = "rpc.timeout_seconds",
        name = "rpc.timeout_seconds",
        env = "RPC_TIMEOUT_SECONDS",
        default_value = "20"
    )]
    timeout_seconds: String,

    /// Maximum number of concurrent connections
    #[arg(
        long = "rpc.max_connections",
        name = "rpc.max_connections",
        env = "RPC_MAX_CONNECTIONS",
        default_value = "100"
    )]
    max_connections: u32,
}

impl RpcArgs {
    /// Convert the CLI arguments into the arguments for the RPC server combining
    /// common and rpc specific arguments.
    #[allow(clippy::too_many_arguments)]
    pub async fn to_args(
        &self,
        common: &CommonArgs,
        precheck_settings: precheck::Settings,
        eth_api_settings: eth::Settings,
        estimation_settings: estimation::Settings,
    ) -> anyhow::Result<rpc::Args> {
        let apis = self
            .api
            .iter()
            .map(|api| api.parse())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rpc::Args {
            port: self.port,
            host: self.host.clone(),
            entry_points: common
                .entry_points
                .iter()
                .map(|ep| ep.parse())
                .collect::<Result<Vec<_>, _>>()
                .context("Invalid entry_points argument")?,
            rpc_url: common
                .node_http
                .clone()
                .context("rpc requires node_http arg")?,
            chain_id: common.chain_id,
            api_namespaces: apis,
            precheck_settings,
            eth_api_settings,
            estimation_settings,
            rpc_timeout: Duration::from_secs(self.timeout_seconds.parse()?),
            max_connections: self.max_connections,
        })
    }
}

/// CLI options for the RPC server standalone
#[derive(Args, Debug)]
pub struct RpcCliArgs {
    #[command(flatten)]
    rpc: RpcArgs,

    #[arg(
        long = "rpc.pool_url",
        name = "rpc.pool_url",
        env = "RPC_POOL_URL",
        default_value = "http://localhost:50051",
        global = true
    )]
    pool_url: String,

    #[arg(
        long = "rpc.builder_url",
        name = "rpc.builder_url",
        env = "RPC_BUILDER_URL",
        default_value = "http://localhost:50052",
        global = true
    )]
    builder_url: String,
}

pub async fn run(rpc_args: RpcCliArgs, common_args: CommonArgs) -> anyhow::Result<()> {
    let RpcCliArgs {
        rpc: rpc_args,
        pool_url,
        builder_url,
    } = rpc_args;

    let task_args = rpc_args
        .to_args(
            &common_args,
            (&common_args).try_into()?,
            (&common_args).into(),
            (&common_args).try_into()?,
        )
        .await?;

    let pool = connect_with_retries_shutdown(
        "op pool from rpc",
        &pool_url,
        RemotePoolClient::connect,
        tokio::signal::ctrl_c(),
    )
    .await?;

    let builder = connect_with_retries_shutdown(
        "builder from rpc",
        &builder_url,
        RemoteBuilderClient::connect,
        tokio::signal::ctrl_c(),
    )
    .await?;

    spawn_tasks_with_shutdown(
        [RpcTask::new(task_args, pool, builder).boxed()],
        tokio::signal::ctrl_c(),
    )
    .await;
    Ok(())
}
