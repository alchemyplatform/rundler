use std::time::Duration;

use anyhow::Context;
use clap::Args;

use super::CommonArgs;
use crate::{
    common::handle::spawn_tasks_with_shutdown,
    op_pool::PoolClientMode,
    rpc::{self, estimation, ClientMode, RpcTask},
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
        default_value = "eth",
        value_delimiter = ',',
        value_parser = ["eth", "debug"]
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
}

impl RpcArgs {
    /// Convert the CLI arguments into the arguments for the RPC server combining
    /// common and rpc specific arguments.
    pub async fn to_args(
        &self,
        common: &CommonArgs,
        estimation_settings: estimation::Settings,
        client_mode: ClientMode,
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
            estimation_settings,
            rpc_timeout: Duration::from_secs(self.timeout_seconds.parse()?),
            client_mode,
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
            ClientMode::Remote {
                pool_url,
                builder_url,
            },
        )
        .await?;

    spawn_tasks_with_shutdown([RpcTask::new(task_args).boxed()], tokio::signal::ctrl_c()).await;
    Ok(())
}
