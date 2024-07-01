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

use std::time::Duration;

use anyhow::Context;
use clap::Args;
use rundler_builder::RemoteBuilderClient;
use rundler_pool::RemotePoolClient;
use rundler_rpc::{EthApiSettings, RpcTask, RpcTaskArgs, RundlerApiSettings};
use rundler_sim::{EstimationSettings, PrecheckSettings};
use rundler_task::{server::connect_with_retries_shutdown, spawn_tasks_with_shutdown};
use rundler_types::chain::ChainSpec;

use super::CommonArgs;

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
        value_parser = ["eth", "debug", "rundler", "admin"]
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
    pub fn to_args(
        &self,
        chain_spec: ChainSpec,
        common: &CommonArgs,
        precheck_settings: PrecheckSettings,
        eth_api_settings: EthApiSettings,
        rundler_api_settings: RundlerApiSettings,
        estimation_settings: EstimationSettings,
    ) -> anyhow::Result<RpcTaskArgs> {
        let apis = self
            .api
            .iter()
            .map(|api| api.parse())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(RpcTaskArgs {
            chain_spec,
            unsafe_mode: common.unsafe_mode,
            port: self.port,
            host: self.host.clone(),
            rpc_url: common
                .node_http
                .clone()
                .context("rpc requires node_http arg")?,
            api_namespaces: apis,
            precheck_settings,
            eth_api_settings,
            rundler_api_settings,
            estimation_settings,
            rpc_timeout: Duration::from_secs(self.timeout_seconds.parse()?),
            max_connections: self.max_connections,
            entry_point_v0_6_enabled: !common.disable_entry_point_v0_6,
            entry_point_v0_7_enabled: !common.disable_entry_point_v0_7,
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

pub async fn run(
    chain_spec: ChainSpec,
    rpc_args: RpcCliArgs,
    common_args: CommonArgs,
) -> anyhow::Result<()> {
    let RpcCliArgs {
        rpc: rpc_args,
        pool_url,
        builder_url,
    } = rpc_args;

    let task_args = rpc_args.to_args(
        chain_spec.clone(),
        &common_args,
        (&common_args).try_into()?,
        (&common_args).into(),
        (&common_args).try_into()?,
        (&common_args).try_into()?,
    )?;

    let pool = connect_with_retries_shutdown(
        "op pool from rpc",
        &pool_url,
        |url| RemotePoolClient::connect(url, chain_spec.clone()),
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
