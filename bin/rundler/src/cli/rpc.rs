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

use std::{sync::Arc, time::Duration};

use clap::Args;
use rundler_builder::RemoteBuilderClient;
use rundler_pool::RemotePoolClient;
use rundler_rpc::{ChainBackend, ChainRouter, RpcTask, RpcTaskArgs, RundlerApiSettings};
use rundler_task::{TaskSpawnerExt, server::connect_with_retries_shutdown};
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

    /// Cors domains seperated by a comma, * is the wildcard
    ///
    /// # Examples
    ///.env
    /// ```env
    /// RPC_CORSDOMAIN=*
    /// RPC_CORSDOMAIN=https://site1.fake,https:://sub.site1.fake
    /// ```
    #[arg(
        long = "rpc.corsdomain",
        name = "rpc.corsdomain",
        env = "RPC_CORSDOMAIN",
        value_delimiter = ','
    )]
    pub corsdomain: Option<Vec<http::HeaderValue>>,

    #[arg(
        long = "rpc.permissions_enabled",
        name = "rpc.permissions_enabled",
        env = "RPC_PERMISSIONS_ENABLED",
        default_value = "false"
    )]
    permissions_enabled: bool,

    /// Priority fee buffer percent for gas price suggestions.
    /// The suggested priority fee will be this percent above the current required priority fee.
    #[arg(
        long = "rpc.priority_fee_suggested_buffer_percent",
        name = "rpc.priority_fee_suggested_buffer_percent",
        env = "RPC_PRIORITY_FEE_SUGGESTED_BUFFER_PERCENT",
        default_value = "30"
    )]
    priority_fee_suggested_buffer_percent: u64,

    /// Base fee buffer percent for gas price suggestions.
    /// The suggested max fee will use a base fee multiplied by (100 + this value) / 100.
    #[arg(
        long = "rpc.base_fee_suggested_buffer_percent",
        name = "rpc.base_fee_suggested_buffer_percent",
        env = "RPC_BASE_FEE_SUGGESTED_BUFFER_PERCENT",
        default_value = "50"
    )]
    base_fee_suggested_buffer_percent: u64,
}

impl RpcArgs {
    /// Convert the CLI arguments into the arguments for the RPC server combining
    /// common and rpc specific arguments.
    pub fn to_args(&self, chain_spec: &ChainSpec) -> anyhow::Result<RpcTaskArgs> {
        let apis = self
            .api
            .iter()
            .map(|api| api.parse())
            .collect::<Result<Vec<_>, _>>()?;

        let rundler_api_settings = RundlerApiSettings {
            priority_fee_buffer_percent: self.priority_fee_suggested_buffer_percent,
            base_fee_buffer_percent: self.base_fee_suggested_buffer_percent,
        };

        Ok(RpcTaskArgs {
            port: self.port,
            host: self.host.clone(),
            api_namespaces: apis,
            permissions_enabled: self.permissions_enabled,
            rundler_api_settings,
            rpc_timeout: Duration::from_secs(self.timeout_seconds.parse()?),
            max_connections: self.max_connections,
            max_request_body_size: (chain_spec.max_transaction_size_bytes * 2)
                .try_into()
                .expect("max_transaction_size_bytes * 2 overflowed u32"),
            corsdomain: self.corsdomain.clone(),
            chain_routing: None,
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

pub async fn spawn_tasks<T: TaskSpawnerExt + 'static>(
    task_spawner: T,
    chain_spec: ChainSpec,
    rpc_args: RpcCliArgs,
    common_args: CommonArgs,
) -> anyhow::Result<()> {
    let RpcCliArgs {
        rpc: rpc_args,
        pool_url,
        builder_url,
    } = rpc_args;

    let task_args = rpc_args.to_args(&chain_spec)?;

    let pool = connect_with_retries_shutdown(
        "op pool from rpc",
        &pool_url,
        |url| RemotePoolClient::connect(url, chain_spec.clone(), Box::new(task_spawner.clone())),
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

    let entry_points = common_args.enabled_entry_points.clone();
    let backend = ChainBackend::new(
        chain_spec,
        Box::new(pool.clone()),
        Box::new(builder.clone()),
        Box::new(pool),
        Box::new(builder),
        entry_points,
    );
    let mut router = ChainRouter::new();
    router.add_chain(Arc::new(backend));

    RpcTask::new(task_args, router).spawn(task_spawner).await?;

    Ok(())
}
