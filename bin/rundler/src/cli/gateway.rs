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
use rundler_rpc::{
    ApiNamespace, ChainBackend, ChainRouter, GatewayConfig, RpcTask, RpcTaskArgs,
    RundlerApiSettings,
};
use rundler_task::{TaskSpawnerExt, server::connect_with_retries_shutdown};

use super::{CommonArgs, chain_spec};

/// CLI options for the Gateway server
#[derive(Args, Debug)]
#[command(next_help_heading = "Gateway")]
pub struct GatewayArgs {
    /// Port to listen on for JSON-RPC requests
    #[arg(
        long = "gateway.port",
        name = "gateway.port",
        env = "GATEWAY_PORT",
        default_value = "3000"
    )]
    port: u16,

    /// Host to listen on for JSON-RPC requests
    #[arg(
        long = "gateway.host",
        name = "gateway.host",
        env = "GATEWAY_HOST",
        default_value = "0.0.0.0"
    )]
    host: String,

    /// Path to the chains configuration file (TOML)
    #[arg(
        long = "gateway.config",
        name = "gateway.config",
        env = "GATEWAY_CONFIG",
        required = true
    )]
    config_path: String,

    /// Timeout for RPC requests in seconds
    #[arg(
        long = "gateway.timeout_seconds",
        name = "gateway.timeout_seconds",
        env = "GATEWAY_TIMEOUT_SECONDS",
        default_value = "20"
    )]
    timeout_seconds: u64,

    /// Maximum number of concurrent connections
    #[arg(
        long = "gateway.max_connections",
        name = "gateway.max_connections",
        env = "GATEWAY_MAX_CONNECTIONS",
        default_value = "2048"
    )]
    max_connections: u32,

    /// CORS domains separated by a comma, * is the wildcard
    #[arg(
        long = "gateway.corsdomain",
        name = "gateway.corsdomain",
        env = "GATEWAY_CORSDOMAIN",
        value_delimiter = ','
    )]
    pub corsdomain: Option<Vec<http::HeaderValue>>,
}

impl GatewayArgs {
    /// Convert to RPC task args (gateway mode).
    pub fn to_args(&self, valid_chains: std::collections::HashSet<u64>) -> RpcTaskArgs {
        RpcTaskArgs {
            port: self.port,
            host: self.host.clone(),
            rpc_timeout: Duration::from_secs(self.timeout_seconds),
            max_connections: self.max_connections,
            max_request_body_size: 262144, // 256KB default
            corsdomain: self.corsdomain.clone(),
            api_namespaces: vec![
                ApiNamespace::Eth,
                ApiNamespace::Debug,
                ApiNamespace::Admin,
                ApiNamespace::Rundler,
            ],
            permissions_enabled: false,
            rundler_api_settings: RundlerApiSettings::default(),
            chain_routing: Some(valid_chains),
        }
    }
}

/// CLI options for the Gateway command
#[derive(Args, Debug)]
pub struct GatewayCliArgs {
    #[command(flatten)]
    pub gateway: GatewayArgs,
}

/// Spawn gateway tasks.
pub async fn spawn_tasks<T: TaskSpawnerExt + 'static>(
    task_spawner: T,
    gateway_args: GatewayCliArgs,
    common_args: CommonArgs,
) -> anyhow::Result<()> {
    // Load the gateway configuration
    let config_content = tokio::fs::read_to_string(&gateway_args.gateway.config_path)
        .await
        .with_context(|| {
            format!(
                "Failed to read gateway config from {}",
                gateway_args.gateway.config_path
            )
        })?;

    let config: GatewayConfig = toml::from_str(&config_content).with_context(|| {
        format!(
            "Failed to parse gateway config from {}",
            gateway_args.gateway.config_path
        )
    })?;

    if config.chains.is_empty() {
        anyhow::bail!("No chains configured in gateway config");
    }

    tracing::info!(
        "Loaded gateway config with {} chains: {:?}",
        config.chains.len(),
        config
            .chains
            .iter()
            .map(|c| format!("{}({})", c.name, c.chain_id))
            .collect::<Vec<_>>()
    );

    // Suppress unused variable warning for common_args
    let _ = &common_args;

    // Create the chain router
    let mut router = ChainRouter::new();

    // Set up each chain with lightweight gRPC clients
    for chain_config in &config.chains {
        tracing::info!(
            "Setting up chain {} ({}) with base '{}'",
            chain_config.name,
            chain_config.chain_id,
            chain_config.base
        );

        // Resolve chain spec from the base network
        let mut chain_spec =
            chain_spec::resolve_chain_spec(&Some(chain_config.base.clone()), &None);

        // Apply per-chain overrides from the gateway config
        if chain_spec.id != chain_config.chain_id {
            tracing::info!(
                "Overriding chain ID from {} to {} for chain {}",
                chain_spec.id,
                chain_config.chain_id,
                chain_config.name
            );
            chain_spec.id = chain_config.chain_id;
        }

        if let Some(chain_name) = &chain_config.chain_name {
            tracing::info!(
                "Overriding chain name from '{}' to '{}' for chain {}",
                chain_spec.name,
                chain_name,
                chain_config.name
            );
            chain_spec.name = chain_name.clone();
        }

        // Parse entry points
        let entry_points = chain_config.parse_entry_points()?;

        // Connect to remote pool (lightweight gRPC channel)
        let pool = connect_with_retries_shutdown(
            &format!("pool for chain {}", chain_config.name),
            &chain_config.pool_url,
            |url| {
                RemotePoolClient::connect(url, chain_spec.clone(), Box::new(task_spawner.clone()))
            },
            tokio::signal::ctrl_c(),
        )
        .await?;

        // Connect to remote builder (lightweight gRPC channel)
        let builder = connect_with_retries_shutdown(
            &format!("builder for chain {}", chain_config.name),
            &chain_config.builder_url,
            RemoteBuilderClient::connect,
            tokio::signal::ctrl_c(),
        )
        .await?;

        // Create the chain backend with gRPC clients and health checkers
        let backend = ChainBackend::new(
            chain_spec,
            Box::new(pool.clone()),
            Box::new(builder.clone()),
            Box::new(pool),
            Box::new(builder),
            entry_points,
        );

        router.add_chain(std::sync::Arc::new(backend));
    }

    // Collect valid chain IDs for routing middleware
    let valid_chains = router.chain_ids().collect();

    // Create and spawn the unified RPC task in gateway mode
    let task_args = gateway_args.gateway.to_args(valid_chains);
    let rpc_task = RpcTask::new(task_args, router);

    rpc_task.spawn(task_spawner).await?;

    Ok(())
}
