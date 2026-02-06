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

use std::str::FromStr;

use rundler_task::server::HealthCheck;
use rundler_types::{EntryPointVersion, builder::Builder, chain::ChainSpec, pool::Pool};
use serde::Deserialize;

/// Configuration for a single chain in the gateway.
#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    /// Chain ID.
    pub chain_id: u64,
    /// Human-readable name for this chain.
    pub name: String,
    /// Base network for ChainSpec resolution.
    #[serde(alias = "network")]
    pub base: String,
    /// HTTP URL for the chain's ETH node
    pub node_http: String,
    /// gRPC URL for the pool server
    pub pool_url: String,
    /// gRPC URL for the builder server
    pub builder_url: String,
    /// Entry point versions to enable
    #[serde(default = "default_entry_points")]
    pub enabled_entry_points: Vec<String>,
    /// Optional: Override the chain name in the chain spec.
    #[serde(default)]
    pub chain_name: Option<String>,
}

fn default_entry_points() -> Vec<String> {
    vec!["v0.7".to_string()]
}

impl ChainConfig {
    /// Parse the enabled entry point versions.
    pub fn parse_entry_points(&self) -> anyhow::Result<Vec<EntryPointVersion>> {
        self.enabled_entry_points
            .iter()
            .map(|s| {
                EntryPointVersion::from_str(s)
                    .map_err(|e| anyhow::anyhow!("Invalid entry point version '{}': {}", s, e))
            })
            .collect()
    }
}

/// Configuration file containing multiple chains.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// List of chain configurations
    #[serde(rename = "chains")]
    pub chains: Vec<ChainConfig>,
}

/// Backend for a single chain, holding trait-object pool and builder clients.
pub struct ChainBackend {
    /// Chain specification
    pub chain_spec: ChainSpec,
    /// Pool client for this chain
    pub pool: Box<dyn Pool>,
    /// Builder client for this chain
    pub builder: Box<dyn Builder>,
    /// Pool health checker
    pub pool_health: Box<dyn HealthCheck>,
    /// Builder health checker
    pub builder_health: Box<dyn HealthCheck>,
    /// Enabled entry point versions
    pub entry_points: Vec<EntryPointVersion>,
}

impl ChainBackend {
    /// Creates a new chain backend.
    pub fn new(
        chain_spec: ChainSpec,
        pool: Box<dyn Pool>,
        builder: Box<dyn Builder>,
        pool_health: Box<dyn HealthCheck>,
        builder_health: Box<dyn HealthCheck>,
        entry_points: Vec<EntryPointVersion>,
    ) -> Self {
        Self {
            chain_spec,
            pool,
            builder,
            pool_health,
            builder_health,
            entry_points,
        }
    }

    /// Returns the chain ID.
    pub fn chain_id(&self) -> u64 {
        self.chain_spec.id
    }

    /// Returns the chain name.
    pub fn chain_name(&self) -> &str {
        &self.chain_spec.name
    }
}
