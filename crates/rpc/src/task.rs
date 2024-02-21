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

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::bail;
use async_trait::async_trait;
use ethers::providers::{Http, Provider, RetryClient};
use jsonrpsee::{
    server::{middleware::ProxyGetRequestLayer, ServerBuilder},
    RpcModule,
};
use rundler_builder::BuilderServer;
use rundler_pool::PoolServer;
use rundler_provider::EntryPoint;
use rundler_sim::{EstimationSettings, PrecheckSettings};
use rundler_task::{
    server::{format_socket_addr, HealthCheck},
    Task,
};
use rundler_types::{chain::ChainSpec, contracts::i_entry_point::IEntryPoint};
use rundler_utils::eth;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    admin::{AdminApi, AdminApiServer},
    debug::{DebugApi, DebugApiServer},
    eth::{EthApi, EthApiServer, EthApiSettings},
    health::{HealthChecker, SystemApiServer},
    metrics::RpcMetricsLogger,
    rundler::{RundlerApi, RundlerApiServer, Settings as RundlerApiSettings},
    types::ApiNamespace,
};

/// RPC server arguments.
#[derive(Debug)]
pub struct Args {
    /// Chain spec
    pub chain_spec: ChainSpec,
    /// Port to listen on.
    pub port: u16,
    /// Host to listen on.
    pub host: String,
    /// List of API namespaces to enable.
    pub api_namespaces: Vec<ApiNamespace>,
    /// Full node RPC URL to use.
    pub rpc_url: String,
    /// Precheck settings.
    pub precheck_settings: PrecheckSettings,
    /// eth_ API settings.
    pub eth_api_settings: EthApiSettings,
    /// rundler_ API settings.
    pub rundler_api_settings: RundlerApiSettings,
    /// Estimation settings.
    pub estimation_settings: EstimationSettings,
    /// RPC timeout.
    pub rpc_timeout: Duration,
    /// Max number of connections.
    pub max_connections: u32,
}

/// JSON-RPC server task.
#[derive(Debug)]
pub struct RpcTask<P, B> {
    args: Args,
    pool: P,
    builder: B,
}

#[async_trait]
impl<P, B> Task for RpcTask<P, B>
where
    P: PoolServer + HealthCheck + Clone,
    B: BuilderServer + HealthCheck + Clone,
{
    async fn run(mut self: Box<Self>, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let addr: SocketAddr = format_socket_addr(&self.args.host, self.args.port).parse()?;
        tracing::info!("Starting rpc server on {}", addr);

        let provider = eth::new_provider(&self.args.rpc_url, None)?;
        let entry_point =
            IEntryPoint::new(self.args.chain_spec.entry_point_address, provider.clone());

        let mut module = RpcModule::new(());
        self.attach_namespaces(provider, entry_point, &mut module)?;

        let servers: Vec<Box<dyn HealthCheck>> =
            vec![Box::new(self.pool.clone()), Box::new(self.builder.clone())];
        let health_checker = HealthChecker::new(servers);
        module.merge(health_checker.into_rpc())?;

        // Set up health check endpoint via GET /health registers the jsonrpc handler
        let service_builder = tower::ServiceBuilder::new()
            // Proxy `GET /health` requests to internal `system_health` method.
            .layer(ProxyGetRequestLayer::new("/health", "system_health")?)
            .timeout(self.args.rpc_timeout);

        let server = ServerBuilder::default()
            .set_logger(RpcMetricsLogger)
            .set_middleware(service_builder)
            .max_connections(self.args.max_connections)
            .http_only()
            .build(addr)
            .await?;
        let handle = server.start(module);

        info!("Started RPC server");

        tokio::select! {
            _ = handle.stopped() => {
                tracing::error!("RPC server stopped unexpectedly");
                bail!("RPC server stopped unexpectedly")
            }
            _ = shutdown_token.cancelled() => {
                tracing::info!("Server shutdown");
                Ok(())
            }
        }
    }
}

impl<P, B> RpcTask<P, B>
where
    P: PoolServer + HealthCheck + Clone,
    B: BuilderServer + HealthCheck + Clone,
{
    /// Creates a new RPC server task.
    pub fn new(args: Args, pool: P, builder: B) -> Self {
        Self {
            args,
            pool,
            builder,
        }
    }

    /// Converts the task into a boxed trait object.
    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }

    fn attach_namespaces<E: EntryPoint + Clone>(
        &self,
        provider: Arc<Provider<RetryClient<Http>>>,
        entry_point: E,
        module: &mut RpcModule<()>,
    ) -> anyhow::Result<()> {
        for api in &self.args.api_namespaces {
            match api {
                ApiNamespace::Eth => module.merge(
                    EthApi::new(
                        self.args.chain_spec.clone(),
                        provider.clone(),
                        // TODO: support multiple entry points
                        vec![entry_point.clone()],
                        self.pool.clone(),
                        self.args.eth_api_settings,
                        self.args.estimation_settings,
                        self.args.precheck_settings,
                    )
                    .into_rpc(),
                )?,
                ApiNamespace::Debug => module
                    .merge(DebugApi::new(self.pool.clone(), self.builder.clone()).into_rpc())?,
                ApiNamespace::Admin => module.merge(AdminApi::new(self.pool.clone()).into_rpc())?,
                ApiNamespace::Rundler => module.merge(
                    RundlerApi::new(
                        &self.args.chain_spec,
                        provider.clone(),
                        entry_point.clone(),
                        self.pool.clone(),
                        self.args.rundler_api_settings,
                    )
                    .into_rpc(),
                )?,
            }
        }

        Ok(())
    }
}
