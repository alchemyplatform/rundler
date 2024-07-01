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
use ethers::providers::{JsonRpcClient, Provider};
use jsonrpsee::{
    server::{middleware::ProxyGetRequestLayer, ServerBuilder},
    RpcModule,
};
use rundler_provider::{EthersEntryPointV0_6, EthersEntryPointV0_7};
use rundler_sim::{
    EstimationSettings, FeeEstimator, GasEstimatorV0_6, GasEstimatorV0_7, PrecheckSettings,
};
use rundler_task::{
    server::{format_socket_addr, HealthCheck},
    Task,
};
use rundler_types::{builder::Builder, chain::ChainSpec, pool::Pool};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    admin::{AdminApi, AdminApiServer},
    debug::{DebugApi, DebugApiServer},
    eth::{
        EntryPointRouteImpl, EntryPointRouter, EntryPointRouterBuilder, EthApi, EthApiServer,
        EthApiSettings, UserOperationEventProviderV0_6, UserOperationEventProviderV0_7,
    },
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
    /// True if using unsafe mode
    pub unsafe_mode: bool,
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
    /// Whether to enable entry point v0.6.
    pub entry_point_v0_6_enabled: bool,
    /// Whether to enable entry point v0.7.
    pub entry_point_v0_7_enabled: bool,
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
    P: Pool + HealthCheck + Clone,
    B: Builder + HealthCheck + Clone,
{
    async fn run(mut self: Box<Self>, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let addr: SocketAddr = format_socket_addr(&self.args.host, self.args.port).parse()?;
        tracing::info!("Starting rpc server on {}", addr);

        let provider = rundler_provider::new_provider(&self.args.rpc_url, None)?;
        let ep_v0_6 = EthersEntryPointV0_6::new(
            self.args.chain_spec.entry_point_address_v0_6,
            &self.args.chain_spec,
            self.args.estimation_settings.max_simulate_handle_ops_gas,
            provider.clone(),
        );
        let ep_v0_7 = EthersEntryPointV0_7::new(
            self.args.chain_spec.entry_point_address_v0_7,
            &self.args.chain_spec,
            self.args.estimation_settings.max_simulate_handle_ops_gas,
            provider.clone(),
        );

        let mut router_builder = EntryPointRouterBuilder::default();
        if self.args.entry_point_v0_6_enabled {
            router_builder = router_builder.v0_6(EntryPointRouteImpl::new(
                ep_v0_6.clone(),
                GasEstimatorV0_6::new(
                    self.args.chain_spec.clone(),
                    provider.clone(),
                    ep_v0_6.clone(),
                    self.args.estimation_settings,
                    FeeEstimator::new(
                        &self.args.chain_spec,
                        Arc::clone(&provider),
                        self.args.precheck_settings.priority_fee_mode,
                        self.args
                            .precheck_settings
                            .bundle_priority_fee_overhead_percent,
                    ),
                ),
                UserOperationEventProviderV0_6::new(
                    self.args.chain_spec.clone(),
                    provider.clone(),
                    self.args
                        .eth_api_settings
                        .user_operation_event_block_distance,
                ),
            ));
        }

        if self.args.entry_point_v0_7_enabled {
            router_builder = router_builder.v0_7(EntryPointRouteImpl::new(
                ep_v0_7.clone(),
                GasEstimatorV0_7::new(
                    self.args.chain_spec.clone(),
                    Arc::clone(&provider),
                    ep_v0_7.clone(),
                    self.args.estimation_settings,
                    FeeEstimator::new(
                        &self.args.chain_spec,
                        Arc::clone(&provider),
                        self.args.precheck_settings.priority_fee_mode,
                        self.args
                            .precheck_settings
                            .bundle_priority_fee_overhead_percent,
                    ),
                ),
                UserOperationEventProviderV0_7::new(
                    self.args.chain_spec.clone(),
                    provider.clone(),
                    self.args
                        .eth_api_settings
                        .user_operation_event_block_distance,
                ),
            ));
        }

        // create the entry point router
        let router = router_builder.build();

        let mut module = RpcModule::new(());
        self.attach_namespaces(provider, router, &mut module)?;

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
            // Set max request body size to 2x the max transaction size as none of our
            // APIs should require more than that.
            .max_request_body_size(
                (self.args.chain_spec.max_transaction_size_bytes * 2)
                    .try_into()
                    .expect("max_transaction_size_bytes * 2 overflowed u32"),
            )
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
    P: Pool + HealthCheck + Clone,
    B: Builder + HealthCheck + Clone,
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

    fn attach_namespaces<C>(
        &self,
        provider: Arc<Provider<C>>,
        entry_point_router: EntryPointRouter,
        module: &mut RpcModule<()>,
    ) -> anyhow::Result<()>
    where
        C: JsonRpcClient + 'static,
    {
        if self.args.api_namespaces.contains(&ApiNamespace::Eth) {
            module.merge(
                EthApi::new(
                    self.args.chain_spec.clone(),
                    entry_point_router.clone(),
                    self.pool.clone(),
                )
                .into_rpc(),
            )?
        }

        if self.args.api_namespaces.contains(&ApiNamespace::Debug) {
            module.merge(DebugApi::new(self.pool.clone(), self.builder.clone()).into_rpc())?;
        }

        if self.args.api_namespaces.contains(&ApiNamespace::Admin) {
            module.merge(AdminApi::new(self.pool.clone()).into_rpc())?;
        }

        if self.args.api_namespaces.contains(&ApiNamespace::Rundler) {
            module.merge(
                RundlerApi::new(
                    &self.args.chain_spec,
                    provider.clone(),
                    entry_point_router,
                    self.pool.clone(),
                    self.args.rundler_api_settings,
                )
                .into_rpc(),
            )?;
        }

        Ok(())
    }
}
