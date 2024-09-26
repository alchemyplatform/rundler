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

use anyhow::{bail, Context};
use async_trait::async_trait;
use jsonrpsee::{
    server::{middleware::http::ProxyGetRequestLayer, RpcServiceBuilder, ServerBuilder},
    types::Request,
    RpcModule,
};
use rundler_provider::{EntryPointProvider, Provider};
use rundler_sim::{
    EstimationSettings, FeeEstimator, GasEstimatorV0_6, GasEstimatorV0_7, PrecheckSettings,
};
use rundler_task::{
    metrics::MetricsLayer,
    server::{format_socket_addr, HealthCheck},
    Task,
};
use rundler_types::{
    builder::Builder, chain::ChainSpec, pool::Pool, v0_6::UserOperation as UserOperationV0_6,
    v0_7::UserOperation as UserOperationV0_7,
};
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
    rpc_metrics::RPCMethodExtractor,
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
pub struct RpcTask<P, B, PR, E06, E07> {
    args: Args,
    pool: P,
    builder: B,
    provider: Arc<PR>,
    ep_06: Option<E06>,
    ep_07: Option<E07>,
}

#[async_trait]
impl<P, B, PR, E06, E07> Task for RpcTask<P, B, PR, E06, E07>
where
    P: Pool + HealthCheck + Clone,
    B: Builder + HealthCheck + Clone,
    PR: Provider,
    E06: EntryPointProvider<UserOperationV0_6>,
    E07: EntryPointProvider<UserOperationV0_7>,
{
    async fn run(mut self: Box<Self>, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let addr: SocketAddr = format_socket_addr(&self.args.host, self.args.port).parse()?;
        tracing::info!("Starting rpc server on {}", addr);

        let mut router_builder = EntryPointRouterBuilder::default();
        if self.args.entry_point_v0_6_enabled {
            let ep = self
                .ep_06
                .clone()
                .context("entry point v0.6 not supplied")?;

            router_builder = router_builder.v0_6(EntryPointRouteImpl::new(
                ep.clone(),
                GasEstimatorV0_6::new(
                    self.args.chain_spec.clone(),
                    Arc::clone(&self.provider),
                    ep.clone(),
                    self.args.estimation_settings,
                    FeeEstimator::new(
                        &self.args.chain_spec,
                        Arc::clone(&self.provider),
                        self.args.precheck_settings.priority_fee_mode,
                        self.args
                            .precheck_settings
                            .bundle_priority_fee_overhead_percent,
                    ),
                ),
                UserOperationEventProviderV0_6::new(
                    self.args.chain_spec.clone(),
                    Arc::clone(&self.provider),
                    self.args
                        .eth_api_settings
                        .user_operation_event_block_distance,
                ),
            ));
        }

        if self.args.entry_point_v0_7_enabled {
            let ep = self
                .ep_07
                .clone()
                .context("entry point v0.7 not supplied")?;

            router_builder = router_builder.v0_7(EntryPointRouteImpl::new(
                ep.clone(),
                GasEstimatorV0_7::new(
                    self.args.chain_spec.clone(),
                    Arc::clone(&self.provider),
                    ep.clone(),
                    self.args.estimation_settings,
                    FeeEstimator::new(
                        &self.args.chain_spec,
                        Arc::clone(&self.provider),
                        self.args.precheck_settings.priority_fee_mode,
                        self.args
                            .precheck_settings
                            .bundle_priority_fee_overhead_percent,
                    ),
                ),
                UserOperationEventProviderV0_7::new(
                    self.args.chain_spec.clone(),
                    Arc::clone(&self.provider),
                    self.args
                        .eth_api_settings
                        .user_operation_event_block_distance,
                ),
            ));
        }

        // create the entry point router
        let router = router_builder.build();

        let mut module = RpcModule::new(());
        self.attach_namespaces(router, &mut module)?;

        let servers: Vec<Box<dyn HealthCheck>> =
            vec![Box::new(self.pool.clone()), Box::new(self.builder.clone())];
        let health_checker = HealthChecker::new(servers);
        module.merge(health_checker.into_rpc())?;

        // Set up health check endpoint via GET /health registers the jsonrpc handler
        let http_middleware = tower::ServiceBuilder::new()
            // Proxy `GET /health` requests to internal `system_health` method.
            .layer(ProxyGetRequestLayer::new("/health", "system_health")?)
            .timeout(self.args.rpc_timeout);

        let rpc_metric_middleware = MetricsLayer::<RPCMethodExtractor, Request<'static>>::new(
            "rundler-eth-service".to_string(),
            "rpc".to_string(),
        );

        let server = ServerBuilder::default()
            .set_http_middleware(http_middleware)
            .set_rpc_middleware(rpc_metric_middleware)
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

impl<P, B, PR, E06, E07> RpcTask<P, B, PR, E06, E07> {
    /// Creates a new RPC server task.
    pub fn new(
        args: Args,
        pool: P,
        builder: B,
        provider: Arc<PR>,
        ep_06: Option<E06>,
        ep_07: Option<E07>,
    ) -> Self {
        Self {
            args,
            pool,
            builder,
            provider,
            ep_06,
            ep_07,
        }
    }
}

impl<P, B, PR, E06, E07> RpcTask<P, B, PR, E06, E07>
where
    P: Pool + HealthCheck + Clone,
    B: Builder + HealthCheck + Clone,
    PR: Provider,
    E06: EntryPointProvider<UserOperationV0_6>,
    E07: EntryPointProvider<UserOperationV0_7>,
{
    /// Converts the task into a boxed trait object.
    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }

    fn attach_namespaces(
        &self,
        entry_point_router: EntryPointRouter,
        module: &mut RpcModule<()>,
    ) -> anyhow::Result<()> {
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
                    Arc::clone(&self.provider),
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
