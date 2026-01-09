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

use std::{net::SocketAddr, time::Duration};

use anyhow::Context;
use futures_util::FutureExt;
use http::{HeaderValue, header::CONTENT_TYPE};
use jsonrpsee::{
    RpcModule,
    server::{RpcServiceBuilder, ServerBuilder, middleware::http::ProxyGetRequestLayer},
};
use rundler_provider::{FeeEstimator, Providers as ProvidersT};
use rundler_sim::{EstimationSettings, GasEstimatorV0_6, GasEstimatorV0_7, PrecheckSettings};
use rundler_task::{
    TaskSpawnerExt,
    server::{HealthCheck, format_socket_addr},
};
use rundler_types::{
    EntryPointAbiVersion, EntryPointVersion, builder::Builder as BuilderT, chain::ChainSpec,
    pool::Pool as PoolT,
};
use tracing::info;

use crate::{
    admin::{AdminApi, AdminApiServer},
    debug::{DebugApi, DebugApiServer},
    eth::{
        EntryPointRouteImpl, EntryPointRouter, EntryPointRouterBuilder, EthApi, EthApiServer,
        EthApiSettings, UserOperationEventProviderV0_6, UserOperationEventProviderV0_7,
    },
    health::{HealthChecker, SystemApiServer},
    rpc_metrics::{HttpMetricMiddlewareLayer, RpcMetricsMiddlewareLayer},
    rundler::{RundlerApi, RundlerApiServer},
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
    /// Estimation settings.
    pub estimation_settings: EstimationSettings,
    /// RPC timeout.
    pub rpc_timeout: Duration,
    /// Max number of connections.
    pub max_connections: u32,
    /// Enabled entry point versions
    pub enabled_entry_points: Vec<EntryPointVersion>,
    /// What domains to use in the corsdomain
    pub corsdomain: Option<Vec<HeaderValue>>,
}

/// JSON-RPC server task.
#[derive(Debug)]
pub struct RpcTask<Pool, Builder, Providers> {
    args: Args,
    pool: Pool,
    builder: Builder,
    providers: Providers,
}

impl<Pool, Builder, Providers> RpcTask<Pool, Builder, Providers> {
    /// Creates a new RPC server task.
    pub fn new(args: Args, pool: Pool, builder: Builder, providers: Providers) -> Self {
        Self {
            args,
            pool,
            builder,
            providers,
        }
    }
}

impl<Pool, Builder, Providers> RpcTask<Pool, Builder, Providers>
where
    Pool: PoolT + HealthCheck + Clone + 'static,
    Builder: BuilderT + HealthCheck + Clone + 'static,
    Providers: ProvidersT + 'static,
{
    /// Spawns the RPC server task on the given task spawner.
    pub async fn spawn<T>(self, task_spawner: T) -> anyhow::Result<()>
    where
        T: TaskSpawnerExt,
    {
        let addr: SocketAddr = format_socket_addr(&self.args.host, self.args.port).parse()?;
        tracing::info!("Starting rpc server on {}", addr);

        let mut router_builder = EntryPointRouterBuilder::default();

        for ep_version in &self.args.enabled_entry_points {
            match ep_version.abi_version() {
                EntryPointAbiVersion::V0_6 => {
                    let ep = self
                        .providers
                        .ep_v0_6()
                        .clone()
                        .context("entry point v0.6 not supplied")?;

                    router_builder = router_builder.add_route(EntryPointRouteImpl::new(
                        ep.clone(),
                        GasEstimatorV0_6::new(
                            self.args.chain_spec.clone(),
                            self.providers.evm().clone(),
                            ep.clone(),
                            self.args.estimation_settings,
                            self.providers.fee_estimator().clone(),
                        ),
                        UserOperationEventProviderV0_6::new(
                            self.args.chain_spec.clone(),
                            self.args.chain_spec.entry_point_address_v0_6,
                            self.providers.evm().clone(),
                            self.args
                                .eth_api_settings
                                .user_operation_event_block_distance,
                            self.args
                                .eth_api_settings
                                .user_operation_event_block_distance_fallback,
                        ),
                    ));
                }
                EntryPointAbiVersion::V0_7 => {
                    let ep = self
                        .providers
                        .ep_v0_7(*ep_version)
                        .clone()
                        .context(format!(
                        "entry point abi v0.7 provider not supplied for entry point version: {:?}",
                        ep_version
                    ))?;

                    router_builder = router_builder.add_route(EntryPointRouteImpl::new(
                        ep.clone(),
                        GasEstimatorV0_7::new(
                            self.args.chain_spec.clone(),
                            self.providers.evm().clone(),
                            ep.clone(),
                            self.args.estimation_settings,
                            self.providers.fee_estimator().clone(),
                        ),
                        UserOperationEventProviderV0_7::new(
                            self.args.chain_spec.clone(),
                            self.args.chain_spec.entry_point_address(*ep_version),
                            self.providers.evm().clone(),
                            self.args
                                .eth_api_settings
                                .user_operation_event_block_distance,
                            self.args
                                .eth_api_settings
                                .user_operation_event_block_distance_fallback,
                        ),
                    ));
                }
            }
        }

        // create the entry point router
        let router = router_builder.build();

        let mut module = RpcModule::new(());
        self.attach_namespaces(
            self.args.eth_api_settings.permissions_enabled,
            router,
            self.providers.fee_estimator().clone(),
            &mut module,
        )?;

        let servers: Vec<Box<dyn HealthCheck>> =
            vec![Box::new(self.pool.clone()), Box::new(self.builder.clone())];
        let health_checker = HealthChecker::new(servers);
        module.merge(health_checker.into_rpc())?;

        // Set up health check endpoint via GET /health registers the jsonrpc handler
        let http_middleware = tower::ServiceBuilder::new()
            .option_layer(self.args.corsdomain.map(|layers| {
                use tower_http::cors::{AllowOrigin, Any};
                // In the case where we pass '*', I want to be able to test the any domain.
                // but without this change the list Origins will reject if there is a wildcard present.
                // So in the case that there is just '*' passed in the args we will treat it like any
                const WILDCARD: HeaderValue = HeaderValue::from_static("*");
                let layers: AllowOrigin = if layers.contains(&WILDCARD) && layers.len() == 1 {
                    Any.into()
                } else {
                    layers.into()
                };
                tower::ServiceBuilder::new().layer(
                    tower_http::cors::CorsLayer::new()
                        // allow `GET` and `POST` when accessing the resource
                        .allow_methods([http::Method::GET, http::Method::POST])
                        // allow requests from any origin
                        .allow_origin(layers)
                        .allow_headers([CONTENT_TYPE]),
                )
            }))
            // Proxy `GET /health` requests to internal `system_health` method.
            .layer(ProxyGetRequestLayer::new("/health", "system_health")?)
            .timeout(self.args.rpc_timeout)
            .layer(HttpMetricMiddlewareLayer::new(
                "rundler-rpc-service-http".to_string(),
            ));

        let rpc_metric_middleware = RpcServiceBuilder::new().layer(RpcMetricsMiddlewareLayer::new(
            "rundler-rpc-service".to_string(),
        ));

        let server = ServerBuilder::default()
            .set_rpc_middleware(rpc_metric_middleware)
            .set_http_middleware(http_middleware)
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

        task_spawner.spawn_critical(
            "rpc server",
            async move {
                handle.stopped().await;
                tracing::error!("RPC server stopped");
            }
            .boxed(),
        );

        info!("Started RPC server");

        Ok(())
    }

    fn attach_namespaces<F: FeeEstimator + 'static>(
        &self,
        permissions_enabled: bool,
        entry_point_router: EntryPointRouter,
        fee_estimator: F,
        module: &mut RpcModule<()>,
    ) -> anyhow::Result<()> {
        if self.args.api_namespaces.contains(&ApiNamespace::Eth) {
            module.merge(
                EthApi::new(
                    self.args.chain_spec.clone(),
                    entry_point_router.clone(),
                    self.pool.clone(),
                    permissions_enabled,
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
                    entry_point_router,
                    self.pool.clone(),
                    fee_estimator,
                    self.providers.evm().clone(),
                )
                .into_rpc(),
            )?;
        }

        Ok(())
    }
}
