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

use anyhow::Context;
use futures_util::FutureExt;
use http::{header::CONTENT_TYPE, HeaderValue};
use jsonrpsee::{
    server::{middleware::http::ProxyGetRequestLayer, RpcServiceBuilder, ServerBuilder},
    RpcModule,
};
use rundler_provider::Providers as ProvidersT;
use rundler_sim::{
    gas::{self, FeeEstimatorImpl, FeeOracle},
    EstimationSettings, FeeEstimator, GasEstimatorV0_6, GasEstimatorV0_7, PrecheckSettings,
};
use rundler_task::{
    server::{format_socket_addr, HealthCheck},
    TaskSpawner,
};
use rundler_types::{builder::Builder as BuilderT, chain::ChainSpec, pool::Pool as PoolT};
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
    pub async fn spawn<T: TaskSpawner>(self, task_spawner: T) -> anyhow::Result<()> {
        let addr: SocketAddr = format_socket_addr(&self.args.host, self.args.port).parse()?;
        tracing::info!("Starting rpc server on {}", addr);

        let mut router_builder = EntryPointRouterBuilder::default();
        let fee_oracle = Arc::<dyn FeeOracle>::from(gas::get_fee_oracle(
            &self.args.chain_spec,
            self.providers.evm().clone(),
        ));
        let fee_estimator = FeeEstimatorImpl::new(
            self.providers.evm().clone(),
            fee_oracle,
            self.args.precheck_settings.priority_fee_mode,
            self.args.precheck_settings.bundle_base_fee_overhead_percent,
            self.args
                .precheck_settings
                .bundle_priority_fee_overhead_percent,
        );

        if self.args.entry_point_v0_6_enabled {
            let ep = self
                .providers
                .ep_v0_6()
                .clone()
                .context("entry point v0.6 not supplied")?;

            router_builder = router_builder.v0_6(EntryPointRouteImpl::new(
                ep.clone(),
                GasEstimatorV0_6::new(
                    self.args.chain_spec.clone(),
                    self.providers.evm().clone(),
                    ep.clone(),
                    self.args.estimation_settings,
                    fee_estimator.clone(),
                ),
                UserOperationEventProviderV0_6::new(
                    self.args.chain_spec.clone(),
                    self.providers.evm().clone(),
                    self.args
                        .eth_api_settings
                        .user_operation_event_block_distance,
                ),
            ));
        }

        if self.args.entry_point_v0_7_enabled {
            let ep = self
                .providers
                .ep_v0_7()
                .clone()
                .context("entry point v0.7 not supplied")?;

            router_builder = router_builder.v0_7(EntryPointRouteImpl::new(
                ep.clone(),
                GasEstimatorV0_7::new(
                    self.args.chain_spec.clone(),
                    self.providers.evm().clone(),
                    ep.clone(),
                    self.args.estimation_settings,
                    fee_estimator.clone(),
                ),
                UserOperationEventProviderV0_7::new(
                    self.args.chain_spec.clone(),
                    self.providers.evm().clone(),
                    self.args
                        .eth_api_settings
                        .user_operation_event_block_distance,
                ),
            ));
        }

        // create the entry point router
        let router = router_builder.build();

        let mut module = RpcModule::new(());
        self.attach_namespaces(router, fee_estimator, &mut module)?;

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
                )
                .into_rpc(),
            )?;
        }

        Ok(())
    }
}
