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

use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use futures_util::FutureExt;
use http::{HeaderValue, header::CONTENT_TYPE};
use jsonrpsee::{
    RpcModule,
    server::{RpcServiceBuilder, ServerBuilder, middleware::http::ProxyGetRequestLayer},
};
use rundler_task::{TaskSpawnerExt, server::format_socket_addr};
use tracing::info;

use crate::{
    admin::{AdminApi, AdminApiServer},
    chain_resolver::ChainResolver,
    debug::{DebugApi, DebugApiServer},
    eth::{EthApi, EthApiServer},
    gateway::{ChainRouter, ChainRoutingLayer},
    health::{HealthChecker, SystemApiServer},
    rpc_metrics::{HttpMetricMiddlewareLayer, RpcMetricsMiddlewareLayer},
    rundler::{RundlerApi, RundlerApiServer, RundlerApiSettings},
    types::ApiNamespace,
};

/// RPC server arguments.
#[derive(Debug)]
pub struct Args {
    /// Port to listen on.
    pub port: u16,
    /// Host to listen on.
    pub host: String,
    /// List of API namespaces to enable.
    pub api_namespaces: Vec<ApiNamespace>,
    /// Whether permissions are enabled.
    pub permissions_enabled: bool,
    /// rundler_ API settings.
    pub rundler_api_settings: RundlerApiSettings,
    /// RPC timeout.
    pub rpc_timeout: Duration,
    /// Max number of connections.
    pub max_connections: u32,
    /// Max request body size in bytes.
    pub max_request_body_size: u32,
    /// CORS domains.
    pub corsdomain: Option<Vec<HeaderValue>>,
    /// If Some, add ChainRoutingMiddleware (gateway mode). If None, node mode.
    pub chain_routing: Option<HashSet<u64>>,
}

/// Unified JSON-RPC server task for both node and gateway modes.
pub struct RpcTask {
    args: Args,
    router: ChainRouter,
}

impl RpcTask {
    /// Creates a new RPC server task.
    pub fn new(args: Args, router: ChainRouter) -> Self {
        Self { args, router }
    }

    /// Spawns the RPC server task on the given task spawner.
    pub async fn spawn<T>(self, task_spawner: T) -> anyhow::Result<()>
    where
        T: TaskSpawnerExt,
    {
        let addr: SocketAddr = format_socket_addr(&self.args.host, self.args.port)
            .parse()
            .context("Invalid server address")?;

        let is_gateway = self.args.chain_routing.is_some();
        let mode = if is_gateway { "gateway" } else { "rpc" };
        info!("Starting {} server on {}", mode, addr);

        if is_gateway {
            info!(
                "Configured chains: {:?}",
                self.router.chain_ids().collect::<Vec<_>>()
            );
        }

        if self.router.is_empty() {
            anyhow::bail!("No chains configured");
        }

        let router = Arc::new(self.router);

        let module = build_rpc_module(
            router.clone(),
            self.args.permissions_enabled,
            self.args.rundler_api_settings,
            &self.args.api_namespaces,
        )?;

        // Health check using the router (covers all chain backends)
        let health_checker = HealthChecker::new(router.clone());

        let mut full_module = module;
        full_module.merge(health_checker.into_rpc())?;

        // Set up CORS
        let cors_layer = self.args.corsdomain.map(|layers| {
            use tower_http::cors::{AllowOrigin, Any};
            const WILDCARD: HeaderValue = HeaderValue::from_static("*");
            let allow_origin: AllowOrigin = if layers.contains(&WILDCARD) && layers.len() == 1 {
                Any.into()
            } else {
                layers.into()
            };
            tower_http::cors::CorsLayer::new()
                .allow_methods([http::Method::GET, http::Method::POST])
                .allow_origin(allow_origin)
                .allow_headers([CONTENT_TYPE])
        });

        // Build HTTP middleware
        let http_middleware = tower::ServiceBuilder::new()
            .option_layer(cors_layer)
            .option_layer(self.args.chain_routing.map(ChainRoutingLayer::new))
            .layer(ProxyGetRequestLayer::new("/health", "system_health")?)
            .timeout(self.args.rpc_timeout)
            .layer(HttpMetricMiddlewareLayer::new(format!(
                "rundler-{}-service-http",
                mode
            )));

        let rpc_metric_middleware = RpcServiceBuilder::new().layer(RpcMetricsMiddlewareLayer::new(
            format!("rundler-{}-service", mode),
        ));

        let server = ServerBuilder::default()
            .set_rpc_middleware(rpc_metric_middleware)
            .set_http_middleware(http_middleware)
            .max_connections(self.args.max_connections)
            .max_request_body_size(self.args.max_request_body_size)
            .http_only()
            .build(addr)
            .await?;

        let handle = server.start(full_module);

        let task_name = if is_gateway {
            "gateway server"
        } else {
            "rpc server"
        };

        task_spawner.spawn_critical(
            task_name,
            async move {
                handle.stopped().await;
                tracing::error!("{} stopped", task_name);
            }
            .boxed(),
        );

        info!("Started {}", task_name);

        Ok(())
    }
}

/// Build an [`RpcModule`] with API namespaces using a [`ChainResolver`].
pub fn build_rpc_module<R: ChainResolver>(
    resolver: Arc<R>,
    permissions_enabled: bool,
    rundler_api_settings: RundlerApiSettings,
    api_namespaces: &[ApiNamespace],
) -> anyhow::Result<RpcModule<()>> {
    let mut module = RpcModule::new(());

    if api_namespaces.contains(&ApiNamespace::Eth) {
        module.merge(EthApi::new(resolver.clone(), permissions_enabled).into_rpc())?;
    }

    if api_namespaces.contains(&ApiNamespace::Debug) {
        module.merge(DebugApi::new(resolver.clone()).into_rpc())?;
    }

    if api_namespaces.contains(&ApiNamespace::Admin) {
        module.merge(AdminApi::new(resolver.clone()).into_rpc())?;
    }

    if api_namespaces.contains(&ApiNamespace::Rundler) {
        module.merge(RundlerApi::new(resolver, rundler_api_settings).into_rpc())?;
    }

    Ok(module)
}
