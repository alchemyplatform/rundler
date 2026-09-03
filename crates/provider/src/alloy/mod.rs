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

use alloy_provider::{Provider as AlloyProvider, ProviderBuilder, network::AnyNetwork};
use alloy_rpc_client::ClientBuilder;
use alloy_transport::{BoxTransport, IntoBoxTransport, TransportError, TransportErrorKind};
use alloy_transport_http::Http;
use evm::AlloyEvmProvider;
use metrics::AlloyMetricLayer;
use tower::{BoxError, Layer, ServiceBuilder, timeout::error::Elapsed};
use url::Url;

use crate::EvmProvider;

mod da;
pub use da::new_alloy_da_gas_oracle;
mod consistency_retry;
pub(crate) mod entry_point;
pub(crate) mod evm;
pub(crate) mod metrics;
mod priority_fallback;

use priority_fallback::PriorityFallbackLayer;

const CLIENT_TIMEOUT_ERROR: &str = "provider request timeout from client side";

/// Configuration for an Alloy network provider
#[derive(Debug, Clone)]
pub struct AlloyNetworkConfig {
    /// RPC URL
    pub rpc_url: Url,
    /// Ordered fallback RPC URLs
    pub rpc_fallback_urls: Vec<Url>,
    /// How long to keep using a fallback before probing the primary again
    pub fallback_recovery_interval_seconds: u64,
    /// Client timeout in seconds
    pub client_timeout_seconds: u64,
    /// Whether to enable consistency retry
    pub consistency_retry_enabled: bool,
    /// Consistency retry max retries
    pub consistency_retry_max_retries: u32,
    /// Consistency retry initial backoff in milliseconds
    pub consistency_retry_initial_backoff_ms: u64,
    /// Consistency retry max backoff in milliseconds
    pub consistency_retry_max_backoff_ms: u64,
    /// Whether to enable rate limit retry
    pub rate_limit_retry_enabled: bool,
    /// Rate limit retry max retries
    pub rate_limit_retry_max_retries: u32,
    /// Rate limit retry initial backoff in milliseconds
    pub rate_limit_retry_initial_backoff_ms: u64,
    /// Rate limit compute units per second
    pub rate_limit_compute_units_per_second: u64,
}

impl Default for AlloyNetworkConfig {
    fn default() -> Self {
        Self {
            rpc_url: Url::parse("http://localhost:9009").unwrap(),
            rpc_fallback_urls: Vec::new(),
            fallback_recovery_interval_seconds: 30,
            client_timeout_seconds: 15,
            consistency_retry_enabled: false,
            consistency_retry_max_retries: 5,
            consistency_retry_initial_backoff_ms: 10,
            consistency_retry_max_backoff_ms: 1_000,
            rate_limit_retry_enabled: true,
            rate_limit_retry_max_retries: 5,
            rate_limit_retry_initial_backoff_ms: 10,
            rate_limit_compute_units_per_second: 100_000_000,
        }
    }
}

/// Create a new alloy evm provider from a given RPC URL
pub fn new_alloy_evm_provider(
    config: &AlloyNetworkConfig,
) -> anyhow::Result<impl EvmProvider + Clone + use<>> {
    let provider = new_alloy_provider(config)?;
    Ok(AlloyEvmProvider::new(provider))
}

/// Create a new alloy provider from a given RPC URL
pub fn new_alloy_provider(
    config: &AlloyNetworkConfig,
) -> anyhow::Result<impl AlloyProvider<AnyNetwork> + Clone + use<>> {
    let is_local = Http::new(config.rpc_url.clone()).guess_local();
    let mut rpc_urls = Vec::with_capacity(1 + config.rpc_fallback_urls.len());
    rpc_urls.push(config.rpc_url.clone());
    rpc_urls.extend(config.rpc_fallback_urls.iter().cloned());

    let transports = rpc_urls
        .into_iter()
        .map(|rpc_url| new_http_transport(config, rpc_url))
        .collect::<Vec<_>>();
    let transport = PriorityFallbackLayer::new(Duration::from_secs(
        config.fallback_recovery_interval_seconds,
    ))
    .layer(transports);
    let client = ClientBuilder::default().transport(transport, is_local);

    Ok(ProviderBuilder::new()
        .network::<AnyNetwork>()
        .connect_client(client))
}

fn new_http_transport(config: &AlloyNetworkConfig, rpc_url: Url) -> BoxTransport {
    let create_rate_limit_layer = |config: &AlloyNetworkConfig| {
        alloy_transport::layers::RetryBackoffLayer::new(
            config.rate_limit_retry_max_retries,
            config.rate_limit_retry_initial_backoff_ms,
            config.rate_limit_compute_units_per_second,
        )
    };
    let create_consistency_layer = |config: &AlloyNetworkConfig| {
        consistency_retry::ConsistencyRetryLayer::new(
            config.consistency_retry_max_retries,
            config.consistency_retry_initial_backoff_ms,
            config.consistency_retry_max_backoff_ms,
        )
    };

    let metric_layer = AlloyMetricLayer::default();
    let timeout_layer = ServiceBuilder::new()
        .map_err(map_timeout_error)
        .timeout(Duration::from_secs(config.client_timeout_seconds));

    let transport = Http::new(rpc_url);
    match (
        config.rate_limit_retry_enabled,
        config.consistency_retry_enabled,
    ) {
        (true, true) => ServiceBuilder::new()
            .layer(create_rate_limit_layer(config))
            .layer(create_consistency_layer(config))
            .layer(metric_layer)
            .layer(timeout_layer)
            .service(transport)
            .into_box_transport(),
        (true, false) => ServiceBuilder::new()
            .layer(create_rate_limit_layer(config))
            .layer(metric_layer)
            .layer(timeout_layer)
            .service(transport)
            .into_box_transport(),
        (false, true) => ServiceBuilder::new()
            .layer(create_consistency_layer(config))
            .layer(metric_layer)
            .layer(timeout_layer)
            .service(transport)
            .into_box_transport(),
        (false, false) => ServiceBuilder::new()
            .layer(metric_layer)
            .layer(timeout_layer)
            .service(transport)
            .into_box_transport(),
    }
}

/// Maps errors from a [`tower::timeout::Timeout`]-wrapped transport back to
/// [`TransportError`], as required by alloy's `Transport` contract.
fn map_timeout_error(error: BoxError) -> TransportError {
    match error.downcast::<Elapsed>() {
        Ok(_) => TransportError::local_usage_str(CLIENT_TIMEOUT_ERROR),
        Err(error) => match error.downcast::<TransportError>() {
            Ok(error) => *error,
            // Unreachable in practice: the inner transport's error type is
            // `TransportError`, so the box holds either that or `Elapsed`.
            Err(error) => TransportErrorKind::custom_str(&error.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{
        thread::{self, sleep},
        time::Duration,
    };

    use alloy_json_rpc::RpcError;
    use alloy_provider::Provider;
    use alloy_transport::{TransportError, TransportErrorKind};
    use futures_util::future;
    use tiny_http::{Response, Server};
    use tower::{Service, ServiceBuilder, ServiceExt, util::service_fn};

    use crate::{
        alloy::{AlloyNetworkConfig, map_timeout_error},
        new_alloy_provider,
    };

    fn setup() {
        let server = Server::http("0.0.0.0:9009").unwrap();
        for request in server.incoming_requests() {
            sleep(Duration::from_secs(5));
            let _ = request.respond(Response::from_string(
                "{\"jsonrpc\": \"2.0\",	\"id\": 1,	\"result\": \"0x146b6d7\"}",
            ));
        }
    }
    #[ignore = "this test is flaky with github action, should only run locally"]
    #[tokio::test]
    async fn test_timeout() {
        let config = AlloyNetworkConfig::default();
        thread::spawn(move || {
            setup();
        });
        {
            // Wait 11 seconds and get result
            let provider = new_alloy_provider(&config).expect("can not initialize provider");
            let x = provider.get_block_number().await;
            assert!(x.is_ok());
        }
        {
            // Wait 9 seconds and timeout form client side
            let provider = new_alloy_provider(&config).expect("can not initialize provider");
            let x = provider.get_block_number().await;
            assert!(x.is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_layer_maps_elapsed_to_transport_error() {
        let mut service = ServiceBuilder::new()
            .map_err(map_timeout_error)
            .timeout(Duration::from_secs(1))
            .service(service_fn(|()| {
                future::pending::<Result<(), TransportError>>()
            }));

        let response = service.ready().await.unwrap().call(());

        tokio::time::advance(Duration::from_secs(1)).await;

        let error = response.await.unwrap_err();
        assert!(matches!(error, RpcError::LocalUsageError(_)));
        assert_eq!(
            error.to_string(),
            "local usage error: provider request timeout from client side"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_layer_passes_through_transport_errors() {
        let mut service = ServiceBuilder::new()
            .map_err(map_timeout_error)
            .timeout(Duration::from_secs(1))
            .service(service_fn(|()| async {
                Err::<(), TransportError>(TransportErrorKind::backend_gone())
            }));

        let error = service.ready().await.unwrap().call(()).await.unwrap_err();

        match error {
            RpcError::Transport(kind) => assert!(kind.is_backend_gone()),
            other => panic!("expected backend gone transport error, got {other:?}"),
        }
    }
}
