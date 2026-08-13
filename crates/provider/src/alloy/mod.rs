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
use alloy_transport::{TransportError, TransportErrorKind};
use evm::AlloyEvmProvider;
use metrics::AlloyMetricLayer;
use tower::{BoxError, ServiceBuilder, timeout::error::Elapsed};
use url::Url;

use crate::EvmProvider;

mod da;
pub use da::new_alloy_da_gas_oracle;
mod consistency_retry;
pub(crate) mod entry_point;
pub(crate) mod evm;
pub(crate) mod metrics;

/// Configuration for an Alloy network provider
#[derive(Debug, Clone)]
pub struct AlloyNetworkConfig {
    /// RPC URL
    pub rpc_url: Url,
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

/// Alchemy's internal RPC backend domain. Response compression is only
/// requested for hosts on this domain: it's the one endpoint we know
/// supports and benefits from it, and we don't want to change negotiated
/// behavior for other hosts (e.g. third-party RPC providers, the Flashbots
/// relay) just because this binary is compiled with gzip/brotli support.
const ALCHEMY_INTERNAL_RPC_DOMAIN: &str = "d.alchemy.com";
const ALCHEMY_INTERNAL_RPC_SUBDOMAIN_SUFFIX: &str = ".d.alchemy.com";

fn host_supports_response_compression(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    // Trim a trailing DNS root-label dot (`d.alchemy.com.` is the same host
    // as `d.alchemy.com`) before matching.
    let host = host.strip_suffix('.').unwrap_or(host);
    host == ALCHEMY_INTERNAL_RPC_DOMAIN || host.ends_with(ALCHEMY_INTERNAL_RPC_SUBDOMAIN_SUFFIX)
}

/// Builds the `reqwest::Client` used for RPC requests to `rpc_url`, requesting
/// response compression only when `rpc_url` is on Alchemy's internal RPC
/// domain.
fn build_http_client(rpc_url: &Url) -> reqwest::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if !host_supports_response_compression(rpc_url) {
        builder = builder.no_gzip().no_brotli();
    }
    builder.build()
}

/// Create a new alloy provider from a given RPC URL
pub fn new_alloy_provider(
    config: &AlloyNetworkConfig,
) -> anyhow::Result<impl AlloyProvider<AnyNetwork> + Clone + use<>> {
    let http_client = build_http_client(&config.rpc_url)?;

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

    // Build the client with layers based on configuration
    let client = match (
        config.rate_limit_retry_enabled,
        config.consistency_retry_enabled,
    ) {
        (true, true) => ClientBuilder::default()
            .layer(create_rate_limit_layer(config))
            .layer(create_consistency_layer(config))
            .layer(metric_layer)
            .layer(timeout_layer)
            .http_with_client(http_client, config.rpc_url.clone()),
        (true, false) => ClientBuilder::default()
            .layer(create_rate_limit_layer(config))
            .layer(metric_layer)
            .layer(timeout_layer)
            .http_with_client(http_client, config.rpc_url.clone()),
        (false, true) => ClientBuilder::default()
            .layer(create_consistency_layer(config))
            .layer(metric_layer)
            .layer(timeout_layer)
            .http_with_client(http_client, config.rpc_url.clone()),
        (false, false) => ClientBuilder::default()
            .layer(metric_layer)
            .layer(timeout_layer)
            .http_with_client(http_client, config.rpc_url.clone()),
    };

    Ok(ProviderBuilder::new()
        .network::<AnyNetwork>()
        .connect_client(client))
}

/// Maps errors from a [`tower::timeout::Timeout`]-wrapped transport back to
/// [`TransportError`], as required by alloy's `Transport` contract.
fn map_timeout_error(error: BoxError) -> TransportError {
    match error.downcast::<Elapsed>() {
        Ok(_) => TransportError::local_usage_str("provider request timeout from client side"),
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
    use flate2::{Compression, write::GzEncoder};
    use futures_util::future;
    use tiny_http::{Header, Response, Server};
    use tower::{Service, ServiceBuilder, ServiceExt, util::service_fn};
    use url::Url;

    use crate::{
        alloy::{
            AlloyNetworkConfig, build_http_client, host_supports_response_compression,
            map_timeout_error,
        },
        new_alloy_provider,
    };

    #[test]
    fn compression_only_negotiated_for_alchemy_internal_domain() {
        let compressible = [
            "https://d.alchemy.com/v2/key",
            "https://eth-mainnet.d.alchemy.com/v2/key",
            "https://arb-mainnet.d.alchemy.com/v2/key",
            // a trailing DNS root-label dot is the same host as without one
            "https://d.alchemy.com./v2/key",
            "https://eth-mainnet.d.alchemy.com./v2/key",
        ];
        for url in compressible {
            assert!(
                host_supports_response_compression(&url.parse().unwrap()),
                "expected {url} to be treated as compressible"
            );
        }

        let not_compressible = [
            "https://eth-mainnet.g.alchemy.com/v2/key",
            "https://relay.flashbots.net",
            "http://localhost:9009",
            // must not match on a bare substring/missing subdomain separator
            "https://notd.alchemy.com",
            "https://d.alchemy.com.evil.com",
        ];
        for url in not_compressible {
            assert!(
                !host_supports_response_compression(&url.parse().unwrap()),
                "expected {url} to NOT be treated as compressible"
            );
        }
    }

    /// Proves the actual wiring, not just the URL-matching predicate: a
    /// client built for an Alchemy-internal decision URL negotiates
    /// compression and transparently decompresses; a client built for any
    /// other decision URL does not, even against a server that sends a
    /// gzip-encoded response unconditionally. The decision URL only informs
    /// how the client is built - both clients send their actual request to
    /// the same local hermetic server, matching production where the
    /// decision URL and the request destination are the same `rpc_url`.
    #[tokio::test]
    async fn compression_wiring_end_to_end() {
        use std::io::Write;

        const PLAINTEXT: &[u8] =
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"pad pad pad pad pad pad pad pad\"}";

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(PLAINTEXT).unwrap();
        let compressed = encoder.finish().unwrap();

        let server = Server::http("127.0.0.1:0").unwrap();
        let local_url: Url = format!("http://{}", server.server_addr()).parse().unwrap();
        let compressed_for_server = compressed.clone();
        thread::spawn(move || {
            for request in server.incoming_requests() {
                let response = Response::from_data(compressed_for_server.clone()).with_header(
                    Header::from_bytes(&b"Content-Encoding"[..], &b"gzip"[..]).unwrap(),
                );
                let _ = request.respond(response);
            }
        });

        let alchemy_decision_url: Url = "https://eth-mainnet.d.alchemy.com/v2/key".parse().unwrap();
        let alchemy_client = build_http_client(&alchemy_decision_url).unwrap();
        let resp = alchemy_client
            .post(local_url.clone())
            .body("{}")
            .send()
            .await
            .expect("request to local hermetic server failed");
        assert!(
            resp.headers().get("content-encoding").is_none(),
            "content-encoding should be stripped once reqwest decodes the body"
        );
        let body = resp.bytes().await.unwrap();
        assert_eq!(
            body.as_ref(),
            PLAINTEXT,
            "expected transparent decompression for an Alchemy-internal decision URL"
        );

        let other_decision_url: Url = "https://relay.flashbots.net".parse().unwrap();
        let other_client = build_http_client(&other_decision_url).unwrap();
        let resp = other_client
            .post(local_url)
            .body("{}")
            .send()
            .await
            .expect("request to local hermetic server failed");
        assert_eq!(
            resp.headers()
                .get("content-encoding")
                .map(|v| v.to_str().unwrap()),
            Some("gzip"),
            "content-encoding should be left untouched when compression isn't negotiated"
        );
        let body = resp.bytes().await.unwrap();
        assert_eq!(
            body.as_ref(),
            compressed.as_slice(),
            "expected raw undecoded bytes for a non-Alchemy decision URL"
        );
    }

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
