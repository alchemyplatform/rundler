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

use alloy_provider::{Provider as AlloyProvider, ProviderBuilder};
use alloy_rpc_client::ClientBuilder;
use alloy_transport::layers::RetryBackoffService;
use alloy_transport_http::Http;
use anyhow::Context;
use evm::AlloyEvmProvider;
use metrics::{AlloyMetricLayer, AlloyMetricMiddleware};
use provider_timeout::{ProviderTimeout, ProviderTimeoutLayer};
use reqwest::Client;
use url::Url;

use crate::EvmProvider;

mod da;
pub use da::new_alloy_da_gas_oracle;
pub(crate) mod entry_point;
pub(crate) mod evm;
pub(crate) mod metrics;
mod provider_timeout;

/// Create a new alloy evm provider from a given RPC URL
pub fn new_alloy_evm_provider(
    rpc_url: &str,
    provider_client_timeout_seconds: u64,
) -> anyhow::Result<impl EvmProvider + Clone> {
    let provider = new_alloy_provider(rpc_url, provider_client_timeout_seconds)?;
    Ok(AlloyEvmProvider::new(provider))
}

/// Create a new alloy provider from a given RPC URL
pub fn new_alloy_provider(
    rpc_url: &str,
    provider_client_timeout_seconds: u64,
) -> anyhow::Result<
    impl AlloyProvider<RetryBackoffService<AlloyMetricMiddleware<ProviderTimeout<Http<Client>>>>>
        + Clone,
> {
    let url = Url::parse(rpc_url).context("invalid rpc url")?;
    let metric_layer = AlloyMetricLayer::default();
    // TODO: make this configurable: use a large number for CUPS for now
    let retry_layer = alloy_transport::layers::RetryBackoffLayer::new(10, 500, 1_000_000);
    // add a timeout layer here.
    let timeout_layer =
        ProviderTimeoutLayer::new(Duration::from_secs(provider_client_timeout_seconds));
    let client = ClientBuilder::default()
        .layer(retry_layer)
        .layer(metric_layer)
        .layer(timeout_layer)
        .http(url);
    let provider = ProviderBuilder::new().on_client(client);
    Ok(provider)
}

#[cfg(test)]
mod tests {
    use std::{
        thread::{self, sleep},
        time::Duration,
    };

    use alloy_provider::Provider;
    use tiny_http::{Response, Server};

    use crate::new_alloy_provider;
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
        thread::spawn(move || {
            setup();
        });
        {
            // Wait 11 seconds and get result
            let provider = new_alloy_provider("http://localhost:9009", 15)
                .expect("can not initialize provider");
            let x = provider.get_block_number().await;
            assert!(x.is_ok());
        }
        {
            // Wait 9 seconds and timeout form client side
            let provider = new_alloy_provider("http://localhost:9009", 1)
                .expect("can not initialize provider");
            let x = provider.get_block_number().await;
            assert!(x.is_err());
        }
    }
}
