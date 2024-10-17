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

use alloy_provider::{Provider as AlloyProvider, ProviderBuilder};
use alloy_rpc_client::ClientBuilder;
use alloy_transport::layers::RetryBackoffService;
use alloy_transport_http::Http;
use anyhow::Context;
use evm::AlloyEvmProvider;
use metrics::{AlloyMetricLayer, AlloyMetricMiddleware};
use reqwest::Client;
use url::Url;

use crate::EvmProvider;

mod da;
pub use da::new_alloy_da_gas_oracle;
pub(crate) mod entry_point;
pub(crate) mod evm;
pub(crate) mod metrics;

/// Create a new alloy evm provider from a given RPC URL
pub fn new_alloy_evm_provider(rpc_url: &str) -> anyhow::Result<impl EvmProvider + Clone> {
    let provider = new_alloy_provider(rpc_url)?;
    Ok(AlloyEvmProvider::new(provider))
}

/// Create a new alloy provider from a given RPC URL
pub fn new_alloy_provider(
    rpc_url: &str,
) -> anyhow::Result<
    impl AlloyProvider<RetryBackoffService<AlloyMetricMiddleware<Http<Client>>>> + Clone,
> {
    let url = Url::parse(rpc_url).context("invalid rpc url")?;
    let metric_layer = AlloyMetricLayer::default();
    let retry_layer = alloy_transport::layers::RetryBackoffLayer::new(10, 500, 0);
    let client = ClientBuilder::default()
        .layer(retry_layer)
        .layer(metric_layer)
        .http(url);
    let provider = ProviderBuilder::new().on_client(client);
    Ok(provider)
}
