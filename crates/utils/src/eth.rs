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

//! Utilities for working with an Ethereum-like chain via Ethers.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use ethers::{
    abi::{AbiDecode, RawLog},
    contract::ContractError,
    providers::{
        Http, HttpRateLimitRetryPolicy, Middleware, Provider, RetryClient, RetryClientBuilder,
    },
    types::{Bytes, Log},
};
use url::Url;

/// Gets the revert data from a contract error if it is a revert error,
/// otherwise returns the original error.
pub fn get_revert_bytes<M: Middleware>(error: ContractError<M>) -> Result<Bytes, ContractError<M>> {
    if let ContractError::Revert(bytes) = error {
        Ok(bytes)
    } else {
        Err(error)
    }
}

/// The abi for what happens when you just `revert("message")` in a contract
#[derive(Clone, Debug, Default, Eq, PartialEq, ethers::contract::EthError)]
#[etherror(name = "Error", abi = "Error(string)")]
pub struct ContractRevertError {
    /// Revert reason
    pub reason: String,
}

/// Parses the revert message from the revert data
pub fn parse_revert_message(revert_data: &[u8]) -> Option<String> {
    ContractRevertError::decode(revert_data)
        .ok()
        .map(|err| err.reason)
}

/// Construct a new Ethers provider from a URL and a poll interval.
///
/// Creates a provider with a retry client that retries 10 times, with an initial backoff of 500ms.
pub fn new_provider(
    url: &str,
    poll_interval: Option<Duration>,
) -> anyhow::Result<Arc<Provider<RetryClient<Http>>>> {
    let parsed_url = Url::parse(url).context("provider url should be valid")?;

    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(1))
        .build()
        .context("failed to build reqwest client")?;
    let http = Http::new_with_client(parsed_url, http_client);

    let client = RetryClientBuilder::default()
        // these retries are if the server returns a 429
        .rate_limit_retries(10)
        // these retries are if the connection is dubious
        .timeout_retries(3)
        .initial_backoff(Duration::from_millis(500))
        .build(http, Box::<HttpRateLimitRetryPolicy>::default());

    let mut provider = Provider::new(client);
    if let Some(poll_interval) = poll_interval {
        provider = provider.interval(poll_interval);
    }

    Ok(Arc::new(provider))
}

/// Converts an ethers `Log` into an ethabi `RawLog`.
pub fn log_to_raw_log(log: Log) -> RawLog {
    let Log { topics, data, .. } = log;
    RawLog {
        topics,
        data: data.to_vec(),
    }
}
