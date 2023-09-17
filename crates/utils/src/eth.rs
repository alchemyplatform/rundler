//! Utilities for working with an Ethereum-like chain via Ethers.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use ethers::{
    abi::AbiDecode,
    contract::ContractError,
    providers::{
        Http, HttpRateLimitRetryPolicy, Middleware, Provider, RetryClient, RetryClientBuilder,
    },
    types::Bytes,
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
    poll_interval: Duration,
) -> anyhow::Result<Arc<Provider<RetryClient<Http>>>> {
    let parsed_url = Url::parse(url).context("provider url should be valid")?;
    let http = Http::new(parsed_url);
    let client = RetryClientBuilder::default()
        // these retries are if the server returns a 429
        .rate_limit_retries(10)
        // these retries are if the connection is dubious
        .timeout_retries(3)
        .initial_backoff(Duration::from_millis(500))
        .build(http, Box::<HttpRateLimitRetryPolicy>::default());
    Ok(Arc::new(Provider::new(client).interval(poll_interval)))
}
