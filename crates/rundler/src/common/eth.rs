use std::{error, future::Future, ops::Deref, sync::Arc, time::Duration};

use anyhow::Context;
use ethers::{
    abi::RawLog,
    contract::{builders::ContractCall, Contract, ContractDeployer, ContractError},
    providers::{
        Http, HttpRateLimitRetryPolicy, JsonRpcClient, Middleware, PendingTransaction,
        Provider as EthersProvider, RetryClient, RetryClientBuilder,
    },
    types::{Address, Bytes, Log, TransactionReceipt},
};
use url::Url;

pub fn new_provider(
    url: &str,
    poll_interval: Duration,
) -> anyhow::Result<Arc<EthersProvider<RetryClient<Http>>>> {
    let parsed_url = Url::parse(url).context("provider url should be valid")?;
    let http = Http::new(parsed_url);
    let client = RetryClientBuilder::default()
        // these retries are if the server returns a 429
        .rate_limit_retries(10)
        // these retries are if the connection is dubious
        .timeout_retries(3)
        .initial_backoff(Duration::from_millis(500))
        .build(http, Box::<HttpRateLimitRetryPolicy>::default());
    Ok(Arc::new(
        EthersProvider::new(client).interval(poll_interval),
    ))
}

/// Waits for a pending transaction to be mined, providing appropriate error
/// messages for each point of failure.
pub async fn await_mined_tx<'a, Fut, C, Err>(
    tx: Fut,
    action: &str,
) -> anyhow::Result<TransactionReceipt>
where
    Fut: Future<Output = Result<PendingTransaction<'a, C>, Err>>,
    C: JsonRpcClient + 'a,
    Err: error::Error + Send + Sync + 'static,
{
    tx.await
        .with_context(|| format!("should send transaction to {action}"))?
        .await
        .with_context(|| format!("should wait for transaction to {action}"))?
        .with_context(|| format!("transaction to {action} should not be dropped"))
}

/// Waits for a contract deployment, providing appropriate error messages.
pub async fn await_contract_deployment<M, C>(
    deployer: Result<ContractDeployer<M, C>, ContractError<M>>,
    contract_name: &str,
) -> anyhow::Result<C>
where
    M: Middleware + 'static,
    C: From<Contract<M>>,
{
    deployer
        .with_context(|| format!("should create deployer for {contract_name}"))?
        .send()
        .await
        .with_context(|| format!("should deploy {contract_name}"))
}

/// Changes out a contract object's signer and returns a new contract of the
/// same type. Needed because although the general-purpose `Contract` has a
/// `.connect()` method to do this, specialized contract objects do not.
pub fn connect_contract<M, C>(contract: &C, provider: Arc<M>) -> C
where
    M: Clone + Middleware,
    C: Deref<Target = Contract<M>> + From<Contract<M>>,
{
    contract.connect(provider).into()
}

/// Packs an address followed by call data into a single `Bytes`. This is used
/// in ERC-4337 for calling wallets, factories, and paymasters.
pub fn compact_call_data<M, D>(address: Address, call: ContractCall<M, D>) -> Bytes {
    let mut bytes = address.as_bytes().to_vec();
    if let Some(call_data) = call.tx.data() {
        bytes.extend(call_data);
    }
    bytes.into()
}

/// Converts an ethers `Log` into an ethabi `RawLog`.
pub fn log_to_raw_log(log: Log) -> RawLog {
    let Log { topics, data, .. } = log;
    RawLog {
        topics,
        data: data.to_vec(),
    }
}

pub async fn get_chain_id<Client: JsonRpcClient>(
    provider: &EthersProvider<Client>,
) -> anyhow::Result<u32> {
    Ok(provider
        .get_chainid()
        .await
        .context("should get chain id")?
        .as_u32())
}

#[derive(Copy, Clone, Debug)]
pub struct Settings {
    pub user_operation_event_block_distance: Option<u64>,
}

impl Settings {
    pub fn new(block_distance: Option<u64>) -> Self {
        Self {
            user_operation_event_block_distance: block_distance,
        }
    }
}
