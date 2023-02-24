use anyhow::Context;
use ethers::abi::RawLog;
use ethers::contract::builders::ContractCall;
use ethers::core::k256::ecdsa::SigningKey;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{
    Http, JsonRpcClient, Middleware, PendingTransaction, Provider, ProviderError,
};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, Bytes, Log, TransactionReceipt, TransactionRequest};
use ethers::utils;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

/// Creates a provider that connects to a locally running Geth node on its
/// default port of 8545.
pub fn new_local_provider() -> Arc<Provider<Http>> {
    // Set low interval because Geth node in --dev mode mines very quickly once
    // it sees a transaction. By default, the provider waits seven seconds to
    // poll for new blocks, which is excruciating while testing.
    let provider = Provider::<Http>::try_from("http://localhost:8545")
        .expect("localhost url should parse")
        .interval(Duration::from_millis(100));
    Arc::new(provider)
}

/// Given a provider connected to a Geth node in --dev mode, grants a large
/// amount of ETH to the specified address.
pub async fn grant_dev_eth(provider: &Provider<Http>, to: Address) -> anyhow::Result<()> {
    // A Geth node in --dev mode has one account with massive amounts of ETH.
    let funder_address = *provider
        .get_accounts()
        .await
        .context("should be able to get accounts from node")?
        .first()
        .context("a Geth node in dev mode should have one account")?;
    // 1000 ETH ought to be enough for anyone.
    let value = utils::parse_ether(1000).unwrap();
    let tx = provider.send_transaction(
        TransactionRequest::pay(to, value).from(funder_address),
        None,
    );
    await_mined_tx(tx, "grant ETH").await?;
    Ok(())
}

/// Waits for a pending transaction to be mined, providing appropriate error
/// messages for each point of failure.
pub async fn await_mined_tx<'a>(
    tx: impl Future<Output = Result<PendingTransaction<'a, impl JsonRpcClient + 'a>, ProviderError>>,
    action: &str,
) -> anyhow::Result<TransactionReceipt> {
    tx.await
        .with_context(|| format!("should send transaction to {action}"))?
        .await
        .with_context(|| format!("should wait for transaction to {action}"))?
        .with_context(|| format!("transaction to {action} should not be dropped"))
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

pub async fn get_chain_id(provider: &Provider<Http>) -> anyhow::Result<u32> {
    Ok(provider
        .get_chainid()
        .await
        .context("should get chain id")?
        .as_u32())
}

/// Creates a client that can send transactions and sign them with a secret
/// based on a fixed id. Can be used to generate accounts with deterministic
/// addresses for testing.
pub fn new_test_client(
    provider: &Arc<Provider<Http>>,
    test_account_id: u8,
    chain_id: u32,
) -> Arc<SignerMiddleware<Arc<Provider<Http>>, LocalWallet>> {
    let wallet = new_test_wallet(test_account_id, chain_id);
    Arc::new(SignerMiddleware::new(Arc::clone(provider), wallet))
}

/// Creates a wallet whose secret is based on a fixed id. Differs from
/// `new_test_client` in that a wallet on its own can only sign messages but
/// not send transactions.
pub fn new_test_wallet(test_account_id: u8, chain_id: u32) -> LocalWallet {
    let mut bytes = [0_u8; 32];
    bytes[31] = test_account_id;
    let key = SigningKey::from_bytes(&bytes).expect("should create signing key for test wallet");
    LocalWallet::from(key).with_chain_id(chain_id)
}
