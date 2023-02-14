use alchemy_bundler::common::contracts::EntryPoint;
use anyhow::Context;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::TransactionRequest;
use std::str::FromStr;
use std::sync::Arc;

const DEPLOYER_PRIVATE_KEY: &str =
    "0000000000000000000000000010000000000000000000000000000000000001";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = Provider::<Http>::try_from("http://localhost:8545")?;
    let funder_address = *provider
        .get_accounts()
        .await
        .context("should be able to get accounts from node")?
        .first()
        .context("Geth node in dev mode should have one account")?;
    println!("Funder address: {funder_address:?}");
    let deployer_wallet = LocalWallet::from_str(DEPLOYER_PRIVATE_KEY)?;
    println!("Deployer address: {:?}", deployer_wallet.address());
    let tx = provider
        .send_transaction(
            TransactionRequest::pay(deployer_wallet.address(), 1000000000000000000_u64)
                .from(funder_address),
            None,
        )
        .await
        .context("should send transaction to fund deployer")?;
    println!("Sent ETH to deployer. Waiting to mine.");
    tx.await
        .context("should mine transaction to fund deployer")?
        .context("transaction to fund deployer shouldn't be dropped")?;
    println!("ETH received by deployer.");
    let client = SignerMiddleware::new_with_provider_chain(provider, deployer_wallet)
        .await
        .context("should create client with provider chain")?;
    let client = Arc::new(client);
    let deployer = EntryPoint::deploy(Arc::clone(&client), ())
        .context("failed to create contract deployer")?;
    println!("Deploying EntryPoint.");
    let entry_point = deployer
        .send()
        .await
        .context("entry point deployment failed")?;
    println!("EntryPoint deployed at {:?}", entry_point.address());
    Ok(())
}
