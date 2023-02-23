use alchemy_bundler::bundler::tracer;
use alchemy_bundler::common::contracts::entry_point::{
    EntryPoint, EntryPointErrors, EntryPointEvents,
};
use alchemy_bundler::common::contracts::simple_account::SimpleAccountEvents;
use alchemy_bundler::common::contracts::simple_account_factory::SimpleAccountFactory;
use alchemy_bundler::common::types::UserOperation;
use anyhow::Context;
use ethers::abi::{AbiDecode, RawLog};
use ethers::contract::builders::ContractCall;
use ethers::contract::{ContractError, EthLogDecode};
use ethers::middleware::signer::SignerMiddlewareError;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::ProviderError;
use ethers::providers::{Http, HttpClientError, Middleware, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, Bytes, Log, TransactionRequest, U256};
use serde_json::Value;
use std::mem;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const DEPLOYER_PRIVATE_KEY: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";
const USER_PRIVATE_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const BUNDLER_PRIVATE_KEY: &str =
    "0000000000000000000000000000000000000000000000000000000000000003";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = Arc::new(
        Provider::<Http>::try_from("http://localhost:8545")?.interval(Duration::from_millis(100)),
    );
    let chain_id = provider
        .get_chainid()
        .await
        .context("should get chain id from the provider")?
        .as_u64();
    let deployer_wallet = LocalWallet::from_str(DEPLOYER_PRIVATE_KEY)?.with_chain_id(chain_id);
    let user_eoa = LocalWallet::from_str(USER_PRIVATE_KEY)?.with_chain_id(chain_id);
    let bundler_wallet = LocalWallet::from_str(BUNDLER_PRIVATE_KEY)?.with_chain_id(chain_id);
    grant_eth(&provider, deployer_wallet.address()).await?;
    grant_eth(&provider, user_eoa.address()).await?;
    grant_eth(&provider, bundler_wallet.address()).await?;
    let deployer_client = Arc::new(SignerMiddleware::new(
        Arc::clone(&provider),
        deployer_wallet,
    ));
    let bundler_client = Arc::new(deployer_client.with_signer(bundler_wallet));
    let entry_point = EntryPoint::deploy(Arc::clone(&deployer_client), ())
        .context("should create entry point deployer")?
        .send()
        .await
        .context("should deploy entry point")?;
    println!("Entry point deployed at {:?}", entry_point.address());
    let entry_point: EntryPoint<_> = entry_point.connect(Arc::clone(&bundler_client)).into();
    let factory = SimpleAccountFactory::deploy(Arc::clone(&deployer_client), entry_point.address())
        .context("should create factory deployer")?
        .send()
        .await
        .context("should deploy factory")?;
    println!("Factory deployed at {:?}", factory.address());
    let salt: U256 = 1.into();
    let wallet_address = factory
        .get_address(user_eoa.address(), salt)
        .call()
        .await
        .context("factory's get_address should return the counterfactual address")?;
    println!("Wallet will be deployed at {wallet_address:?}");
    grant_eth(&provider, wallet_address).await?;
    let init_code = get_compacted_call_data(
        factory.address(),
        factory.create_account(user_eoa.address(), salt),
    );
    let mut op = UserOperation {
        sender: wallet_address,
        init_code,
        call_gas_limit: 1_000_000.into(),
        verification_gas_limit: 1_000_000.into(),
        pre_verification_gas: 1_000_000.into(),
        max_fee_per_gas: 100.into(),
        max_priority_fee_per_gas: 5.into(),
        ..UserOperation::default()
    };
    let op_hash = entry_point
        .get_user_op_hash(op.clone())
        .call()
        .await
        .context("entry point should compute hash of user operation")?;
    let signature = user_eoa
        .sign_message(op_hash)
        .await
        .context("user eoa should sign op hash")?;
    op.signature = signature.to_vec().into();
    let simulation_error = entry_point
        .simulate_validation(op.clone())
        .call()
        .await
        .err()
        .context("simulate call should revert")?;
    let tx = entry_point.simulate_validation(op.clone()).tx;
    let json = serde_json::to_string_pretty(&tx)?;
    println!("\nThe tx\n");
    println!("{tx:#?}");
    println!("\nThe tx as JSON (in case you wanted to paste it into Postman):\n");
    println!("{json}");
    let revert_data =
        get_revert_data(simulation_error).context("error from simulation should be a revert")?;
    let simulation_result =
        EntryPointErrors::decode_hex(revert_data).context("execution error should decode")?;
    println!();
    println!("Simulation result:");
    println!();
    println!("{simulation_result:#?}");

    let trace_result = tracer::trace_op_validation(&entry_point, op.clone()).await?;
    println!();
    println!("Trace result:");
    println!();
    println!("{trace_result:#?}");

    // let receipt = entry_point
    //     .handle_ops(vec![op], bundler_client.address())
    //     .send()
    //     .await
    //     .context("should call entry point to deploy wallet")?
    //     .await
    //     .context("entry point should deploy wallet")?
    //     .context("transaction where entry point deploys wallet should not be dropped")?;
    // println!();
    // println!("Logs from wallet creation:");
    // println!();
    // for log in receipt.logs {
    //     let raw_log = log_to_raw_log(log);
    //     if let Ok(event) = EntryPointEvents::decode_log(&raw_log) {
    //         println!("{event:?}");
    //     } else if let Ok(event) = SimpleAccountEvents::decode_log(&raw_log) {
    //         println!("{event:?}");
    //     } else {
    //         println!("Unrecognized log: {raw_log:?}");
    //     }
    // }
    Ok(())
}

async fn grant_eth(provider: &Provider<Http>, address: Address) -> anyhow::Result<()> {
    // A Geth node in --dev mode comes with one account with massive amounts of ETH.
    let funder_address = *provider
        .get_accounts()
        .await
        .context("should be able to get accounts from node")?
        .first()
        .context("Geth node in dev mode should have one account")?;
    provider
        .send_transaction(
            TransactionRequest::pay(address, 1000000000000000000_u64).from(funder_address),
            None,
        )
        .await
        .context("should send transaction to grant ETH")?
        .await
        .context("Geth dev account should grant ETH")?
        .context("transaction to grant ETH should not be dropped")?;
    Ok(())
}

/// Packs an address followed by call data into a single `Bytes`. This is used
/// in ERC-4337 for calling wallets, factories, and paymasters.
fn get_compacted_call_data<M, D>(address: Address, call: ContractCall<M, D>) -> Bytes {
    let mut bytes = address.as_bytes().to_vec();
    if let Some(call_data) = call.tx.data() {
        bytes.extend(call_data);
    }
    bytes.into()
}

/// Converts an ethers-rs `Log` into an ethabi `RawLog`.
fn log_to_raw_log(log: Log) -> RawLog {
    let Log { topics, data, .. } = log;
    RawLog {
        topics,
        data: data.to_vec(),
    }
}

type EthCallError = ContractError<SignerMiddleware<Arc<Provider<Http>>, LocalWallet>>;

/// Extracts the revert reason if this is a revert error, otherwise returns the original error.
fn get_revert_data(mut error: EthCallError) -> Result<String, EthCallError> {
    let dyn_error = match &mut error {
        ContractError::MiddlewareError(SignerMiddlewareError::MiddlewareError(
            ProviderError::JsonRpcClientError(e),
        )) => e,
        _ => return Err(error),
    };
    let jsonrpc_error = match dyn_error.downcast_mut::<HttpClientError>() {
        Some(HttpClientError::JsonRpcError(e)) => e,
        _ => return Err(error),
    };
    match &mut jsonrpc_error.data {
        Some(Value::String(s)) => Ok(mem::take(s)),
        _ => Err(error),
    }
}
