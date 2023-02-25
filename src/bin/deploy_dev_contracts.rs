use alchemy_bundler::common::contracts::entry_point::EntryPoint;
use alchemy_bundler::common::contracts::simple_account_factory::SimpleAccountFactory;
use alchemy_bundler::common::eth;
use alchemy_bundler::common::eth::test_signing_key_bytes;
use alchemy_bundler::common::types::UserOperation;
use anyhow::Context;
use ethers::signers::Signer;
use ethers::types::U256;
use ethers::utils::hex;
use std::sync::Arc;

const DEPLOYER_ACCOUNT_ID: u8 = 1;
const BUNDLER_ACCOUNT_ID: u8 = 2;
const WALLET_OWNER_ACCOUNT_ID: u8 = 3;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = eth::new_local_provider();
    let chain_id = eth::get_chain_id(&provider).await?;
    let deployer_client = eth::new_test_client(&provider, DEPLOYER_ACCOUNT_ID, chain_id);
    let bundler_client = eth::new_test_client(&provider, BUNDLER_ACCOUNT_ID, chain_id);
    let wallet_owner_eoa = eth::new_test_wallet(WALLET_OWNER_ACCOUNT_ID, chain_id);
    eth::grant_dev_eth(&provider, deployer_client.address()).await?;
    eth::grant_dev_eth(&provider, bundler_client.address()).await?;
    let entry_point_deployer = EntryPoint::deploy(Arc::clone(&deployer_client), ());
    let entry_point = eth::await_contract_deployment(entry_point_deployer, "EntryPoint").await?;
    let entry_point = eth::connect_contract(&entry_point, Arc::clone(&bundler_client));
    let factory_deployer =
        SimpleAccountFactory::deploy(Arc::clone(&deployer_client), entry_point.address());
    let factory = eth::await_contract_deployment(factory_deployer, "SimpleAccountFactory").await?;
    let factory = eth::connect_contract(&factory, Arc::clone(&bundler_client));
    let salt = U256::from(1);
    let wallet_address = factory
        .get_address(wallet_owner_eoa.address(), salt)
        .call()
        .await
        .context("factory's get_address should return the counterfactual address")?;
    eth::grant_dev_eth(&provider, wallet_address).await?;
    let init_code = eth::compact_call_data(
        factory.address(),
        factory.create_account(wallet_owner_eoa.address(), salt),
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
    let signature = wallet_owner_eoa
        .sign_message(op_hash)
        .await
        .context("user eoa should sign op hash")?;
    op.signature = signature.to_vec().into();
    let call = entry_point.handle_ops(vec![op], bundler_client.address());
    eth::await_mined_tx(call.send(), "deploy wallet using entry point").await?;

    println!("Entry point address: {:?}", entry_point.address());
    println!("Factory address: {:?}", factory.address());
    println!("Wallet address: {wallet_address:?}");
    println!();
    println!(
        "Bundler private key: {}",
        hex::encode(test_signing_key_bytes(BUNDLER_ACCOUNT_ID))
    );
    println!(
        "Wallet owner private key: {}",
        hex::encode(test_signing_key_bytes(WALLET_OWNER_ACCOUNT_ID))
    );
    Ok(())
}
