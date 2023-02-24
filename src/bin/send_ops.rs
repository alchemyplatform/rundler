use alchemy_bundler::common::contracts::entry_point::EntryPoint;
use alchemy_bundler::common::contracts::simple_account::SimpleAccount;
use alchemy_bundler::common::eth;
use alchemy_bundler::common::types::UserOperation;
use anyhow::Context;
use ethers::signers::Signer;
use ethers::types::Address;
use std::str::FromStr;

// NOTE: run dev_deploy_contracts first to deploy the contracts
// set these to the addresses of the deployed contracts
const ENTRYPOINT_ADDRESS: &str = "";
const WALLET_ADDRESS: &str = "";

const BUNDLER_ACCOUNT_ID: u8 = 2;
const WALLET_OWNER_ACCOUNT_ID: u8 = 3;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = eth::new_local_provider();
    let chain_id = eth::get_chain_id(&provider).await?;
    let bundler_client = eth::new_test_client(&provider, BUNDLER_ACCOUNT_ID, chain_id);
    let wallet_owner_eoa = eth::new_test_wallet(WALLET_OWNER_ACCOUNT_ID, chain_id);

    let entry_point = EntryPoint::new(
        Address::from_str(ENTRYPOINT_ADDRESS).context("should parse entry point address")?,
        bundler_client.clone(),
    );

    let scw_address = WALLET_ADDRESS
        .parse()
        .context("should parse wallet address")?;
    let scw = SimpleAccount::new(scw_address, bundler_client.clone());

    // simply call the nonce method multiple times
    let call_data = scw
        .nonce()
        .calldata()
        .expect("should encode nonce calldata");

    for i in 0..10 {
        println!("Sending op {i}");
        let nonce = scw
            .nonce()
            .call()
            .await
            .context("should get nonce of simple account")?;
        let mut op = UserOperation {
            sender: scw_address,
            call_data: call_data.clone(),
            nonce,
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
        eth::await_mined_tx(call.send(), "send user operation").await?;
    }

    Ok(())
}
