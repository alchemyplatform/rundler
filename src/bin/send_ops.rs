use alchemy_bundler::common::dev::DevClients;
use alchemy_bundler::common::types::UserOperation;
use alchemy_bundler::common::{dev, eth};
use anyhow::Context;
use dotenv::dotenv;
use ethers::signers::Signer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv()?;
    let DevClients {
        bundler_client,
        entry_point,
        wallet: scw,
        wallet_owner_signer,
        ..
    } = DevClients::new_from_env()?;

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
            sender: scw.address(),
            call_data: call_data.clone(),
            nonce,
            ..dev::base_user_op()
        };
        let op_hash = entry_point
            .get_user_op_hash(op.clone())
            .call()
            .await
            .context("entry point should compute hash of user operation")?;
        let signature = wallet_owner_signer
            .sign_message(op_hash)
            .await
            .context("user eoa should sign op hash")?;
        op.signature = signature.to_vec().into();

        let call = entry_point.handle_ops(vec![op], bundler_client.address());
        eth::await_mined_tx(call.send(), "send user operation").await?;
    }

    Ok(())
}
