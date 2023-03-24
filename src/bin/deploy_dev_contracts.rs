use alchemy_bundler::common::{
    dev,
    dev::{DevAddresses, BUNDLER_ACCOUNT_ID, PAYMASTER_SIGNER_ACCOUNT_ID, WALLET_OWNER_ACCOUNT_ID},
};
use ethers::utils::hex;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addresses = dev::deploy_dev_contracts().await?;
    addresses.write_to_env_file()?;
    let DevAddresses {
        entry_point_address: entry_point,
        factory_address: factory,
        wallet_address: wallet,
        paymaster_address: paymaster,
    } = addresses;
    println!("Entry point address: {entry_point:?}");
    println!("Factory address: {factory:?}");
    println!("Wallet address: {wallet:?}");
    println!("Paymaster address: {paymaster:?}");
    println!();
    println!(
        "Bundler private key: {}",
        hex::encode(dev::test_signing_key_bytes(BUNDLER_ACCOUNT_ID))
    );
    println!(
        "Wallet owner private key: {}",
        hex::encode(dev::test_signing_key_bytes(WALLET_OWNER_ACCOUNT_ID))
    );
    println!(
        "Paymaster private signing key: {}",
        hex::encode(dev::test_signing_key_bytes(PAYMASTER_SIGNER_ACCOUNT_ID))
    );
    Ok(())
}
