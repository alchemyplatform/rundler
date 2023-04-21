use ethers::utils::hex;
use rundler::common::{
    dev,
    dev::{DevAddresses, BUNDLER_ACCOUNT_ID, PAYMASTER_SIGNER_ACCOUNT_ID, WALLET_OWNER_ACCOUNT_ID},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addresses = dev::deploy_dev_contracts().await?;

    // TODO fix this not to overwrite, but to append/modify the existing vars
    // addresses.write_to_env_file()?;

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
        "Bundler private key: 0x{}",
        hex::encode(dev::test_signing_key_bytes(BUNDLER_ACCOUNT_ID))
    );
    println!(
        "Wallet owner private key: 0x{}",
        hex::encode(dev::test_signing_key_bytes(WALLET_OWNER_ACCOUNT_ID))
    );
    println!(
        "Paymaster private signing key: 0x{}",
        hex::encode(dev::test_signing_key_bytes(PAYMASTER_SIGNER_ACCOUNT_ID))
    );
    Ok(())
}
