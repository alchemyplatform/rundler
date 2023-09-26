// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use ethers::utils::hex;
use rundler_dev::{
    self, DevAddresses, BUNDLER_ACCOUNT_ID, PAYMASTER_SIGNER_ACCOUNT_ID, WALLET_OWNER_ACCOUNT_ID,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bytecode = include_str!(
        "../../../../crates/types/contracts/bytecode/entrypoint/0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789.txt",
    );
    let addresses = rundler_dev::deploy_dev_contracts(bytecode).await?;
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
        "Bundler private key: 0x{}",
        hex::encode(rundler_dev::test_signing_key_bytes(BUNDLER_ACCOUNT_ID))
    );
    println!(
        "Wallet owner private key: 0x{}",
        hex::encode(rundler_dev::test_signing_key_bytes(WALLET_OWNER_ACCOUNT_ID))
    );
    println!(
        "Paymaster private signing key: 0x{}",
        hex::encode(rundler_dev::test_signing_key_bytes(
            PAYMASTER_SIGNER_ACCOUNT_ID
        ))
    );
    Ok(())
}
