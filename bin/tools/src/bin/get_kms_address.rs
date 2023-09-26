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

// Use ethers to get a ETH address from a KMS key id
use anyhow::Context;
use clap::{arg, Command};
use ethers_signers::{AwsSigner, Signer};
use rusoto_core::Region;
use rusoto_kms::KmsClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Command::new("get_kms_address")
        .arg(arg!(-k --key <KEY>).required(true))
        .arg(arg!(-c --chain_id <CHAIN_ID>).required(true))
        .get_matches();
    let key = matches
        .get_one::<String>("key")
        .context("Missing key use -k KEY flag")?;
    let chain_id = matches
        .get_one::<String>("chain_id")
        .context("Missing chain id use -c CHAIN_ID flag")?
        .parse::<u64>()
        .context("bad chain id")?;

    let kms = KmsClient::new(Region::UsEast1);

    let signer = AwsSigner::new(kms, key, chain_id)
        .await
        .context("Failed to create signer")?;

    println!("Address: {:?}", signer.address());
    Ok(())
}
