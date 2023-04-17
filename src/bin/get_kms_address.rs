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
