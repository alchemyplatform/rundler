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

use alloy_primitives::U256;
use anyhow::Context;
use clap::Args;
use rundler_provider::{EvmProvider, Providers};
use rundler_signer::SigningScheme;
use rundler_task::TaskSpawnerExt;
use rundler_types::chain::ChainSpec;

use crate::cli::signer::SignerArgs;

#[derive(Debug, Args)]
pub(super) struct FundSignersArgs {
    /// The number of signers to fund
    #[arg(short, long)]
    count: u64,

    /// Signer arguments
    #[command(flatten)]
    signer_args: SignerArgs,

    /// Broadcast the funding transaction
    #[arg(short, long)]
    broadcast: bool,
}

pub(super) async fn fund_signers(
    args: FundSignersArgs,
    chain_spec: ChainSpec,
    providers: impl Providers + 'static,
    task_spawner: impl TaskSpawnerExt + 'static,
) -> anyhow::Result<()> {
    let signing_scheme = args.signer_args.signing_scheme(args.count as usize)?;
    if !signing_scheme.supports_funding() {
        anyhow::bail!("Signing scheme does not support funding");
    }
    let Some(fund_below) = args.signer_args.fund_below else {
        anyhow::bail!("Fund below balance not set");
    };
    let Some(fund_to) = args.signer_args.fund_to else {
        anyhow::bail!("Fund to balance not set");
    };
    if let SigningScheme::KmsFundingMnemonics {
        mnemonics_by_key_id,
        ..
    } = &signing_scheme
    {
        if mnemonics_by_key_id.len() > 1 {
            anyhow::bail!("Only one key ID with mnemonic is supported for funding");
        }
    }

    let signer_manager = rundler_signer::new_signer_manager(
        &signing_scheme,
        false,
        &chain_spec,
        providers.evm().clone(),
        &task_spawner,
    )
    .await?;

    let balances = providers
        .evm()
        .get_balances(signer_manager.addresses())
        .await?;

    let mut total = U256::ZERO;
    for (address, balance) in &balances {
        if *balance < fund_below && *balance < fund_to {
            let to_fund = fund_to - balance;
            let balance = alloy_primitives::utils::format_ether(*balance);
            let to_fund_str = alloy_primitives::utils::format_ether(to_fund);
            println!("Signer: {address:?} Balance: {balance} To fund: {to_fund_str}");
            total += to_fund;
        }
    }

    signer_manager
        .fund_signers()
        .context("Failed to fund signers")?;

    println!(
        "Total to fund: {}",
        alloy_primitives::utils::format_ether(total)
    );

    if !args.broadcast {
        return Ok(());
    }

    let count = signer_manager.addresses().len();
    println!("Waiting for {count} signers to be funded...");
    let _ = signer_manager.wait_for_available(count).await;
    println!("All signers funded");

    let new_balances = providers
        .evm()
        .get_balances(signer_manager.addresses())
        .await?;

    for (address, balance) in new_balances {
        let eth_string = alloy_primitives::utils::format_ether(balance);
        println!("Signer: {address:?} Balance: {eth_string}");
    }

    Ok(())
}
