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

use clap::Args;
use rundler_provider::{EvmProvider, Providers};
use rundler_task::TaskSpawnerExt;
use rundler_types::chain::ChainSpec;

use crate::cli::signer::SignerArgs;

#[derive(Debug, Args)]
pub(super) struct ListSignersArgs {
    /// The number of signers to list
    #[arg(short, long)]
    count: u64,

    /// Signer arguments
    #[command(flatten)]
    signer_args: SignerArgs,
}

pub(super) async fn list_signers(
    args: ListSignersArgs,
    chain_spec: ChainSpec,
    providers: impl Providers + 'static,
    task_spawner: impl TaskSpawnerExt + 'static,
) -> anyhow::Result<()> {
    let signing_scheme = args.signer_args.signing_scheme(args.count as usize)?;

    let signer_manager = rundler_signer::new_signer_manager(
        &signing_scheme,
        false,
        &chain_spec,
        providers.evm().clone(),
        &task_spawner,
    )
    .await?;

    println!("Listing signers...");

    let balances = providers
        .evm()
        .get_balances(signer_manager.addresses())
        .await?;

    for (address, balance) in balances {
        let eth_string = alloy_primitives::utils::format_ether(balance);
        println!("Signer: {address:?} Balance: {eth_string}");
    }

    Ok(())
}
