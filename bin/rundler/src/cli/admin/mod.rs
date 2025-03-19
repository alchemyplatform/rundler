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

use clap::{Parser, Subcommand};
use rundler_provider::Providers;
use rundler_task::TaskSpawnerExt;
use rundler_types::chain::ChainSpec;

mod defund_signers;
mod fund_signers;
mod list_signers;

#[derive(Debug, Parser)]
pub(crate) struct AdminCliArgs {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::enum_variant_names)]
enum Command {
    /// List all signers
    #[command(name = "list-signers")]
    ListSigners(list_signers::ListSignersArgs),
    /// Fund signers
    #[command(name = "fund-signers")]
    FundSigners(fund_signers::FundSignersArgs),
    /// Defund signers
    #[command(name = "defund-signers")]
    DefundSigners(defund_signers::DefundSignersArgs),
}

pub async fn run(
    args: AdminCliArgs,
    chain_spec: ChainSpec,
    providers: impl Providers + 'static,
    task_spawner: impl TaskSpawnerExt + 'static,
) -> anyhow::Result<()> {
    match args.command {
        Command::ListSigners(args) => {
            list_signers::list_signers(args, chain_spec, providers, task_spawner).await?;
        }
        Command::FundSigners(args) => {
            fund_signers::fund_signers(args, chain_spec, providers, task_spawner).await?;
        }
        Command::DefundSigners(args) => {
            defund_signers::defund_signers(args, chain_spec, providers, task_spawner).await?;
        }
    }

    Ok(())
}
