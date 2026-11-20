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

use anyhow::bail;
use clap::{Parser, Subcommand};
use rundler_provider::Providers;
use rundler_task::TaskSpawnerExt;
use rundler_types::chain::ChainSpec;

use crate::cli::signer::{SignerArgs, SignerLayout};

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

impl Command {
    fn signer_args(&self) -> &SignerArgs {
        match self {
            Command::ListSigners(args) => &args.signer_args,
            Command::FundSigners(args) => &args.signer_args,
            Command::DefundSigners(args) => &args.signer_args,
        }
    }
}

/// The admin signer commands only build the legacy signing scheme. Under the mapping
/// layout they would act on the legacy key chunks instead of the mapped keys, so they
/// refuse to run.
fn ensure_legacy_layout(signer_args: &SignerArgs) -> anyhow::Result<()> {
    if signer_args.layout == SignerLayout::Mapping {
        bail!(
            "admin signer commands do not support SIGNER_LAYOUT=mapping yet; they only know the legacy signer layout"
        );
    }
    Ok(())
}

pub async fn run(
    args: AdminCliArgs,
    chain_spec: ChainSpec,
    providers: impl Providers + 'static,
    task_spawner: impl TaskSpawnerExt + 'static,
) -> anyhow::Result<()> {
    ensure_legacy_layout(args.command.signer_args())?;

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

#[cfg(test)]
mod tests {
    use super::*;

    const DEFUND_TO: &str = "0x0000000000000000000000000000000000000001";

    fn command(args: &[&str]) -> Command {
        AdminCliArgs::parse_from(std::iter::once("admin").chain(args.iter().copied())).command
    }

    #[test]
    fn signer_commands_refuse_mapping_layout() {
        for args in [
            vec!["list-signers"],
            vec!["fund-signers"],
            vec!["defund-signers", "--to", DEFUND_TO],
        ] {
            let mut args = args;
            args.extend(["--signer.layout", "mapping"]);
            let err = ensure_legacy_layout(command(&args).signer_args()).unwrap_err();
            assert!(
                err.to_string().contains("SIGNER_LAYOUT=mapping"),
                "{args:?}: {err}"
            );
        }
    }

    #[test]
    fn signer_commands_allow_legacy_layout() {
        for args in [
            vec!["list-signers"],
            vec!["fund-signers", "--signer.layout", "legacy"],
            vec!["defund-signers", "--to", DEFUND_TO],
        ] {
            ensure_legacy_layout(command(&args).signer_args()).unwrap();
        }
    }
}
