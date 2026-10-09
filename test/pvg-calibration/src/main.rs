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

//! Experiments that measure the gas the EntryPoint does not meter, i.e. what
//! preVerificationGas has to pay the bundler back for. See `README.md`.

#![warn(missing_docs, unused_crate_dependencies)]
#![deny(unused_must_use, rust_2018_idioms)]

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use clap::{Parser, Subcommand};

mod bundle;
mod contracts;
mod experiments;
mod fit;
mod fixtures;
mod harness;

use bundle::BundleRunner;
use fixtures::EpVersion;
use harness::Harness;
use rundler_types::chain::{ChainSpec, ForkActivation};

#[derive(Parser)]
#[command(about = "Measure the gas the EntryPoint does not meter, to calibrate PVG")]
struct Cli {
    /// RPC URL of the chain under test
    #[arg(
        long,
        env = "PVG_RPC_URL",
        hide_env_values = true,
        global = true,
        default_value = "http://127.0.0.1:8545"
    )]
    rpc_url: String,

    /// Private key of a funded EOA. Read from the environment only; never put it in a file
    /// that is committed.
    #[arg(long, env = "PVG_PRIVATE_KEY", hide_env_values = true, global = true)]
    private_key: Option<String>,

    /// Directory to write the JSON report to
    #[arg(long, global = true, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/results"))]
    out_dir: PathBuf,

    /// E2 only: comma-separated list; run just the parts whose label contains an entry, e.g.
    /// `Paymaster/deploy,PaymasterPostOp/deploy,beneficiary,penalty-check`
    #[arg(long, global = true)]
    only: Option<String>,

    /// Compare measurements with rundler's Glamsterdam gas schedule (`glamsterdam_activation`)
    /// instead of today's
    #[arg(long, global = true)]
    glamsterdam_prediction: bool,

    /// EntryPoint version the probe experiments (E2, E3, E5) and E6 run against. E4 needs v0.7.
    #[arg(long, global = true, value_enum, default_value = "v0.7")]
    entry_point: EpVersion,

    /// Label for the report file name, e.g. `anvil-prague` or `devnet`
    #[arg(long, global = true, default_value = "run")]
    label: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// E0: transaction-level prices (base tx, new account, calldata, calldata floor)
    CalibrateChain,
    /// E1: deploy (or find) the EntryPoint and probe fixtures, and print their addresses
    Fixtures,
    /// E2: shared and per-op unmetered overhead by payer and deploy path
    Overhead,
    /// E3: unmetered gas per byte of callData and signature
    Calldata,
    /// E4: unmetered cost of EIP-7702 authorizations by authority state (EntryPoint v0.7 only)
    Authorization,
    /// E5: storage shapes that move gas between metered and unmetered
    Hazards,
    /// E7: state-heavy ops (large contract deployments) bundled alone with a state-gas
    /// reservoir above 2^24, measured with reth's `stateGasTracer`. Always compares against the
    /// Glamsterdam gas schedule.
    IsolatedState {
        /// Sizes in bytes of the contracts the ops deploy
        #[arg(long, value_delimiter = ',', default_value = "4096,16384,24576")]
        sizes: Vec<usize>,
        /// Gas limit of the traced calls (default: the latest block's gas limit)
        #[arg(long)]
        trace_gas: Option<u64>,
    },
    /// E6: end to end through a running rundler, with real account implementations; measures
    /// the bundler's margin on each bundle rundler sends
    EndToEnd {
        /// JSON-RPC URL of the rundler instance under test
        #[arg(
            long,
            env = "PVG_BUNDLER_RPC_URL",
            default_value = "http://127.0.0.1:3000"
        )]
        bundler_rpc_url: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    let private_key = cli
        .private_key
        .as_deref()
        .context("PVG_PRIVATE_KEY (or --private-key) is required")?;
    let harness = Harness::connect(&cli.rpc_url, private_key).await?;
    let ep = cli.entry_point;
    // Report names carry the EntryPoint version for every experiment that runs against one.
    let experiment = |id: &str| format!("{id}-{}", ep.as_str());

    match cli.command {
        Command::CalibrateChain => {
            let report = experiments::chain::run(&harness).await?;
            let path = write_report(&cli.out_dir, &cli.label, "e0", report.chain_id(), &report)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            eprintln!("report written to {}", path.display());
        }
        Command::EndToEnd { bundler_rpc_url } => {
            let chain_id = harness.chain_info().await?.chain_id;
            let fixtures = fixtures::ensure(&harness, ep).await?;
            let report =
                experiments::e2e::run(&harness, &fixtures, chain_id, &bundler_rpc_url).await?;
            let path = write_report(
                &cli.out_dir,
                &cli.label,
                &experiment("e6"),
                chain_id,
                &report,
            )?;
            eprintln!("report written to {}", path.display());
        }
        Command::IsolatedState {
            ref sizes,
            trace_gas,
        } => {
            let chain_id = harness.chain_info().await?.chain_id;
            let fixtures = fixtures::ensure(&harness, ep).await?;
            let spec = prediction_spec(chain_id, true);
            let report =
                experiments::isolated_state::run(&harness, &fixtures, &spec, sizes, trace_gas)
                    .await?;
            let path = write_report(
                &cli.out_dir,
                &cli.label,
                &experiment("e7"),
                chain_id,
                &report,
            )?;
            eprintln!("report written to {}", path.display());
        }
        Command::Fixtures => {
            let fixtures = fixtures::ensure(&harness, ep).await?;
            println!("{}", serde_json::to_string_pretty(&fixtures)?);
        }
        Command::Overhead | Command::Calldata | Command::Authorization | Command::Hazards => {
            if matches!(cli.command, Command::Authorization) && ep != EpVersion::V0_7 {
                anyhow::bail!("E4 (authorization) runs against EntryPoint v0.7 only");
            }
            let chain_id = harness.chain_info().await?.chain_id;
            let fixtures = fixtures::ensure(&harness, ep).await?;
            let spec = prediction_spec(chain_id, cli.glamsterdam_prediction);
            let runner = BundleRunner {
                harness: &harness,
                fixtures: &fixtures,
                spec: &spec,
            };
            let (label, id) = (&cli.label, chain_id);
            let path = match cli.command {
                Command::Overhead => {
                    let report = experiments::overhead::run(&runner, cli.only.as_deref()).await?;
                    write_report(&cli.out_dir, label, &experiment("e2"), id, &report)?
                }
                Command::Calldata => {
                    let report = experiments::calldata::run(&runner).await?;
                    write_report(&cli.out_dir, label, &experiment("e3"), id, &report)?
                }
                Command::Authorization => {
                    let report = experiments::authorization::run(&runner, chain_id).await?;
                    write_report(&cli.out_dir, label, &experiment("e4"), id, &report)?
                }
                Command::Hazards => {
                    let report = experiments::hazards::run(&runner).await?;
                    write_report(&cli.out_dir, label, &experiment("e5"), id, &report)?
                }
                Command::CalibrateChain
                | Command::Fixtures
                | Command::EndToEnd { .. }
                | Command::IsolatedState { .. } => {
                    unreachable!()
                }
            };
            eprintln!("report written to {}", path.display());
        }
    }
    Ok(())
}

/// The ChainSpec whose PVG formula the measurements are compared against: rundler's
/// defaults with EIP-7623 enabled, as on Ethereum mainnet and Sepolia today, optionally with the
/// Glamsterdam gas schedule.
fn prediction_spec(chain_id: u64, glamsterdam: bool) -> ChainSpec {
    let spec = ChainSpec {
        id: chain_id,
        eip7623_enabled: true,
        glamsterdam_activation: if glamsterdam {
            ForkActivation::Genesis
        } else {
            ForkActivation::Never
        },
        ..ChainSpec::default()
    };
    // Apply the active gas schedule so the ChainSpec accessors return its values.
    spec.at_timestamp(0).into_owned()
}

fn write_report<T: serde::Serialize>(
    out_dir: &PathBuf,
    label: &str,
    experiment: &str,
    chain_id: u64,
    report: &T,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(out_dir)?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let path = out_dir.join(format!("{experiment}-{label}-{chain_id}-{ts}.json"));
    fs::write(&path, serde_json::to_string_pretty(report)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}
