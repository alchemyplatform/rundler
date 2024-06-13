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

use std::{error, io::ErrorKind, process::Command};

use ethers::contract::{Abigen, MultiAbigen};

fn main() -> Result<(), Box<dyn error::Error>> {
    println!("cargo:rerun-if-changed=contracts/lib");
    println!("cargo:rerun-if-changed=contracts/src");
    println!("cargo:rerun-if-changed=contracts/foundry.toml");
    generate_v0_6_bindings()?;
    generate_v0_7_bindings()?;
    generate_utils_bindings()?;
    generate_arbitrum_bindings()?;
    generate_optimism_bindings()?;
    Ok(())
}

fn generate_v0_6_bindings() -> Result<(), Box<dyn error::Error>> {
    run_command(
        forge_build("v0_6")
            .arg("--remappings")
            .arg("@openzeppelin/=lib/openzeppelin-contracts-versions/v4_9"),
        "https://getfoundry.sh/",
        "generate ABIs",
    )?;

    MultiAbigen::from_abigens([
        abigen_of("v0_6", "IEntryPoint")?,
        abigen_of("v0_6", "IAggregator")?,
        abigen_of("v0_6", "IStakeManager")?,
        abigen_of("v0_6", "GetBalances")?,
        abigen_of("v0_6", "SimpleAccount")?,
        abigen_of("v0_6", "SimpleAccountFactory")?,
        abigen_of("v0_6", "VerifyingPaymaster")?,
        abigen_of("v0_6", "CallGasEstimationProxy")?,
    ])
    .build()?
    .write_to_module("src/contracts/v0_6", false)?;

    Ok(())
}

fn generate_v0_7_bindings() -> Result<(), Box<dyn error::Error>> {
    run_command(
        forge_build("v0_7")
            .arg("--remappings")
            .arg("@openzeppelin/=lib/openzeppelin-contracts-versions/v5_0"),
        "https://getfoundry.sh/",
        "generate ABIs",
    )?;

    MultiAbigen::from_abigens([
        abigen_of("v0_7", "IEntryPoint")?,
        abigen_of("v0_7", "IAccount")?,
        abigen_of("v0_7", "IPaymaster")?,
        abigen_of("v0_7", "IAggregator")?,
        abigen_of("v0_7", "IStakeManager")?,
        abigen_of("v0_7", "GetBalances")?,
        abigen_of("v0_7", "EntryPointSimulations")?,
        abigen_of("v0_7", "CallGasEstimationProxy")?,
        abigen_of("v0_7", "SenderCreator")?,
    ])
    .build()?
    .write_to_module("src/contracts/v0_7", false)?;

    Ok(())
}

fn generate_utils_bindings() -> Result<(), Box<dyn error::Error>> {
    run_command(
        &mut forge_build("utils"),
        "https://getfoundry.sh/",
        "generate ABIs",
    )?;

    MultiAbigen::from_abigens([
        abigen_of("utils", "GetCodeHashes")?,
        abigen_of("utils", "GetGasUsed")?,
        abigen_of("utils", "StorageLoader")?,
    ])
    .build()?
    .write_to_module("src/contracts/utils", false)?;

    Ok(())
}

fn generate_arbitrum_bindings() -> Result<(), Box<dyn error::Error>> {
    run_command(
        &mut forge_build("arbitrum"),
        "https://getfoundry.sh/",
        "generate ABIs",
    )?;

    MultiAbigen::from_abigens([abigen_of("arbitrum", "NodeInterface")?])
        .build()?
        .write_to_module("src/contracts/arbitrum", false)?;

    Ok(())
}

fn generate_optimism_bindings() -> Result<(), Box<dyn error::Error>> {
    run_command(
        &mut forge_build("optimism"),
        "https://getfoundry.sh/",
        "generate ABIs",
    )?;

    MultiAbigen::from_abigens([abigen_of("optimism", "GasPriceOracle")?])
        .build()?
        .write_to_module("src/contracts/optimism", false)?;

    Ok(())
}

fn forge_build(src: &str) -> Command {
    let mut cmd = Command::new("forge");

    cmd.arg("build")
        .arg("--root")
        .arg("./contracts")
        .arg("--contracts")
        .arg(format!("src/{src}"))
        .arg("--out")
        .arg(format!("out/{src}"));

    cmd
}

fn abigen_of(extra_path: &str, contract: &str) -> Result<Abigen, Box<dyn error::Error>> {
    Ok(Abigen::new(
        contract,
        format!("contracts/out/{extra_path}/{contract}.sol/{contract}.json"),
    )?)
}

fn run_command(
    command: &mut Command,
    install_page_url: &str,
    action: &str,
) -> Result<(), Box<dyn error::Error>> {
    let output = match command.output() {
        Ok(o) => o,
        Err(e) => {
            if let ErrorKind::NotFound = e.kind() {
                let program = command.get_program().to_str().unwrap();
                Err(format!(
                    "{program} not installed. See instructions at {install_page_url}"
                ))?;
            }
            Err(e)?
        }
    };
    if !output.status.success() {
        if let Ok(error_output) = String::from_utf8(output.stderr) {
            eprintln!("{error_output}");
        }
        Err(format!("Failed to {action}."))?;
    }
    Ok(())
}
