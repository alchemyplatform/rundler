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
    update_submodules()?;
    generate_contract_bindings()?;
    Ok(())
}

fn generate_contract_bindings() -> Result<(), Box<dyn error::Error>> {
    generate_abis()?;
    MultiAbigen::from_abigens([
        abigen_of("IEntryPoint")?,
        abigen_of("EntryPoint")?,
        abigen_of("IAggregator")?,
        abigen_of("GetCodeHashes")?,
        abigen_of("GetGasUsed")?,
        abigen_of("CallGasEstimationProxy")?,
        abigen_of("SimpleAccount")?,
        abigen_of("SimpleAccountFactory")?,
        abigen_of("VerifyingPaymaster")?,
        abigen_of("NodeInterface")?,
        abigen_of("GasPriceOracle")?,
    ])
    .build()?
    .write_to_module("src/contracts", false)?;
    Ok(())
}

fn abigen_of(contract: &str) -> Result<Abigen, Box<dyn error::Error>> {
    Ok(Abigen::new(
        contract,
        format!("contracts/out/{contract}.sol/{contract}.json"),
    )?)
}

fn generate_abis() -> Result<(), Box<dyn error::Error>> {
    run_command(
        Command::new("forge")
            .arg("build")
            .arg("--root")
            .arg("./contracts"),
        "https://getfoundry.sh/",
        "generate ABIs",
    )
}

fn update_submodules() -> Result<(), Box<dyn error::Error>> {
    run_command(
        Command::new("git").arg("submodule").arg("update"),
        "https://github.com/git-guides/install-git",
        "update submodules",
    )
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
