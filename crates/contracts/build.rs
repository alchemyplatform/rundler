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

use std::{error, fs, io::ErrorKind, process::Command};

use serde_json::Value;

macro_rules! write_deployed_bytecode {
    ($version:literal, $contract_name:ident) => {
        let json_file = fs::File::open(concat!(
            "contracts/out/",
            $version,
            "/",
            stringify!($contract_name),
            ".sol/",
            stringify!($contract_name),
            ".json"
        ))?;
        let val: Value = serde_json::from_reader(json_file)?;
        let bytecode = val
            .get("deployedBytecode")
            .unwrap()
            .get("object")
            .unwrap()
            .as_str()
            .unwrap();
        fs::write(
            concat!(
                "contracts/out/",
                $version,
                "/",
                stringify!($contract_name),
                ".sol/",
                stringify!($contract_name),
                "_deployedBytecode.txt"
            ),
            bytecode,
        )
        .unwrap();
    };
}

fn main() -> Result<(), Box<dyn error::Error>> {
    println!("cargo:rerun-if-changed=contracts/lib");
    println!("cargo:rerun-if-changed=contracts/src");
    println!("cargo:rerun-if-changed=contracts/foundry.toml");
    generate_v0_6_bindings()?;
    generate_v0_7_bindings()?;
    generate_utils_bindings()?;
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

    write_deployed_bytecode!("v0_6", VerificationGasEstimationHelper);

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

    write_deployed_bytecode!("v0_7", CallGasEstimationProxy);
    write_deployed_bytecode!("v0_7", EntryPointSimulations);
    write_deployed_bytecode!("v0_7", VerificationGasEstimationHelper);

    Ok(())
}

fn generate_utils_bindings() -> Result<(), Box<dyn error::Error>> {
    run_command(
        &mut forge_build("utils"),
        "https://getfoundry.sh/",
        "generate ABIs",
    )?;

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
