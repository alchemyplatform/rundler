use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Command;
use std::{env, error};
use ethers::contract::{Abigen, MultiAbigen};

fn main() -> Result<(), Box<dyn error::Error>> {
    println!("cargo:rerun-if-changed=foundry/lib");
    println!("cargo:rerun-if-changed=foundry/src");
    println!("cargo:rerun-if-changed=proto");
    generate_contract_bindings()?;
    generate_protos()?;
    Ok(())
}

fn generate_contract_bindings() -> Result<(), Box<dyn error::Error>> {
    generate_abis()?;
    MultiAbigen::from_abigens([
        abigen_of("EntryPoint")?,
        abigen_of("SimpleAccount")?,
        abigen_of("SimpleAccountFactory")?,
    ])
        .build()?
        .write_to_module("src/common/contracts2", false)?;
    Ok(())
}

fn abigen_of(contract: &str) -> Result<Abigen, Box<dyn error::Error>> {
    Ok(Abigen::new(contract, format!("foundry/out/{contract}.sol/{contract}.json"))?
        .add_event_derive("serde::Deserialize")
        .add_event_derive("serde::Serialize"))
}

fn generate_abis() -> Result<(), Box<dyn error::Error>> {
    let output = Command::new("forge").arg("build").output();
    let output = match output {
        Ok(o) => o,
        Err(e) => {
            if let ErrorKind::NotFound = e.kind() {
                Err("Foundry not installed. See instructions at https://getfoundry.sh/")?;
            }
            Err(e)?
        }
    };
    if !output.status.success() {
        if let Ok(error_output) = String::from_utf8(output.stderr) {
            eprintln!("{error_output}");
        }
        Err("Failed to generate EntryPoint ABI.")?;
    }
    Ok(())
}

fn generate_protos() -> Result<(), Box<dyn error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("op_pool_descriptor.bin"))
        .compile(&["proto/op_pool.proto"], &["proto"])?;
    Ok(())
}
