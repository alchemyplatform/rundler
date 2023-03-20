use ethers::contract::{Abigen, MultiAbigen};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Command;
use std::{env, error};

fn main() -> Result<(), Box<dyn error::Error>> {
    println!("cargo:rerun-if-changed=contracts/lib");
    println!("cargo:rerun-if-changed=contracts/src");
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=tracer/package.json");
    println!("cargo:rerun-if-changed=tracer/src/index.ts");
    generate_contract_bindings()?;
    generate_protos()?;
    compile_tracer()?;
    Ok(())
}

fn generate_contract_bindings() -> Result<(), Box<dyn error::Error>> {
    generate_abis()?;
    MultiAbigen::from_abigens([
        abigen_of("EntryPoint")?,
        abigen_of("IAggregator")?,
        abigen_of("GetCodeHashes")?,
        abigen_of("SimpleAccount")?,
        abigen_of("SimpleAccountFactory")?,
        abigen_of("VerifyingPaymaster")?,
    ])
    .build()?
    .write_to_module("src/common/contracts", false)?;
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
        Command::new("forge").arg("build"),
        "https://getfoundry.sh/",
        "generate ABIs",
    )
}

fn generate_protos() -> Result<(), Box<dyn error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("op_pool_descriptor.bin"))
        .compile(&["proto/op_pool.proto"], &["proto"])?;
    Ok(())
}

fn compile_tracer() -> Result<(), Box<dyn error::Error>> {
    let install_url = "https://classic.yarnpkg.com/en/docs/install";
    let action = "compile tracer";
    run_command(
        Command::new("yarn").current_dir("tracer"),
        install_url,
        action,
    )?;
    run_command(
        Command::new("yarn").arg("build").current_dir("tracer"),
        install_url,
        action,
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
