use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Command;
use std::{env, error};

fn main() -> Result<(), Box<dyn error::Error>> {
    println!("cargo:rerun-if-changed=foundry/src");
    println!("cargo:rerun-if-changed=proto");
    generate_abis()?;
    generate_protos()?;
    Ok(())
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
