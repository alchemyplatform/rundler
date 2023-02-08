use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, error};

fn main() -> Result<(), Box<dyn error::Error>> {
    generate_abis_if_needed()?;
    generate_protos()?;
    Ok(())
}

fn generate_abis_if_needed() -> Result<(), Box<dyn error::Error>> {
    if Path::new("abis/EntryPoint.json").exists() {
        return Ok(());
    }
    let output = Command::new("bash")
        .arg("scripts/generate-entrypoint-abi.sh")
        .output()?;
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
