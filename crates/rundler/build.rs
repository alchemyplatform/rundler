use std::{env, error, io::ErrorKind, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=tracer/package.json");
    println!("cargo:rerun-if-changed=tracer/src/validationTracer.ts");
    generate_protos()?;
    compile_tracer()?;
    Ok(())
}

fn generate_protos() -> Result<(), Box<dyn error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("op_pool_descriptor.bin"))
        .compile(&["proto/op_pool/op_pool.proto"], &["proto"])?;
    tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("builder_descriptor.bin"))
        .compile(&["proto/builder/builder.proto"], &["proto"])?;
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
