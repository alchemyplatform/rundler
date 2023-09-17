use std::{env, error, path::PathBuf};

fn main() -> Result<(), Box<dyn error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    generate_protos()?;
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
