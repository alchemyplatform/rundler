use std::path::PathBuf;
use std::{env, error};

fn main() -> Result<(), Box<dyn error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("core_descriptor.bin"))
        .compile(&["proto/core.proto", "proto/common.proto"], &["proto"])?;
    tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("op_pool_descriptor.bin"))
        .compile(&["proto/op_pool.proto", "proto/common.proto"], &["proto"])?;
    Ok(())
}
