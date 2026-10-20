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

use std::{fs, io::ErrorKind, process::Command};

use anyhow::{Context, bail};

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=contracts/src");
    println!("cargo:rerun-if-changed=contracts/entrypoint");
    println!("cargo:rerun-if-changed=contracts/foundry.toml");

    // Probe fixtures (default profile), then EntryPoint v0.7 with its canonical settings.
    forge_build(None)?;
    forge_build(Some("entrypoint"))?;

    // Only the EntryPoint's creation code is needed (to deploy it where the canonical one is
    // missing); its full ABI is already bound in rundler-contracts.
    let artifact: serde_json::Value = serde_json::from_reader(
        fs::File::open("contracts/out-entrypoint/EntryPoint.sol/EntryPoint.json")
            .context("EntryPoint artifact missing")?,
    )?;
    let init_code = artifact["bytecode"]["object"]
        .as_str()
        .context("EntryPoint artifact has no bytecode")?;
    let out_dir = std::env::var("OUT_DIR")?;
    fs::write(
        format!("{out_dir}/entry_point_v0_7_init_code.hex"),
        init_code,
    )?;
    Ok(())
}

fn forge_build(profile: Option<&str>) -> anyhow::Result<()> {
    let mut cmd = Command::new("forge");
    cmd.arg("build").arg("--root").arg("./contracts");
    if let Some(profile) = profile {
        cmd.env("FOUNDRY_PROFILE", profile);
    }
    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            bail!("forge not installed. See instructions at https://getfoundry.sh/")
        }
        Err(e) => return Err(e).context("failed to run forge"),
    };
    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        bail!(
            "Failed to build contracts (profile {}).",
            profile.unwrap_or("default")
        );
    }
    Ok(())
}
