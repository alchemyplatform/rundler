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

// Credit to https://github.com/mvertescher/fastlz-rs/blob/master/fastlz-sys/build.rs

extern crate cc;

use std::{env, path::PathBuf};

fn main() {
    let mut build = cc::Build::new();
    build.include("fastlz");

    #[cfg(target_os = "linux")]
    build.flag("-Wno-unused-parameter");

    let files = ["fastlz/fastlz.c"];

    build.files(files.iter()).compile("fastlz");
    println!("cargo:rustc-link-lib=static=fastlz");

    // Generate bindings
    let bindings = bindgen::Builder::default()
        .header("fastlz/fastlz.h")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!")
}
