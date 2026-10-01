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

//! Bindings for the contracts in `contracts/`, built by `build.rs`.

#![allow(missing_docs)]

use alloy_primitives::{Bytes, hex};
use alloy_sol_macro::sol;

sol!(Burner, "contracts/out/Probes.sol/Burner.json");
sol!(ProbeAccount, "contracts/out/Probes.sol/ProbeAccount.json");
sol!(ProbeFactory, "contracts/out/Probes.sol/ProbeFactory.json");
sol!(
    ProbePaymaster,
    "contracts/out/Probes.sol/ProbePaymaster.json"
);
sol!(Scratch, "contracts/out/Probes.sol/Scratch.json");

sol! {
    interface IStakeManagerLite {
        function depositTo(address account) external payable;
        function balanceOf(address account) external view returns (uint256);
    }
}

/// Creation code of EntryPoint v0.7 built with the canonical deployment settings.
pub fn entry_point_v0_7_init_code() -> Bytes {
    hex::decode(include_str!(concat!(
        env!("OUT_DIR"),
        "/entry_point_v0_7_init_code.hex"
    )))
    .expect("build.rs writes valid hex")
    .into()
}
