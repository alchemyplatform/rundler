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

//! Generated contract interfaces

#![allow(non_snake_case)]
#![allow(clippy::all)]
#![allow(missing_docs)]

use ethers::types::Bytes;

pub mod arbitrum;
pub mod optimism;
pub mod utils;
pub mod v0_6;
pub mod v0_7;

// https://etherscan.io/address/0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789#code
const __ENTRY_POINT_V0_6_DEPLOYED_BYTECODE_HEX: &[u8] = include_bytes!(
    "../../contracts/bytecode/entrypoint/0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789_deployed.txt"
);
const __ENTRY_POINT_V0_6_DEPLOYED_BYTECODE: [u8; 23689] = {
    match const_hex::const_decode_to_array(__ENTRY_POINT_V0_6_DEPLOYED_BYTECODE_HEX) {
        Ok(a) => a,
        Err(_) => panic!("Failed to decode entrypoint hex"),
    }
};
pub static ENTRY_POINT_V0_6_DEPLOYED_BYTECODE: Bytes =
    Bytes::from_static(&__ENTRY_POINT_V0_6_DEPLOYED_BYTECODE);
