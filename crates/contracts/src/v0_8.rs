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

use alloy_primitives::Bytes;

// EntryPointSimulations deployed bytecode
static __ENTRY_POINT_SIMULATIONS_V0_8_DEPLOYED_BYTECODE_HEX: &[u8] = include_bytes!(
    "../contracts/out/v0_8/EntryPointSimulations.sol/EntryPointSimulations_deployedBytecode.txt"
);

static __ENTRY_POINT_SIMULATIONS_V0_8_DEPLOYED_BYTECODE: [u8; 18842] = {
    match const_hex::const_decode_to_array(__ENTRY_POINT_SIMULATIONS_V0_8_DEPLOYED_BYTECODE_HEX) {
        Ok(a) => a,
        Err(_) => panic!("Failed to decode entry point simulations hex"),
    }
};

pub static ENTRY_POINT_SIMULATIONS_V0_8_DEPLOYED_BYTECODE: Bytes =
    Bytes::from_static(&__ENTRY_POINT_SIMULATIONS_V0_8_DEPLOYED_BYTECODE);
