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

//! Utilities for working with an EVM chains.

use alloy_primitives::Address;

/// Format the ethers address type to string without ellipsis
pub fn format_address(address: Address) -> String {
    format!("{:#x}", address).to_string()
}

/// Calculate the size of a transaction in bytes including transaction overhead
/// This function estimates the complete transaction size for a bundle before it's fully constructed
/// Note: Bundle transactions are sent via EOA, so EIP-7702 authorization lists are not included
pub fn calculate_transaction_size(bundle_data_size: usize, auth_list_count: usize) -> usize {
    let mut size = 0;

    size += 8; // nonce (will be set when sending)
    size += 20; // from address (sender EOA)
    size += 20; // to address (entry point or proxy)
    size += 32; // value (always 0 for bundle transactions)
    size += 8; // gas_limit (max encoding size)
    size += 32; // max_fee_per_gas (max encoding size)
    size += 32; // max_priority_fee_per_gas (max encoding size)

    // Bundle data (input field)
    size += bundle_data_size;

    // Signature
    size += 65; // signature (r, s, v)

    // RLP encoding overhead
    size += 50; // headers, lengths, etc.

    if auth_list_count > 0 {
        // chain_id + address + nonce + y_parity + r + s
        let auth_item_size = 32 + 20 + 8 + 1 + 32 + 32;
        size += auth_list_count * auth_item_size;
    }

    size
}
