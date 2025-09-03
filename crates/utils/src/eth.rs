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

#[cfg(test)]
mod tests {
    use alloy_consensus::{Signed, TxEip7702, TxLegacy};
    use alloy_eips::eip7702::{Authorization, SignedAuthorization};
    use alloy_primitives::{Address, Bytes, Signature, U256};

    use super::*;

    #[test]
    fn test_calculate_transaction_size_without_auth_list() {
        let bundle_data_size = 1000;
        let auth_list_count = 0;

        let calculated_size = calculate_transaction_size(bundle_data_size, auth_list_count);

        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 42,
            gas_price: 20_000_000_000u128,
            gas_limit: 21_000,
            to: alloy_primitives::TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::from(vec![0u8; bundle_data_size]),
        };

        let signature = Signature::from_bytes_and_parity(&[0u8; 64], false);
        let signed_tx = Signed::new_unchecked(tx, signature, Default::default());

        let mut encoded = Vec::new();
        signed_tx.rlp_encode(&mut encoded);
        let actual_size = encoded.len();

        // The calculated size should be close to the actual size (within reasonable overhead)
        let diff = if calculated_size > actual_size {
            calculated_size - actual_size
        } else {
            actual_size - calculated_size
        };

        // The estimate is intentionally conservative (overestimates) for safety
        // Allow up to 300 bytes difference for encoding overhead estimation
        assert!(
            diff <= 300,
            "Size difference too large: calculated={}, actual={}, diff={}",
            calculated_size,
            actual_size,
            diff
        );

        // Verify that our calculation is never less than the actual size
        assert!(
            calculated_size >= actual_size,
            "Calculated size must not underestimate: calculated={}, actual={}",
            calculated_size,
            actual_size
        );
    }

    #[test]
    fn test_calculate_transaction_size_with_auth_list() {
        let bundle_data_size = 1000;
        let auth_list_count = 2;

        let calculated_size = calculate_transaction_size(bundle_data_size, auth_list_count);

        let auth1 = Authorization {
            chain_id: U256::from(1),
            address: Address::from([1u8; 20]),
            nonce: 1,
        };

        let auth2 = Authorization {
            chain_id: U256::from(1),
            address: Address::from([2u8; 20]),
            nonce: 2,
        };

        let signed_auth1 =
            SignedAuthorization::new_unchecked(auth1, 0, U256::from(1), U256::from(2));
        let signed_auth2 =
            SignedAuthorization::new_unchecked(auth2, 1, U256::from(3), U256::from(4));

        let tx = TxEip7702 {
            nonce: 42,
            gas_limit: 21_000,
            max_fee_per_gas: 20_000_000_000u128,
            max_priority_fee_per_gas: 1_000_000_000u128,
            to: Address::ZERO,
            value: U256::ZERO,
            input: Bytes::from(vec![0u8; bundle_data_size]),
            authorization_list: vec![signed_auth1, signed_auth2],
            chain_id: 1,
            access_list: Default::default(),
        };

        let signature = Signature::from_bytes_and_parity(&[0u8; 64], false);
        let signed_tx = Signed::new_unchecked(tx, signature, Default::default());

        let mut encoded = Vec::new();
        signed_tx.rlp_encode(&mut encoded);
        let actual_size = encoded.len();

        let diff = if calculated_size > actual_size {
            calculated_size - actual_size
        } else {
            actual_size - calculated_size
        };

        // The estimate is intentionally conservative (overestimates) for safety
        // Allow up to 500 bytes difference for encoding overhead estimation
        assert!(
            diff <= 500,
            "Size difference too large: calculated={}, actual={}, diff={}",
            calculated_size,
            actual_size,
            diff
        );

        // Verify that our calculation is never less than the actual size
        assert!(
            calculated_size >= actual_size,
            "Calculated size must not underestimate: calculated={}, actual={}",
            calculated_size,
            actual_size
        );
    }

    #[test]
    fn test_auth_list_size_calculation() {
        let bundle_data_size = 100;

        let size_without_auth = calculate_transaction_size(bundle_data_size, 0);
        let size_with_one_auth = calculate_transaction_size(bundle_data_size, 1);
        let size_with_two_auth = calculate_transaction_size(bundle_data_size, 2);

        // Each auth item should add exactly the expected size
        let auth_item_size = 32 + 20 + 8 + 1 + 32 + 32;

        assert_eq!(size_with_one_auth - size_without_auth, auth_item_size);
        assert_eq!(size_with_two_auth - size_with_one_auth, auth_item_size);
    }
}
