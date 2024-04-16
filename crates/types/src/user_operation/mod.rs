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

use std::fmt::Debug;

use ethers::{
    abi::AbiEncode,
    types::{Address, Bytes, H256, U256},
};

/// User Operation types for Entry Point v0.6
pub mod v0_6;
/// User Operation types for Entry Point v0.7
pub mod v0_7;

use crate::Entity;

/// ERC-4337 Entry point version
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EntryPointVersion {
    /// Unspecified version
    Unspecified,
    /// Version 0.6
    V0_6,
    /// Version 0.7
    V0_7,
}

/// Unique identifier for a user operation from a given sender
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserOperationId {
    /// sender of user operation
    pub sender: Address,
    /// nonce of user operation
    pub nonce: U256,
}

/// User operation trait
pub trait UserOperation: Debug + Clone + Send + Sync + 'static {
    /// Optional gas type
    ///
    /// Associated type for the version of a user operation that has optional gas and fee fields
    type OptionalGas;

    /// Get the entry point version for this UO
    fn entry_point_version() -> EntryPointVersion;

    /*
     * Getters
     */

    /// Get the user operation sender address
    fn sender(&self) -> Address;

    /// Get the user operation nonce
    fn nonce(&self) -> U256;

    /// Get the user operation paymaster address, if any
    fn paymaster(&self) -> Option<Address>;

    /// Get the user operation factory address, if any
    fn factory(&self) -> Option<Address>;

    /// Get the user operation calldata
    fn call_data(&self) -> &Bytes;

    /// Returns the call gas limit
    fn call_gas_limit(&self) -> U256;

    /// Returns the verification gas limit
    fn verification_gas_limit(&self) -> U256;

    /// Returns the max fee per gas
    fn max_fee_per_gas(&self) -> U256;

    /// Returns the max priority fee per gas
    fn max_priority_fee_per_gas(&self) -> U256;

    /// Returns the maximum cost, in wei, of this user operation
    fn max_gas_cost(&self) -> U256;

    /*
     * Enhanced functions
     */

    /// Hash a user operation with the given entry point and chain ID.
    ///
    /// The hash is used to uniquely identify a user operation in the entry point.
    /// It does not include the signature field.
    fn hash(&self, entry_point: Address, chain_id: u64) -> H256;

    /// Get the user operation id
    fn id(&self) -> UserOperationId;

    /// Gets an iterator on all entities associated with this user operation
    fn entities(&'_ self) -> Vec<Entity>;

    /// Returns the heap size of the user operation
    fn heap_size(&self) -> usize;

    /// Returns the total verification gas limit
    fn total_verification_gas_limit(&self) -> U256;

    /// Returns the required pre-execution buffer
    ///
    /// This should capture all of the gas that is needed to execute the user operation,
    /// minus the call gas limit. The entry point will check for this buffer before
    /// executing the user operation.
    fn required_pre_execution_buffer(&self) -> U256;

    /// Returns the pre-verification gas
    fn pre_verification_gas(&self) -> U256;

    /// Calculate the static portion of the pre-verification gas for this user operation
    fn calc_static_pre_verification_gas(&self, include_fixed_gas_overhead: bool) -> U256;

    /// Clear the signature field of the user op
    ///
    /// Used when a user op is using a signature aggregator prior to being submitted
    fn clear_signature(&mut self);

    /// Abi encode size of the user operation
    fn abi_encoded_size(&self) -> usize;
}

/// User operation enum
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UserOperationVariant {
    /// User operation version 0.6
    V0_6(v0_6::UserOperation),
    /// User operation version 0.7
    V0_7(v0_7::UserOperation),
}

impl UserOperation for UserOperationVariant {
    type OptionalGas = UserOperationOptionalGas;

    fn entry_point_version() -> EntryPointVersion {
        EntryPointVersion::Unspecified
    }

    fn hash(&self, entry_point: Address, chain_id: u64) -> H256 {
        match self {
            UserOperationVariant::V0_6(op) => op.hash(entry_point, chain_id),
            UserOperationVariant::V0_7(op) => op.hash(entry_point, chain_id),
        }
    }

    fn id(&self) -> UserOperationId {
        match self {
            UserOperationVariant::V0_6(op) => op.id(),
            UserOperationVariant::V0_7(op) => op.id(),
        }
    }

    fn sender(&self) -> Address {
        match self {
            UserOperationVariant::V0_6(op) => op.sender(),
            UserOperationVariant::V0_7(op) => op.sender(),
        }
    }

    fn nonce(&self) -> U256 {
        match self {
            UserOperationVariant::V0_6(op) => op.nonce(),
            UserOperationVariant::V0_7(op) => op.nonce(),
        }
    }

    fn paymaster(&self) -> Option<Address> {
        match self {
            UserOperationVariant::V0_6(op) => op.paymaster(),
            UserOperationVariant::V0_7(op) => op.paymaster(),
        }
    }

    fn factory(&self) -> Option<Address> {
        match self {
            UserOperationVariant::V0_6(op) => op.factory(),
            UserOperationVariant::V0_7(op) => op.factory(),
        }
    }

    fn call_data(&self) -> &Bytes {
        match self {
            UserOperationVariant::V0_6(op) => op.call_data(),
            UserOperationVariant::V0_7(op) => op.call_data(),
        }
    }

    fn max_gas_cost(&self) -> U256 {
        match self {
            UserOperationVariant::V0_6(op) => op.max_gas_cost(),
            UserOperationVariant::V0_7(op) => op.max_gas_cost(),
        }
    }

    fn entities(&'_ self) -> Vec<Entity> {
        match self {
            UserOperationVariant::V0_6(op) => op.entities(),
            UserOperationVariant::V0_7(op) => op.entities(),
        }
    }

    fn heap_size(&self) -> usize {
        match self {
            UserOperationVariant::V0_6(op) => op.heap_size(),
            UserOperationVariant::V0_7(op) => op.heap_size(),
        }
    }

    fn call_gas_limit(&self) -> U256 {
        match self {
            UserOperationVariant::V0_6(op) => op.call_gas_limit(),
            UserOperationVariant::V0_7(op) => op.call_gas_limit(),
        }
    }

    fn verification_gas_limit(&self) -> U256 {
        match self {
            UserOperationVariant::V0_6(op) => op.verification_gas_limit(),
            UserOperationVariant::V0_7(op) => op.verification_gas_limit(),
        }
    }

    fn total_verification_gas_limit(&self) -> U256 {
        match self {
            UserOperationVariant::V0_6(op) => op.total_verification_gas_limit(),
            UserOperationVariant::V0_7(op) => op.total_verification_gas_limit(),
        }
    }

    fn required_pre_execution_buffer(&self) -> U256 {
        match self {
            UserOperationVariant::V0_6(op) => op.required_pre_execution_buffer(),
            UserOperationVariant::V0_7(op) => op.required_pre_execution_buffer(),
        }
    }

    fn pre_verification_gas(&self) -> U256 {
        match self {
            UserOperationVariant::V0_6(op) => op.pre_verification_gas(),
            UserOperationVariant::V0_7(op) => op.pre_verification_gas(),
        }
    }

    fn calc_static_pre_verification_gas(&self, include_fixed_gas_overhead: bool) -> U256 {
        match self {
            UserOperationVariant::V0_6(op) => {
                op.calc_static_pre_verification_gas(include_fixed_gas_overhead)
            }
            UserOperationVariant::V0_7(op) => {
                op.calc_static_pre_verification_gas(include_fixed_gas_overhead)
            }
        }
    }

    fn max_fee_per_gas(&self) -> U256 {
        match self {
            UserOperationVariant::V0_6(op) => op.max_fee_per_gas(),
            UserOperationVariant::V0_7(op) => op.max_fee_per_gas(),
        }
    }

    fn max_priority_fee_per_gas(&self) -> U256 {
        match self {
            UserOperationVariant::V0_6(op) => op.max_priority_fee_per_gas(),
            UserOperationVariant::V0_7(op) => op.max_priority_fee_per_gas(),
        }
    }

    fn clear_signature(&mut self) {
        match self {
            UserOperationVariant::V0_6(op) => op.clear_signature(),
            UserOperationVariant::V0_7(op) => op.clear_signature(),
        }
    }

    fn abi_encoded_size(&self) -> usize {
        match self {
            UserOperationVariant::V0_6(op) => op.abi_encoded_size(),
            UserOperationVariant::V0_7(op) => op.abi_encoded_size(),
        }
    }
}

impl UserOperationVariant {
    fn into_v0_6(self) -> Option<v0_6::UserOperation> {
        match self {
            UserOperationVariant::V0_6(op) => Some(op),
            _ => None,
        }
    }

    fn into_v0_7(self) -> Option<v0_7::UserOperation> {
        match self {
            UserOperationVariant::V0_7(op) => Some(op),
            _ => None,
        }
    }

    /// Returns the user operation type
    pub fn uo_type(&self) -> EntryPointVersion {
        match self {
            UserOperationVariant::V0_6(_) => EntryPointVersion::V0_6,
            UserOperationVariant::V0_7(_) => EntryPointVersion::V0_7,
        }
    }
}

/// User operation optional gas enum
#[derive(Debug, Clone)]
pub enum UserOperationOptionalGas {
    /// User operation optional gas for version 0.6
    V0_6(v0_6::UserOperationOptionalGas),
    /// User operation optional gas for version 0.7
    V0_7(v0_7::UserOperationOptionalGas),
}

/// Gas estimate
#[derive(Debug, Clone)]
pub struct GasEstimate {
    /// Pre verification gas
    pub pre_verification_gas: U256,
    /// Call gas limit
    pub call_gas_limit: U256,
    /// Verification gas limit
    pub verification_gas_limit: U256,
    /// Paymaster verification gas limit
    ///
    /// v0.6: unused
    ///
    /// v0.7: populated only if the user operation has a paymaster
    pub paymaster_verification_gas_limit: Option<U256>,
}

/// User operations per aggregator
#[derive(Debug, Eq, PartialEq, Clone, Default)]
pub struct UserOpsPerAggregator<UO: UserOperation> {
    /// User operations
    pub user_ops: Vec<UO>,
    /// Aggregator address, zero if no aggregator is used
    pub aggregator: Address,
    /// Aggregator signature, empty if no aggregator is used
    pub signature: Bytes,
}

/// Gas overheads for user operations used in calculating the pre-verification gas. See: https://github.com/eth-infinitism/bundler/blob/main/packages/sdk/src/calcPreVerificationGas.ts
#[derive(Clone, Copy, Debug)]
pub struct GasOverheads {
    /// The Entrypoint requires a gas buffer for the bundle to account for the gas spent outside of the major steps in the processing of UOs
    pub bundle_transaction_gas_buffer: U256,
    /// The fixed gas overhead for any EVM transaction
    pub transaction_gas_overhead: U256,
    per_user_op: U256,
    per_user_op_word: U256,
    zero_byte: U256,
    non_zero_byte: U256,
}

impl Default for GasOverheads {
    fn default() -> Self {
        Self {
            bundle_transaction_gas_buffer: 5_000.into(),
            transaction_gas_overhead: 21_000.into(),
            per_user_op: 18_300.into(),
            per_user_op_word: 4.into(),
            zero_byte: 4.into(),
            non_zero_byte: 16.into(),
        }
    }
}

pub(crate) fn op_calldata_gas_cost<UO: AbiEncode>(uo: UO) -> U256 {
    let ov = GasOverheads::default();
    let encoded_op = uo.encode();
    let length_in_words = encoded_op.len() / 32; // size of packed user op is always a multiple of 32 bytes
    let call_data_cost: U256 = encoded_op
        .iter()
        .map(|&x| {
            if x == 0 {
                ov.zero_byte
            } else {
                ov.non_zero_byte
            }
        })
        .reduce(|a, b| a + b)
        .unwrap_or_default();

    call_data_cost + ov.per_user_op + ov.per_user_op_word * length_in_words
}
/// Calculates the size a byte array padded to the next largest multiple of 32
pub(crate) fn byte_array_abi_len(b: &Bytes) -> usize {
    (b.len() + 31) & !31
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_array_abi_len() {
        let b = Bytes::from(vec![0u8; 32]);
        assert_eq!(byte_array_abi_len(&b), 32);

        let b = Bytes::from(vec![0u8; 31]);
        assert_eq!(byte_array_abi_len(&b), 32);

        let b = Bytes::from(vec![0u8; 33]);
        assert_eq!(byte_array_abi_len(&b), 64);
    }
}
