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

use std::{fmt::Debug, time::Duration};

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::SolValue;
use rand::{self, RngCore};

/// User Operation types for Entry Point v0.6
pub mod v0_6;
/// User Operation types for Entry Point v0.7
pub mod v0_7;

use crate::{authorization::Authorization, chain::ChainSpec, Entity};

/// A user op must be valid for at least this long into the future to be included.
pub const TIME_RANGE_BUFFER: Duration = Duration::from_secs(60);

/// Overhead for bytes required for each bundle
/// 4 bytes for function signature
/// 32 bytes for user op array offset
/// 32 bytes for beneficiary
/// 32 bytes for array count
/// On top of this offset there needs to be another 32 bytes for each
/// user operation in the bundle to store its offset within the array
pub const BUNDLE_BYTE_OVERHEAD: usize = 4 + 32 + 32 + 32;

/// Size of word that stores offset of user op location
/// within handleOps `ops` array
pub const USER_OP_OFFSET_WORD_SIZE: usize = 32;

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
    fn call_gas_limit(&self) -> u128;

    /// Returns the verification gas limit
    fn verification_gas_limit(&self) -> u128;

    /// Returns the max fee per gas
    fn max_fee_per_gas(&self) -> u128;

    /// Returns the max priority fee per gas
    fn max_priority_fee_per_gas(&self) -> u128;

    /// Returns the maximum cost, in wei, of this user operation
    fn max_gas_cost(&self) -> U256;

    /// Returns the gas price for this UO given the base fee
    fn gas_price(&self, base_fee: u128) -> u128 {
        self.max_fee_per_gas()
            .min(base_fee + self.max_priority_fee_per_gas())
    }

    /// Return the authorization list of the UO. empty if it is not 7702 txn.
    fn authorization_tuple(&self) -> Option<Authorization>;

    /*
     * Enhanced functions
     */

    /// Hash a user operation with the given entry point and chain ID.
    ///
    /// The hash is used to uniquely identify a user operation in the entry point.
    /// It does not include the signature field.
    fn hash(&self, entry_point: Address, chain_id: u64) -> B256;

    /// Get the user operation id
    fn id(&self) -> UserOperationId;

    /// Gets an iterator on all entities associated with this user operation
    fn entities(&'_ self) -> Vec<Entity>;

    /// Returns the heap size of the user operation
    fn heap_size(&self) -> usize;

    /// Returns the total verification gas limit
    fn total_verification_gas_limit(&self) -> u128;

    /// Returns the required pre-execution buffer
    ///
    /// This should capture all of the gas that is needed to execute the user operation,
    /// minus the call gas limit. The entry point will check for this buffer before
    /// executing the user operation.
    fn required_pre_execution_buffer(&self) -> u128;

    /// Returns the limit of gas that may be used used prior to the execution of the user operation
    fn pre_op_gas_limit(&self) -> u128 {
        self.pre_verification_gas() + self.total_verification_gas_limit()
    }

    /// Returns the pre-verification gas
    fn pre_verification_gas(&self) -> u128;

    /// Get the static portion of the pre-verification gas for this user operation
    ///
    /// This does NOT include any shared gas costs for a bundle (i.e. intrinsic gas)
    fn static_pre_verification_gas(&self, chain_spec: &ChainSpec) -> u128;

    /// Clear the signature field of the user op
    ///
    /// Used when a user op is using a signature aggregator prior to being submitted
    fn clear_signature(&mut self);

    /// Abi encode size of the user operation
    fn abi_encoded_size(&self) -> usize;

    /// Calculate the size of the user operation in single UO bundle in bytes
    fn single_uo_bundle_size_bytes(&self) -> usize {
        self.abi_encoded_size() + BUNDLE_BYTE_OVERHEAD + USER_OP_OFFSET_WORD_SIZE
    }

    /// Gas limit functions
    ///
    /// Gas limit: Total as limit for the bundle transaction
    ///     - This value is required to be high enough so that the bundle transaction does not
    ///         run out of gas.
    /// Execution gas limit: Gas spent during the execution part of the bundle transaction
    ///     - This value is typically limited by block builders/sequencers and is the value by which
    ///         we will limit the amount of gas used in a bundle.
    ///
    /// For example, on Arbitrum chains the L1-DA gas portion is added at the beginning of transaction execution
    /// and uses up the gas limit of the transaction. However, this L1-DA portion is not part of the maximum gas
    /// allowed by the sequencer per block.
    ///
    /// If calculating the gas limit value to put on a bundle transaction, use the gas limit functions.
    /// If limiting the size of a bundle transaction to adhere to block gas limit, use the execution gas limit functions.

    /// Returns the gas limit that applies to bundle's total gas limit
    ///
    /// On an L2 this is the total gas limit for the bundle transaction ~including~ any potential DA costs
    /// if the chain requires it.
    ///
    /// This is needed to set the gas limit for the bundle transaction.
    ///
    /// `bundle_size` is the size of the bundle if applying shared gas to the gas limit, otherwise `None`.
    fn gas_limit(&self, chain_spec: &ChainSpec, bundle_size: Option<usize>) -> u128 {
        self.pre_verification_gas_limit(chain_spec, bundle_size)
            + self.total_verification_gas_limit()
            + self.required_pre_execution_buffer()
            + self.call_gas_limit()
    }

    /// Returns the gas limit that applies to the execution portion of a bundle's gas limit
    ///
    /// On an L2 this is the total gas limit for the bundle transaction ~excluding~ any potential DA costs.
    ///
    /// This is needed to limit the size of the bundle transaction to adhere to the block gas limit.
    ///
    /// `bundle_size` is the size of the bundle if applying shared gas to the gas limit, otherwise `None`.
    fn execution_gas_limit(&self, chain_spec: &ChainSpec, bundle_size: Option<usize>) -> u128 {
        self.pre_verification_execution_gas_limit(chain_spec, bundle_size)
            + self.total_verification_gas_limit()
            + self.required_pre_execution_buffer()
            + self.call_gas_limit()
    }

    /// Returns the portion of pre-verification gas the applies to the DA portion of a bundle's gas limit
    ///
    /// On an L2 this is the portion of the pre_verification_gas that is due to DA costs
    ///
    /// `bundle_size` is the size of the bundle if applying shared gas to the gas limit, otherwise `None`.
    fn pre_verification_da_gas_limit(
        &self,
        chain_spec: &ChainSpec,
        bundle_size: Option<usize>,
    ) -> u128 {
        // On some chains (OP bedrock) the DA gas fee is charged via pre_verification_gas
        // but this not part of the gas limit of the transaction.
        //
        // On other chains (Arbitrum), the DA portion IS charged in the gas limit, so calculate it here.
        if chain_spec.da_pre_verification_gas && chain_spec.include_da_gas_in_gas_limit {
            self.pre_verification_gas()
                .saturating_sub(self.static_pre_verification_gas(chain_spec))
                .saturating_sub(optional_bundle_per_uo_shared_gas(chain_spec, bundle_size))
        } else {
            0
        }
    }

    /// Returns the portion of pre-verification gas the applies to the execution portion of a bundle's gas limit
    ///
    /// On an L2 this is the total gas limit for the bundle transaction ~excluding~ any potential DA costs
    ///
    /// `bundle_size` is the size of the bundle if applying shared gas to the gas limit, otherwise `None`.
    fn pre_verification_execution_gas_limit(
        &self,
        chain_spec: &ChainSpec,
        bundle_size: Option<usize>,
    ) -> u128 {
        // On some chains (OP bedrock, Arbitrum) the DA gas fee is charged via pre_verification_gas
        // but this not part of the EXECUTION gas limit of the transaction.
        //
        // On other chains, the DA portion is zero.
        //
        // Thus, only consider the static portion of the pre_verification_gas in the gas limit.
        self.static_pre_verification_gas(chain_spec)
            .saturating_add(optional_bundle_per_uo_shared_gas(chain_spec, bundle_size))
    }

    /// Returns the portion of pre-verification gas that applies to a bundle's total gas limit
    ///
    /// On an L2 this is the total gas limit for the bundle transaction ~including~ any potential DA costs
    ///
    /// `bundle_size` is the size of the bundle if applying shared gas to the gas limit, otherwise `None`.
    fn pre_verification_gas_limit(
        &self,
        chain_spec: &ChainSpec,
        bundle_size: Option<usize>,
    ) -> u128 {
        self.pre_verification_execution_gas_limit(chain_spec, bundle_size)
            + self.pre_verification_da_gas_limit(chain_spec, bundle_size)
    }

    /// Returns the required pre-verification gas for the given user operation
    ///
    /// `bundle_size` is the size of the bundle
    /// `da_gas` is the DA gas cost for the user operation, calculated elsewhere
    fn required_pre_verification_gas(
        &self,
        chain_spec: &ChainSpec,
        bundle_size: usize,
        da_gas: u128,
    ) -> u128 {
        self.static_pre_verification_gas(chain_spec)
            .saturating_add(bundle_per_uo_shared_gas(chain_spec, bundle_size))
            .saturating_add(da_gas)
    }

    /// Returns true if the user operation has enough pre-verification gas to be included in a bundle
    ///
    /// `bundle_size` is the size of the bundle
    /// `da_gas` is the DA gas cost for the user operation, calculated elsewhere
    fn has_required_pre_verification_gas(
        &self,
        chain_spec: &ChainSpec,
        bundle_size: usize,
        da_gas: u128,
    ) -> bool {
        self.pre_verification_gas()
            > self.required_pre_verification_gas(chain_spec, bundle_size, da_gas)
    }
}

/// Returns the total shared gas for a bundle
pub fn bundle_shared_gas(chain_spec: &ChainSpec) -> u128 {
    chain_spec.transaction_intrinsic_gas()
}

/// Returns the shared gas per user operation for a given bundle size
///
/// `bundle_size` is the size of the bundle if applying shared gas to the gas limit, otherwise `None`.
pub fn bundle_per_uo_shared_gas(chain_spec: &ChainSpec, bundle_size: usize) -> u128 {
    if bundle_size == 0 {
        0
    } else {
        bundle_shared_gas(chain_spec) / bundle_size as u128
    }
}

fn optional_bundle_per_uo_shared_gas(chain_spec: &ChainSpec, bundle_size: Option<usize>) -> u128 {
    if let Some(bundle_size) = bundle_size {
        bundle_per_uo_shared_gas(chain_spec, bundle_size)
    } else {
        0
    }
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

    fn hash(&self, entry_point: Address, chain_id: u64) -> B256 {
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

    fn call_gas_limit(&self) -> u128 {
        match self {
            UserOperationVariant::V0_6(op) => op.call_gas_limit(),
            UserOperationVariant::V0_7(op) => op.call_gas_limit(),
        }
    }

    fn verification_gas_limit(&self) -> u128 {
        match self {
            UserOperationVariant::V0_6(op) => op.verification_gas_limit(),
            UserOperationVariant::V0_7(op) => op.verification_gas_limit(),
        }
    }

    fn total_verification_gas_limit(&self) -> u128 {
        match self {
            UserOperationVariant::V0_6(op) => op.total_verification_gas_limit(),
            UserOperationVariant::V0_7(op) => op.total_verification_gas_limit(),
        }
    }

    fn required_pre_execution_buffer(&self) -> u128 {
        match self {
            UserOperationVariant::V0_6(op) => op.required_pre_execution_buffer(),
            UserOperationVariant::V0_7(op) => op.required_pre_execution_buffer(),
        }
    }

    fn pre_verification_gas(&self) -> u128 {
        match self {
            UserOperationVariant::V0_6(op) => op.pre_verification_gas(),
            UserOperationVariant::V0_7(op) => op.pre_verification_gas(),
        }
    }

    fn static_pre_verification_gas(&self, chain_spec: &ChainSpec) -> u128 {
        match self {
            UserOperationVariant::V0_6(op) => op.static_pre_verification_gas(chain_spec),
            UserOperationVariant::V0_7(op) => op.static_pre_verification_gas(chain_spec),
        }
    }

    fn max_fee_per_gas(&self) -> u128 {
        match self {
            UserOperationVariant::V0_6(op) => op.max_fee_per_gas(),
            UserOperationVariant::V0_7(op) => op.max_fee_per_gas(),
        }
    }

    fn max_priority_fee_per_gas(&self) -> u128 {
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

    fn authorization_tuple(&self) -> Option<Authorization> {
        match self {
            UserOperationVariant::V0_6(op) => op.authorization_tuple(),
            UserOperationVariant::V0_7(op) => op.authorization_tuple(),
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

impl UserOperationOptionalGas {
    /// Returns the user operation type
    pub fn single_uo_bundle_size_bytes(&self) -> usize {
        let abi_size = match self {
            UserOperationOptionalGas::V0_6(op) => op.abi_encoded_size(),
            UserOperationOptionalGas::V0_7(op) => op.abi_encoded_size(),
        };
        abi_size + BUNDLE_BYTE_OVERHEAD + USER_OP_OFFSET_WORD_SIZE
    }
}

/// Gas estimate
#[derive(Debug, Clone)]
pub struct GasEstimate {
    /// Pre verification gas
    pub pre_verification_gas: u128,
    /// Call gas limit
    pub call_gas_limit: u128,
    /// Verification gas limit
    pub verification_gas_limit: u128,
    /// Paymaster verification gas limit
    ///
    /// v0.6: unused
    ///
    /// v0.7: populated only if the user operation has a paymaster
    pub paymaster_verification_gas_limit: Option<u128>,
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

pub(crate) fn op_calldata_gas_cost<UO: SolValue>(
    uo: UO,
    zero_byte_cost: u128,
    non_zero_byte_cost: u128,
    per_word_cost: u128,
) -> u128 {
    let encoded_op = uo.abi_encode();
    let length_in_words: u128 = (encoded_op.len() as u128 + 31) >> 5; // ceil(encoded_op.len() / 32)
    let call_data_cost = encoded_op
        .iter()
        .map(|&x| {
            if x == 0 {
                zero_byte_cost
            } else {
                non_zero_byte_cost
            }
        })
        .reduce(|a, b| a + b)
        .unwrap_or_default();

    call_data_cost + per_word_cost * length_in_words
}

/// Calculates the size a byte array padded to the next largest multiple of 32
pub(crate) fn byte_array_abi_len(b: &Bytes) -> usize {
    (b.len() + 31) & !31
}

/// Returns the default value if the option is None or the value is equal to the equal value
pub(crate) fn default_if_none_or_equal<V: Copy + PartialEq>(
    v: Option<V>,
    default: V,
    equal: V,
) -> V {
    v.filter(|v| v != &equal).unwrap_or(default)
}

/// Fills a bytes array of size ARR_SIZE with FILL_SIZE random bytes starting
/// at the beginning
fn random_bytes_array<const ARR_SIZE: usize, const FILL_SIZE: usize>() -> [u8; ARR_SIZE] {
    let mut bytes = [0_u8; ARR_SIZE];
    rand::thread_rng().fill_bytes(&mut bytes[..FILL_SIZE]);
    bytes
}

/// Fills a bytes object with fill_size random bytes
fn random_bytes(fill_size: usize) -> Bytes {
    let mut bytes = vec![0_u8; fill_size];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.into()
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
