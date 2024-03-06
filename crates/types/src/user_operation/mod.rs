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

use ethers::types::{Address, Bytes, H256, U256};

mod v0_6;
pub use v0_6::{
    UserOperation as UserOperationV0_6, UserOpsPerAggregator as UserOpsPerAggregatorV0_6,
};
mod v0_7;
pub use v0_7::UserOperation as UserOperationV0_7;

use crate::Entity;

/// Unique identifier for a user operation from a given sender
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserOperationId {
    /// sender of user operation
    pub sender: Address,
    /// nonce of user operation
    pub nonce: U256,
}

/// User operation type enum
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UserOperationType {
    V0_6,
    V0_7,
}

/// User operation enum
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UserOperation {
    /// User operation version 0.6
    V0_6(UserOperationV0_6),
    /// User operation version 0.7
    V0_7(UserOperationV0_7),
}

impl UserOperation {
    /// Hash a user operation with the given entry point and chain ID.
    ///
    /// The hash is used to uniquely identify a user operation in the entry point.
    /// It does not include the signature field.
    pub fn hash(&self, entry_point: Address, chain_id: u64) -> H256 {
        match self {
            UserOperation::V0_6(op) => op.hash(entry_point, chain_id),
            UserOperation::V0_7(op) => op.hash(entry_point, chain_id),
        }
    }

    /// Get the user operation id
    pub fn id(&self) -> UserOperationId {
        match self {
            UserOperation::V0_6(op) => op.id(),
            UserOperation::V0_7(op) => op.id(),
        }
    }

    /// Get the user operation sender address
    pub fn sender(&self) -> Address {
        match self {
            UserOperation::V0_6(op) => op.sender,
            UserOperation::V0_7(op) => op.sender,
        }
    }

    /// Get the user operation paymaster address, if any
    pub fn paymaster(&self) -> Option<Address> {
        match self {
            UserOperation::V0_6(op) => op.paymaster(),
            UserOperation::V0_7(op) => op.paymaster(),
        }
    }

    /// Get the user operation factory address, if any
    pub fn factory(&self) -> Option<Address> {
        match self {
            UserOperation::V0_6(op) => op.factory(),
            UserOperation::V0_7(op) => op.factory(),
        }
    }

    /// Returns the maximum cost, in wei, of this user operation
    pub fn max_gas_cost(&self) -> U256 {
        match self {
            UserOperation::V0_6(op) => op.max_gas_cost(),
            UserOperation::V0_7(op) => op.max_gas_cost(),
        }
    }

    /// Gets an iterator on all entities associated with this user operation
    pub fn entities(&'_ self) -> Vec<Entity> {
        match self {
            UserOperation::V0_6(op) => op.entities(),
            UserOperation::V0_7(op) => op.entities(),
        }
    }

    /// Returns the heap size of the user operation
    pub fn heap_size(&self) -> usize {
        match self {
            UserOperation::V0_6(op) => op.heap_size(),
            UserOperation::V0_7(op) => op.heap_size(),
        }
    }

    /// Returns the call gas limit
    pub fn call_gas_limit(&self) -> U256 {
        match self {
            UserOperation::V0_6(op) => op.call_gas_limit,
            UserOperation::V0_7(op) => op.call_gas_limit.into(),
        }
    }

    pub fn verification_gas_limit(&self) -> U256 {
        match self {
            UserOperation::V0_6(op) => op.verification_gas_limit,
            UserOperation::V0_7(op) => op.verification_gas_limit.into(),
        }
    }

    /// Returns the total verification gas limit
    pub fn total_verification_gas_limit(&self) -> U256 {
        match self {
            UserOperation::V0_6(op) => op.total_verification_gas_limit(),
            UserOperation::V0_7(op) => op.total_verification_gas_limit(),
        }
    }

    // TODO(danc)
    pub fn required_pre_execution_buffer(&self) -> U256 {
        match self {
            UserOperation::V0_6(op) => op.verification_gas_limit + U256::from(5_000),
            UserOperation::V0_7(op) => {
                U256::from(op.paymaster_post_op_gas_limit) + U256::from(10_000)
            }
        }
    }

    pub fn post_op_required_gas(&self) -> U256 {
        match self {
            UserOperation::V0_6(op) => {
                if op.paymaster().is_some() {
                    op.verification_gas_limit
                } else {
                    U256::zero()
                }
            }
            UserOperation::V0_7(op) => op.paymaster_post_op_gas_limit.into(),
        }
    }

    /// Returns the pre-verification gas
    pub fn pre_verification_gas(&self) -> U256 {
        match self {
            UserOperation::V0_6(op) => op.pre_verification_gas,
            UserOperation::V0_7(op) => op.pre_verification_gas,
        }
    }

    /// Calculate the static portion of the pre-verification gas for this user operation
    pub fn calc_static_pre_verification_gas(&self, include_fixed_gas_overhead: bool) -> U256 {
        match self {
            UserOperation::V0_6(op) => {
                op.calc_static_pre_verification_gas(include_fixed_gas_overhead)
            }
            UserOperation::V0_7(op) => {
                op.calc_static_pre_verification_gas(include_fixed_gas_overhead)
            }
        }
    }

    /// Returns the max fee per gas
    pub fn max_fee_per_gas(&self) -> U256 {
        match self {
            UserOperation::V0_6(op) => op.max_fee_per_gas,
            UserOperation::V0_7(op) => op.max_fee_per_gas.into(),
        }
    }

    /// Returns the max priority fee per gas
    pub fn max_priority_fee_per_gas(&self) -> U256 {
        match self {
            UserOperation::V0_6(op) => op.max_priority_fee_per_gas,
            UserOperation::V0_7(op) => op.max_priority_fee_per_gas.into(),
        }
    }

    /// Clear the signature field of the user op
    ///
    /// Used when a user op is using a signature aggregator prior to being submitted
    pub fn clear_signature(&mut self) {
        match self {
            UserOperation::V0_6(op) => op.signature = Bytes::new(),
            UserOperation::V0_7(op) => op.signature = Bytes::new(),
        }
    }

    /// Returns the user operation type
    pub fn uo_type(&self) -> UserOperationType {
        match self {
            UserOperation::V0_6(_) => UserOperationType::V0_6,
            UserOperation::V0_7(_) => UserOperationType::V0_7,
        }
    }

    /// Returns true if the user operation is of type [UserOperationV0_6]
    pub fn is_v0_6(&self) -> bool {
        matches!(self, UserOperation::V0_6(_))
    }

    /// Returns true if the user operation is of type [UserOperationV0_7]
    pub fn is_v0_7(&self) -> bool {
        matches!(self, UserOperation::V0_7(_))
    }

    /// Returns a reference to the [UserOperationV0_6] variant if the user operation is of that type
    pub fn as_v0_6(&self) -> Option<&UserOperationV0_6> {
        match self {
            UserOperation::V0_6(op) => Some(op),
            _ => None,
        }
    }

    /// Returns a reference to the [UserOperationV0_7] variant if the user operation is of that type
    pub fn as_v0_7(&self) -> Option<&UserOperationV0_7> {
        match self {
            UserOperation::V0_7(op) => Some(op),
            _ => None,
        }
    }

    /// Returns the [UserOperationV0_6] variant if the user operation is of that type
    pub fn into_v0_6(self) -> Option<UserOperationV0_6> {
        match self {
            UserOperation::V0_6(op) => Some(op),
            _ => None,
        }
    }

    /// Returns the [UserOperationV0_7] variant if the user operation is of that type
    pub fn into_v0_7(self) -> Option<UserOperationV0_7> {
        match self {
            UserOperation::V0_7(op) => Some(op),
            _ => None,
        }
    }
}

impl From<UserOperation> for UserOperationV0_6 {
    fn from(value: UserOperation) -> Self {
        value.into_v0_6().expect("Expected UserOperationV0_6")
    }
}

impl From<UserOperation> for UserOperationV0_7 {
    fn from(value: UserOperation) -> Self {
        value.into_v0_7().expect("Expected UserOperationV0_7")
    }
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

#[derive(Debug)]
pub struct UserOpsPerAggregator {
    pub user_ops: Vec<UserOperation>,
    pub aggregator: Address,
    pub signature: Bytes,
}

impl From<UserOpsPerAggregator> for UserOpsPerAggregatorV0_6 {
    fn from(value: UserOpsPerAggregator) -> Self {
        Self {
            user_ops: value.user_ops.into_iter().map(Into::into).collect(),
            aggregator: value.aggregator,
            signature: value.signature,
        }
    }
}
