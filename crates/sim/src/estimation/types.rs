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

use ethers::types::{Address, Bytes, U256};
use rand::RngCore;
use rundler_types::UserOperation;
use serde::{Deserialize, Serialize};

use crate::precheck::MIN_CALL_GAS_LIMIT;

/// Settings for gas estimation
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// The maximum amount of gas that can be used for the verification step of a user operation
    pub max_verification_gas: u64,
    /// The maximum amount of gas that can be used for the call step of a user operation
    pub max_call_gas: u64,
    /// The maximum amount of gas that can be used in a call to `simulateHandleOps`
    pub max_simulate_handle_ops_gas: u64,
    /// The gas fee to use during verification gas estimation, required to be held by the fee-payer
    /// during estimation. If using a paymaster, the fee-payer must have 3x this value.
    /// As the gas limit is varied during estimation, the fee is held constant by varied the
    /// gas price.
    /// Clients can use state overrides to set the balance of the fee-payer to at least this value.
    pub verification_estimation_gas_fee: u64,
}

impl Settings {
    /// Check if the settings are valid
    pub fn validate(&self) -> Option<String> {
        if U256::from(self.max_call_gas)
            .cmp(&MIN_CALL_GAS_LIMIT)
            .is_lt()
        {
            return Some("max_call_gas field cannot be lower than MIN_CALL_GAS_LIMIT".to_string());
        }
        None
    }
}

/// User operation with optional gas fields for gas estimation
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UserOperationOptionalGas {
    /// Sender (required)
    pub sender: Address,
    /// Nonce (required)
    pub nonce: U256,
    /// Init code (required)
    pub init_code: Bytes,
    /// Call data (required)
    pub call_data: Bytes,
    /// Call gas limit (optional, set to maximum if unset)
    pub call_gas_limit: Option<U256>,
    /// Verification gas limit (optional, set to maximum if unset)
    pub verification_gas_limit: Option<U256>,
    /// Pre verification gas (optional, ignored if set)
    pub pre_verification_gas: Option<U256>,
    /// Max fee per gas (optional, ignored if set)
    pub max_fee_per_gas: Option<U256>,
    /// Max priority fee per gas (optional, ignored if set)
    pub max_priority_fee_per_gas: Option<U256>,
    /// Paymaster and data (required, dummy value)
    ///
    /// This is typically a "dummy" value with the following constraints:
    /// - The first 20 bytes are the paymaster address
    /// - The rest of the paymaster and data must be at least as long as the
    /// longest possible data field for this user operation
    /// - The data must also cause the paymaster validation call to use
    /// the maximum amount of gas possible
    ///
    /// This is required in order to get an accurate gas estimation for the validation phase.
    pub paymaster_and_data: Bytes,
    /// Signature (required, dummy value)
    ///
    /// This is typically a "dummy" value with the following constraints:
    /// - The signature must be at least as long as the longs possible signature for this user operation
    /// - The data must also cause the account validation call to use
    /// the maximum amount of gas possible,
    ///
    /// This is required in order to get an accurate gas estimation for the validation phase.
    pub signature: Bytes,
}

impl UserOperationOptionalGas {
    /// Fill in the optional and dummy fields of the user operation with values
    /// that will cause the maximum possible calldata gas cost.
    ///
    /// When estimating pre-verification gas, callers take the results and plug them
    /// into their user operation. Doing so changes the
    /// pre-verification gas. To make sure the returned gas is enough to
    /// cover the modified user op, calculate the gas needed for the worst
    /// case scenario where the gas fields of the user operation are entirely
    /// nonzero bytes. Likewise for the signature field.
    pub fn max_fill(&self, settings: &Settings) -> UserOperation {
        UserOperation {
            call_gas_limit: U256::MAX,
            verification_gas_limit: U256::MAX,
            pre_verification_gas: U256::MAX,
            max_fee_per_gas: U256::MAX,
            max_priority_fee_per_gas: U256::MAX,
            signature: vec![255_u8; self.signature.len()].into(),
            paymaster_and_data: vec![255_u8; self.paymaster_and_data.len()].into(),
            ..self.clone().into_user_operation(settings)
        }
    }

    /// Fill in the optional and dummy fields of the user operation with random values.
    ///
    /// When estimating pre-verification gas, specifically on networks that use
    /// compression algorithms on their data that they post to their data availability
    /// layer (like Arbitrum), it is important to make sure that the data that is
    /// random such that it compresses to a representative size.
    //
    /// Note that this will slightly overestimate the calldata gas needed as it uses
    /// the worst case scenario for the unknown gas values and paymaster_and_data.
    pub fn random_fill(&self, settings: &Settings) -> UserOperation {
        UserOperation {
            call_gas_limit: U256::from_big_endian(&Self::random_bytes(4)), // 30M max
            verification_gas_limit: U256::from_big_endian(&Self::random_bytes(4)), // 30M max
            pre_verification_gas: U256::from_big_endian(&Self::random_bytes(4)), // 30M max
            max_fee_per_gas: U256::from_big_endian(&Self::random_bytes(8)), // 2^64 max
            max_priority_fee_per_gas: U256::from_big_endian(&Self::random_bytes(8)), // 2^64 max
            signature: Self::random_bytes(self.signature.len()),
            paymaster_and_data: Self::random_bytes(self.paymaster_and_data.len()),
            ..self.clone().into_user_operation(settings)
        }
    }

    /// Convert into a full user operation.
    /// Fill in the optional fields of the user operation with default values if unset
    pub fn into_user_operation(self, settings: &Settings) -> UserOperation {
        UserOperation {
            sender: self.sender,
            nonce: self.nonce,
            init_code: self.init_code,
            call_data: self.call_data,
            paymaster_and_data: self.paymaster_and_data,
            signature: self.signature,
            // If unset, default these to gas limits from settings
            // Cap their values to the gas limits from settings
            verification_gas_limit: self
                .verification_gas_limit
                .unwrap_or_else(|| settings.max_verification_gas.into())
                .min(settings.max_verification_gas.into()),
            call_gas_limit: self
                .call_gas_limit
                .unwrap_or_else(|| settings.max_call_gas.into())
                .min(settings.max_call_gas.into()),
            // These aren't used in gas estimation, set to if unset 0 so that there are no payment attempts during gas estimation
            pre_verification_gas: self.pre_verification_gas.unwrap_or_default(),
            max_fee_per_gas: self.max_fee_per_gas.unwrap_or_default(),
            max_priority_fee_per_gas: self.max_priority_fee_per_gas.unwrap_or_default(),
        }
    }

    /// Convert into a full user operation with the provided gas estimates.
    ///
    /// Fee fields are left unchanged or are defaulted.
    pub fn into_user_operation_with_estimates(self, estimates: GasEstimate) -> UserOperation {
        UserOperation {
            sender: self.sender,
            nonce: self.nonce,
            init_code: self.init_code,
            call_data: self.call_data,
            paymaster_and_data: self.paymaster_and_data,
            signature: self.signature,
            verification_gas_limit: estimates.verification_gas_limit,
            call_gas_limit: estimates.call_gas_limit,
            pre_verification_gas: estimates.pre_verification_gas,
            max_fee_per_gas: self.max_fee_per_gas.unwrap_or_default(),
            max_priority_fee_per_gas: self.max_priority_fee_per_gas.unwrap_or_default(),
        }
    }

    /// Convert from a full user operation, keeping the gas fields set
    pub fn from_user_operation_keeping_gas(op: UserOperation) -> Self {
        Self::from_user_operation(op, true)
    }

    /// Convert from a full user operation, ignoring the gas fields
    pub fn from_user_operation_without_gas(op: UserOperation) -> Self {
        Self::from_user_operation(op, false)
    }

    fn from_user_operation(op: UserOperation, keep_gas: bool) -> Self {
        let if_keep_gas = |x: U256| Some(x).filter(|_| keep_gas);
        Self {
            sender: op.sender,
            nonce: op.nonce,
            init_code: op.init_code,
            call_data: op.call_data,
            call_gas_limit: if_keep_gas(op.call_gas_limit),
            verification_gas_limit: if_keep_gas(op.verification_gas_limit),
            pre_verification_gas: if_keep_gas(op.pre_verification_gas),
            max_fee_per_gas: if_keep_gas(op.max_fee_per_gas),
            max_priority_fee_per_gas: if_keep_gas(op.max_priority_fee_per_gas),
            paymaster_and_data: op.paymaster_and_data,
            signature: op.signature,
        }
    }

    fn random_bytes(len: usize) -> Bytes {
        let mut bytes = vec![0_u8; len];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes.into()
    }
}

/// Gas estimate for a user operation
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GasEstimate {
    /// Pre verification gas estimate
    pub pre_verification_gas: U256,
    /// Verification gas limit estimate
    pub verification_gas_limit: U256,
    /// Call gas limit estimate
    pub call_gas_limit: U256,
}
