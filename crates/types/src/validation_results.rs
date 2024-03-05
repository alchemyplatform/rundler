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

use ethers::{
    abi,
    abi::{AbiDecode, AbiError},
    types::{Address, Bytes, U256},
};

use crate::{
    contracts::v0_6::entry_point::{ValidationResult, ValidationResultWithAggregation},
    Timestamp,
};

/// Equivalent to the generated `ValidationResult` or
/// `ValidationResultWithAggregation` from `EntryPoint`, but with named structs
/// instead of tuples and with a helper for deserializing.
#[derive(Debug)]
pub struct ValidationOutput {
    /// The return info from the validation function
    pub return_info: ValidationReturnInfo,
    /// The stake info for the sender
    pub sender_info: StakeInfo,
    /// The stake info for the factory
    pub factory_info: StakeInfo,
    /// The stake info for the paymaster
    pub paymaster_info: StakeInfo,
    /// Optional aggregator_info
    pub aggregator_info: Option<AggregatorInfo>,
}

impl AbiDecode for ValidationOutput {
    fn decode(bytes: impl AsRef<[u8]>) -> Result<Self, AbiError> {
        if let Ok(result) = ValidationResult::decode(bytes.as_ref()) {
            return Ok(result.into());
        }
        if let Ok(result) = ValidationResultWithAggregation::decode(bytes) {
            return Ok(result.into());
        }
        Err(AbiError::DecodingError(abi::Error::InvalidData))
    }
}

impl From<ValidationResult> for ValidationOutput {
    fn from(value: ValidationResult) -> Self {
        let ValidationResult {
            return_info,
            sender_info,
            factory_info,
            paymaster_info,
        } = value;
        Self {
            return_info: return_info.into(),
            sender_info: sender_info.into(),
            factory_info: factory_info.into(),
            paymaster_info: paymaster_info.into(),
            aggregator_info: None,
        }
    }
}

impl From<ValidationResultWithAggregation> for ValidationOutput {
    fn from(value: ValidationResultWithAggregation) -> Self {
        let ValidationResultWithAggregation {
            return_info,
            sender_info,
            factory_info,
            paymaster_info,
            aggregator_info,
        } = value;
        Self {
            return_info: return_info.into(),
            sender_info: sender_info.into(),
            factory_info: factory_info.into(),
            paymaster_info: paymaster_info.into(),
            aggregator_info: Some(aggregator_info.into()),
        }
    }
}

/// ValidationReturnInfo from EntryPoint contract
#[derive(Debug)]
pub struct ValidationReturnInfo {
    /// The amount of gas used before the op was executed (pre verification gas and validation gas)
    pub pre_op_gas: U256,
    /// Whether the signature verification failed
    pub sig_failed: bool,
    /// The time after which the op is valid
    pub valid_after: Timestamp,
    /// The time until which the op is valid
    pub valid_until: Timestamp,
    /// The paymaster context
    pub paymaster_context: Bytes,
}

impl From<(U256, U256, bool, u64, u64, Bytes)> for ValidationReturnInfo {
    fn from(value: (U256, U256, bool, u64, u64, Bytes)) -> Self {
        let (
            pre_op_gas,
            _, /* prefund */
            sig_failed,
            valid_after,
            valid_until,
            paymaster_context,
        ) = value;
        Self {
            pre_op_gas,
            sig_failed,
            valid_after: valid_after.into(),
            valid_until: valid_until.into(),
            paymaster_context,
        }
    }
}

/// StakeInfo from EntryPoint contract
#[derive(Clone, Copy, Debug)]
pub struct StakeInfo {
    /// The amount of stake
    pub stake: U256,
    /// The delay for unstaking
    pub unstake_delay_sec: U256,
}

impl From<(U256, U256)> for StakeInfo {
    fn from((stake, unstake_delay_sec): (U256, U256)) -> Self {
        Self {
            stake,
            unstake_delay_sec,
        }
    }
}

/// AggregatorInfo from EntryPoint contract
#[derive(Clone, Copy, Debug)]
pub struct AggregatorInfo {
    /// The address of the aggregator
    pub address: Address,
    /// The stake info for the aggregator
    pub stake_info: StakeInfo,
}

impl From<(Address, (U256, U256))> for AggregatorInfo {
    fn from((address, stake_info): (Address, (U256, U256))) -> Self {
        Self {
            address,
            stake_info: stake_info.into(),
        }
    }
}
