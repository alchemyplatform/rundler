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
use rundler_types::{
    contracts::entry_point::{ValidationResult, ValidationResultWithAggregation},
    Timestamp,
};

/// Equivalent to the generated `ValidationResult` or
/// `ValidationResultWithAggregation` from `EntryPoint`, but with named structs
/// instead of tuples and with a helper for deserializing.
#[derive(Debug)]
pub(crate) struct ValidationOutput {
    pub(crate) return_info: ValidationReturnInfo,
    pub(crate) sender_info: StakeInfo,
    pub(crate) factory_info: StakeInfo,
    pub(crate) paymaster_info: StakeInfo,
    pub(crate) aggregator_info: Option<AggregatorInfo>,
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

#[derive(Debug)]
pub(crate) struct ValidationReturnInfo {
    pub(crate) pre_op_gas: U256,
    pub(crate) sig_failed: bool,
    pub(crate) valid_after: Timestamp,
    pub(crate) valid_until: Timestamp,
    pub(crate) paymaster_context: Bytes,
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct StakeInfo {
    pub(crate) stake: U256,
    pub(crate) unstake_delay_sec: U256,
}

impl From<(U256, U256)> for StakeInfo {
    fn from((stake, unstake_delay_sec): (U256, U256)) -> Self {
        Self {
            stake,
            unstake_delay_sec,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AggregatorInfo {
    pub(crate) address: Address,
    pub(crate) stake_info: StakeInfo,
}

impl From<(Address, (U256, U256))> for AggregatorInfo {
    fn from((address, stake_info): (Address, (U256, U256))) -> Self {
        Self {
            address,
            stake_info: stake_info.into(),
        }
    }
}
