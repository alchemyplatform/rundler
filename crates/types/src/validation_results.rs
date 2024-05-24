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

use std::ops::Add;

use ethers::{
    abi::{self, AbiDecode, AbiError},
    types::{Address, Bytes, H160, U256},
};
use rundler_utils::eth::ContractRevertError;

use crate::{
    contracts::{
        v0_6::i_entry_point::{
            FailedOp as FailedOpV0_6, ValidationResult as ValidationResultV0_6,
            ValidationResultWithAggregation as ValidationResultWithAggregationV0_6,
        },
        v0_7::entry_point_simulations::{
            AggregatorStakeInfo as AggregatorStakeInfoV0_7, FailedOp as FailedOpV0_7,
            FailedOpWithRevert as FailedOpWithRevertV0_7, ReturnInfo as ReturnInfoV0_7,
            StakeInfo as StakeInfoV0_7, ValidationResult as ValidationResultV0_7,
        },
    },
    Timestamp, ValidTimeRange, TIME_RANGE_BUFFER,
};

/// Both v0.6 and v0.7 contracts use this aggregator address to indicate that the signature validation failed
/// Zero is also used to indicate that no aggregator is used AND that the signature validation failed.
const SIG_VALIDATION_FAILED: Address =
    H160([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

/// Error during validation simulation
#[derive(Clone, Debug, thiserror::Error, Ord, PartialOrd, Eq, PartialEq)]
pub enum ValidationRevert {
    /// The entry point reverted
    #[error("{0}")]
    EntryPoint(String),
    /// The operation reverted
    #[error("{}", Self::display_operation_error(.entry_point_reason, .inner_revert_reason))]
    Operation {
        /// Error message returned by entry point
        entry_point_reason: String,
        /// Revert data of the validation failure returned by an entity
        inner_revert_data: Bytes,
        /// Message parsed from the inner revert data, if the entity used the
        /// `revert` or `require` Solidity keywords
        inner_revert_reason: Option<String>,
    },
    /// Validation everted with an unknown signature
    #[error("revert with bytes: {0:?}")]
    Unknown(Bytes),
}

impl ValidationRevert {
    /// Extracts the error code string returned by the entry point, e.g.
    /// `"AA24"`, if it exists.
    pub fn entry_point_error_code(&self) -> Option<&str> {
        let message = match self {
            Self::EntryPoint(message) => Some(message),
            Self::Operation {
                entry_point_reason: entry_point_message,
                ..
            } => Some(entry_point_message),
            Self::Unknown(_) => None,
        };
        message
            .filter(|m| m.len() >= 4 && m.starts_with("AA"))
            .map(|m| &m[..4])
    }

    fn display_operation_error(
        entry_point_message: &str,
        inner_message: &Option<String>,
    ) -> String {
        match inner_message {
            Some(inner_message) => format!("{entry_point_message} : {inner_message}"),
            None => entry_point_message.to_owned(),
        }
    }
}

impl From<ContractRevertError> for ValidationRevert {
    fn from(value: ContractRevertError) -> Self {
        ValidationRevert::EntryPoint(value.reason)
    }
}

impl From<FailedOpV0_6> for ValidationRevert {
    fn from(value: FailedOpV0_6) -> Self {
        ValidationRevert::EntryPoint(value.reason)
    }
}

impl From<FailedOpV0_7> for ValidationRevert {
    fn from(value: FailedOpV0_7) -> Self {
        ValidationRevert::EntryPoint(value.reason)
    }
}

impl From<FailedOpWithRevertV0_7> for ValidationRevert {
    fn from(value: FailedOpWithRevertV0_7) -> Self {
        let inner_message = ContractRevertError::decode(&value.inner)
            .ok()
            .map(|err| err.reason);
        ValidationRevert::Operation {
            entry_point_reason: value.reason,
            inner_revert_data: value.inner,
            inner_revert_reason: inner_message,
        }
    }
}

/// Error during validation simulation
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// The validation reverted
    #[error(transparent)]
    Revert(#[from] ValidationRevert),
    /// Other error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Equivalent to the generated `ValidationResult` or
/// `ValidationResultWithAggregation` from `EntryPoint`, but with named structs
/// instead of tuples and with a helper for deserializing.
#[derive(Clone, Debug)]
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

impl ValidationOutput {
    /// Decode a v0.6 validation result from bytes.
    pub fn decode_v0_6(bytes: impl AsRef<[u8]>) -> Result<Self, AbiError> {
        if let Ok(result) = ValidationResultV0_6::decode(bytes.as_ref()) {
            return Ok(result.into());
        }
        if let Ok(result) = ValidationResultWithAggregationV0_6::decode(bytes) {
            return Ok(result.into());
        }
        Err(AbiError::DecodingError(abi::Error::InvalidData))
    }

    /// Decode a v0.6 validation result from hex.
    pub fn decode_v0_6_hex(hex: impl AsRef<str>) -> Result<Self, AbiError> {
        let bytes: Bytes = hex.as_ref().parse()?;
        Self::decode_v0_6(&bytes)
    }

    /// Decode a v0.7 validation result from bytes.
    pub fn decode_v0_7(bytes: impl AsRef<[u8]>) -> Result<Self, AbiError> {
        if let Ok(result) = ValidationResultV0_7::decode(bytes.as_ref()) {
            return Ok(result.into());
        }
        Err(AbiError::DecodingError(abi::Error::InvalidData))
    }

    /// Decode a v0.7 validation result from hex.
    pub fn decode_v0_7_hex(hex: impl AsRef<str>) -> Result<Self, AbiError> {
        let bytes: Bytes = hex.as_ref().parse()?;
        Self::decode_v0_7(&bytes)
    }
}

impl From<ValidationResultV0_6> for ValidationOutput {
    fn from(value: ValidationResultV0_6) -> Self {
        let ValidationResultV0_6 {
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

impl From<ValidationResultWithAggregationV0_6> for ValidationOutput {
    fn from(value: ValidationResultWithAggregationV0_6) -> Self {
        let ValidationResultWithAggregationV0_6 {
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

impl From<ValidationResultV0_7> for ValidationOutput {
    fn from(value: ValidationResultV0_7) -> Self {
        let ValidationResultV0_7 {
            return_info,
            sender_info,
            factory_info,
            paymaster_info,
            aggregator_info,
        } = value;

        let aggregator_info = if aggregator_info.aggregator.is_zero() {
            None
        } else {
            Some(aggregator_info.into())
        };

        Self {
            return_info: return_info.into(),
            sender_info: sender_info.into(),
            factory_info: factory_info.into(),
            paymaster_info: paymaster_info.into(),
            aggregator_info,
        }
    }
}

/// ValidationReturnInfo from EntryPoint contract
#[derive(Clone, Debug)]
pub struct ValidationReturnInfo {
    /// The amount of gas used before the op was executed (pre verification gas and validation gas)
    pub pre_op_gas: U256,
    /// Whether the account signature verification failed
    pub account_sig_failed: bool,
    /// Whether the paymaster signature verification failed
    pub paymaster_sig_failed: bool,
    /// The time after which the op is valid
    pub valid_after: Timestamp,
    /// The time until which the op is valid
    pub valid_until: Timestamp,
    /// The paymaster context
    pub paymaster_context: Bytes,
}

impl ValidationReturnInfo {
    /// helper function to check if the returned time range is valid
    pub fn is_valid_time_range(&self) -> bool {
        let now = Timestamp::now();
        self.valid_after <= now || self.valid_until > now.add(TIME_RANGE_BUFFER)
    }
}

// Conversion for v0.6
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
        // In v0.6 if one signature fails both do
        Self {
            pre_op_gas,
            account_sig_failed: sig_failed,
            paymaster_sig_failed: sig_failed,
            valid_after: valid_after.into(),
            valid_until: valid_until.into(),
            paymaster_context,
        }
    }
}

impl From<ReturnInfoV0_7> for ValidationReturnInfo {
    fn from(value: ReturnInfoV0_7) -> Self {
        let ReturnInfoV0_7 {
            pre_op_gas,
            prefund: _,
            account_validation_data,
            paymaster_validation_data,
            paymaster_context,
        } = value;

        let account = parse_validation_data(account_validation_data);
        let paymaster = parse_validation_data(paymaster_validation_data);

        let intersect_range = account
            .valid_time_range()
            .intersect(paymaster.valid_time_range());

        Self {
            pre_op_gas,
            account_sig_failed: !account.signature_valid(),
            paymaster_sig_failed: !paymaster.signature_valid(),
            valid_after: intersect_range.valid_after,
            valid_until: intersect_range.valid_until,
            paymaster_context,
        }
    }
}

/// ValidationData from EntryPoint contract
pub struct ValidationData {
    aggregator: Address,
    valid_after: u64,
    valid_until: u64,
}

impl ValidationData {
    /// Valid time range for the validation data
    pub fn valid_time_range(&self) -> ValidTimeRange {
        ValidTimeRange::new(self.valid_after.into(), self.valid_until.into())
    }

    /// Whether the signature is valid
    pub fn signature_valid(&self) -> bool {
        self.aggregator != SIG_VALIDATION_FAILED
    }

    /// The aggregator address, if any
    pub fn aggregator(&self) -> Option<Address> {
        if self.aggregator == SIG_VALIDATION_FAILED || self.aggregator.is_zero() {
            None
        } else {
            Some(self.aggregator)
        }
    }
}

/// Parse the validation data from a U256
///
/// Works for both v0.6 and v0.7 validation data
pub fn parse_validation_data(data: U256) -> ValidationData {
    let slice: [u8; 32] = data.into();
    let aggregator = Address::from_slice(&slice[12..]);

    let mut buf = [0; 8];
    buf[2..8].copy_from_slice(&slice[6..12]);
    let valid_until = u64::from_be_bytes(buf);

    let mut buf = [0; 8];
    buf[2..8].copy_from_slice(&slice[..6]);
    let valid_after = u64::from_be_bytes(buf);

    ValidationData {
        aggregator,
        valid_after,
        valid_until,
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

impl From<StakeInfoV0_7> for StakeInfo {
    fn from(value: StakeInfoV0_7) -> Self {
        let StakeInfoV0_7 {
            stake,
            unstake_delay_sec,
        } = value;
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

impl From<AggregatorStakeInfoV0_7> for AggregatorInfo {
    fn from(value: AggregatorStakeInfoV0_7) -> Self {
        let AggregatorStakeInfoV0_7 {
            aggregator,
            stake_info,
        } = value;
        Self {
            address: aggregator,
            stake_info: stake_info.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_validation_data;

    #[test]
    fn test_parse_validation_data() {
        let data = "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let parsed = parse_validation_data(data.into());
        assert_eq!(
            parsed.aggregator,
            "0xccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap()
        );

        assert_eq!(parsed.valid_until, 0x66778899aabb);
        assert_eq!(parsed.valid_after, 0x001122334455);
    }
}
