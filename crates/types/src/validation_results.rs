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

use std::{cmp::Ordering, ops::Add};

use alloy_primitives::{address, Address, Bytes, U256};
use alloy_sol_types::{Panic, Revert, SolError};
use rundler_contracts::{
    v0_6::{
        AggregatorStakeInfo as AggregatorStakeInfoV0_6,
        IEntryPoint::{
            FailedOp as FailedOpV0_6, ValidationResult as ValidationResultV0_6,
            ValidationResultWithAggregation as ValidationResultWithAggregationV0_6,
        },
        ReturnInfo as ReturnInfoV0_6, StakeInfo as StakeInfoV0_6,
    },
    v0_7::{
        AggregatorStakeInfo as AggregatorStakeInfoV0_7,
        IEntryPoint::{FailedOp as FailedOpV0_7, FailedOpWithRevert as FailedOpWithRevertV0_7},
        ReturnInfo as ReturnInfoV0_7, StakeInfo as StakeInfoV0_7,
        ValidationResult as ValidationResultV0_7,
    },
};

use crate::{Timestamp, ValidTimeRange, TIME_RANGE_BUFFER};

/// Both v0.6 and v0.7 contracts use this aggregator address to indicate that the signature validation failed
/// Zero is also used to indicate that no aggregator is used AND that the signature validation failed.
const SIG_VALIDATION_FAILED: Address = address!("0000000000000000000000000000000000000001");

/// Error during validation simulation
#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
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
    /// Validation reverted with an unknown signature
    #[error("revert with bytes: {0:?}")]
    Unknown(Bytes),
    /// Validation reverted with a panic
    #[error("panic: {0}")]
    Panic(Panic),
}

impl PartialOrd for ValidationRevert {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ValidationRevert {
    fn cmp(&self, other: &Self) -> Ordering {
        // choose any deterministic order
        self.to_string().cmp(&other.to_string())
    }
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
            Self::Unknown(_) | Self::Panic(_) => None,
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

impl From<Revert> for ValidationRevert {
    fn from(value: Revert) -> Self {
        ValidationRevert::EntryPoint(value.reason)
    }
}

impl From<Panic> for ValidationRevert {
    fn from(value: Panic) -> Self {
        ValidationRevert::Panic(value)
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
        let inner_message = Revert::abi_decode(&value.inner).ok().map(|err| err.reason);
        ValidationRevert::Operation {
            entry_point_reason: value.reason,
            inner_revert_data: value.inner,
            inner_revert_reason: inner_message,
        }
    }
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
    pub fn decode_v0_6(bytes: impl AsRef<[u8]>) -> Result<Self, &'static str> {
        if let Ok(result) = ValidationResultV0_6::abi_decode(bytes.as_ref()) {
            return ValidationOutput::try_from(result);
        }
        if let Ok(result) = ValidationResultWithAggregationV0_6::abi_decode(bytes.as_ref()) {
            return ValidationOutput::try_from(result);
        }
        Err("Invalid validation result")
    }
}

impl TryFrom<ValidationResultV0_6> for ValidationOutput {
    type Error = &'static str;

    fn try_from(value: ValidationResultV0_6) -> Result<Self, Self::Error> {
        let ValidationResultV0_6 {
            returnInfo,
            senderInfo,
            factoryInfo,
            paymasterInfo,
        } = value;
        Ok(Self {
            return_info: returnInfo.try_into()?,
            sender_info: senderInfo.try_into()?,
            factory_info: factoryInfo.try_into()?,
            paymaster_info: paymasterInfo.try_into()?,
            aggregator_info: None,
        })
    }
}

impl TryFrom<ValidationResultWithAggregationV0_6> for ValidationOutput {
    type Error = &'static str;

    fn try_from(value: ValidationResultWithAggregationV0_6) -> Result<Self, Self::Error> {
        let ValidationResultWithAggregationV0_6 {
            returnInfo,
            senderInfo,
            factoryInfo,
            paymasterInfo,
            aggregatorInfo,
        } = value;
        Ok(Self {
            return_info: returnInfo.try_into()?,
            sender_info: senderInfo.try_into()?,
            factory_info: factoryInfo.try_into()?,
            paymaster_info: paymasterInfo.try_into()?,
            aggregator_info: Some(aggregatorInfo.try_into()?),
        })
    }
}

impl TryFrom<ValidationResultV0_7> for ValidationOutput {
    type Error = &'static str;

    fn try_from(value: ValidationResultV0_7) -> Result<Self, Self::Error> {
        let ValidationResultV0_7 {
            returnInfo,
            senderInfo,
            factoryInfo,
            paymasterInfo,
            aggregatorInfo,
        } = value;

        let aggregator_info = if aggregatorInfo.aggregator.is_zero() {
            None
        } else {
            Some(aggregatorInfo.try_into()?)
        };

        Ok(Self {
            return_info: returnInfo.try_into()?,
            sender_info: senderInfo.try_into()?,
            factory_info: factoryInfo.try_into()?,
            paymaster_info: paymasterInfo.try_into()?,
            aggregator_info,
        })
    }
}

/// ValidationReturnInfo from EntryPoint contract
#[derive(Clone, Debug, Default)]
pub struct ValidationReturnInfo {
    /// The amount of gas used before the op was executed (pre verification gas and validation gas)
    pub pre_op_gas: u128,
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
        self.valid_after <= now && self.valid_until > now.add(TIME_RANGE_BUFFER)
    }
}

// Conversion for v0.6
impl TryFrom<ReturnInfoV0_6> for ValidationReturnInfo {
    type Error = &'static str;

    fn try_from(value: ReturnInfoV0_6) -> Result<Self, Self::Error> {
        let ReturnInfoV0_6 {
            preOpGas,
            prefund: _,
            sigFailed,
            validAfter,
            validUntil,
            paymasterContext,
        } = value;
        Ok(Self {
            pre_op_gas: preOpGas
                .try_into()
                .map_err(|_| "preOpGas is larger than u128")?,
            // In v0.6 if one signature fails both do
            account_sig_failed: sigFailed,
            paymaster_sig_failed: sigFailed,
            valid_after: validAfter.to::<u64>().into(),
            valid_until: validUntil.to::<u64>().into(),
            paymaster_context: paymasterContext,
        })
    }
}

impl TryFrom<ReturnInfoV0_7> for ValidationReturnInfo {
    type Error = &'static str;

    fn try_from(value: ReturnInfoV0_7) -> Result<Self, Self::Error> {
        let ReturnInfoV0_7 {
            preOpGas,
            prefund: _,
            accountValidationData,
            paymasterValidationData,
            paymasterContext,
        } = value;

        let account = parse_validation_data(accountValidationData);
        let paymaster = parse_validation_data(paymasterValidationData);
        let intersect_range = account
            .valid_time_range()
            .intersect(paymaster.valid_time_range());

        Ok(Self {
            pre_op_gas: preOpGas
                .try_into()
                .map_err(|_| "preOpGas is larger than u128")?,
            account_sig_failed: !account.signature_valid(),
            paymaster_sig_failed: !paymaster.signature_valid(),
            valid_after: intersect_range.valid_after,
            valid_until: intersect_range.valid_until,
            paymaster_context: paymasterContext,
        })
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
///
/// Converts 0 valid until to u64::MAX
pub fn parse_validation_data(data: U256) -> ValidationData {
    let slice: [u8; 32] = data.to_be_bytes();
    let aggregator = Address::from_slice(&slice[12..]);

    let mut buf = [0; 8];
    buf[2..8].copy_from_slice(&slice[6..12]);
    let mut valid_until = u64::from_be_bytes(buf);
    if valid_until == 0 {
        valid_until = u64::MAX;
    }

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
#[derive(Clone, Copy, Debug, Default)]
pub struct StakeInfo {
    /// The amount of stake
    pub stake: U256,
    /// The delay for unstaking
    pub unstake_delay_sec: u32,
}

impl TryFrom<StakeInfoV0_6> for StakeInfo {
    type Error = &'static str;

    fn try_from(value: StakeInfoV0_6) -> Result<Self, Self::Error> {
        let StakeInfoV0_6 {
            stake,
            unstakeDelaySec,
        } = value;
        Ok(Self {
            stake,
            unstake_delay_sec: unstakeDelaySec
                .try_into()
                .map_err(|_| "unstake delay is larger than u32")?,
        })
    }
}

impl TryFrom<StakeInfoV0_7> for StakeInfo {
    type Error = &'static str;

    fn try_from(value: StakeInfoV0_7) -> Result<Self, Self::Error> {
        let StakeInfoV0_7 {
            stake,
            unstakeDelaySec,
        } = value;
        Ok(Self {
            stake,
            unstake_delay_sec: unstakeDelaySec
                .try_into()
                .map_err(|_| "unstake delay is larger than u32")?,
        })
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

impl TryFrom<AggregatorStakeInfoV0_6> for AggregatorInfo {
    type Error = &'static str;

    fn try_from(value: AggregatorStakeInfoV0_6) -> Result<Self, Self::Error> {
        let AggregatorStakeInfoV0_6 {
            aggregator,
            stakeInfo,
        } = value;
        Ok(Self {
            address: aggregator,
            stake_info: stakeInfo.try_into()?,
        })
    }
}

impl TryFrom<AggregatorStakeInfoV0_7> for AggregatorInfo {
    type Error = &'static str;

    fn try_from(value: AggregatorStakeInfoV0_7) -> Result<Self, Self::Error> {
        let AggregatorStakeInfoV0_7 {
            aggregator,
            stakeInfo,
        } = value;
        Ok(Self {
            address: aggregator,
            stake_info: stakeInfo.try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{address, uint};

    use super::parse_validation_data;

    #[test]
    fn test_parse_validation_data() {
        let data = uint!(0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff_U256);
        let parsed = parse_validation_data(data);
        assert_eq!(
            parsed.aggregator,
            address!("ccddeeff00112233445566778899aabbccddeeff")
        );

        assert_eq!(parsed.valid_until, 0x66778899aabb);
        assert_eq!(parsed.valid_after, 0x001122334455);
    }

    #[test]
    fn test_parse_validation_data_zero_valid_until() {
        let data = uint!(0x001122334455000000000000ccddeeff00112233445566778899aabbccddeeff_U256);
        let parsed = parse_validation_data(data);
        assert_eq!(
            parsed.aggregator,
            address!("ccddeeff00112233445566778899aabbccddeeff")
        );

        assert_eq!(parsed.valid_until, u64::MAX);
        assert_eq!(parsed.valid_after, 0x001122334455);
    }
}
