use crate::common::contracts::entry_point::{ValidationResult, ValidationResultWithAggregation};
use ethers::abi;
use ethers::abi::{AbiDecode, AbiError};
use ethers::types::{Address, Bytes, U256};

/// Equivalent to the generated `ValidationResult` or
/// `ValidationResultWithAggregation` from `EntryPoint`, but with named structs
/// instead of tuples and with a helper for deserializing.
#[derive(Debug)]
pub struct EntryPointOutput {
    pub return_info: EntryPointReturnInfo,
    pub sender_info: StakeInfo,
    pub factory_info: StakeInfo,
    pub paymaster_info: StakeInfo,
    pub aggregator_info: Option<AggregatorInfo>,
}

impl AbiDecode for EntryPointOutput {
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

impl From<ValidationResult> for EntryPointOutput {
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

impl From<ValidationResultWithAggregation> for EntryPointOutput {
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
pub struct EntryPointReturnInfo {
    pub pre_op_gas: U256,
    pub prefund: U256,
    pub sig_failed: bool,
    pub valid_after: u64,
    pub valid_until: u64,
    pub paymaster_context: Bytes,
}

impl From<(U256, U256, bool, u64, u64, Bytes)> for EntryPointReturnInfo {
    fn from(value: (U256, U256, bool, u64, u64, Bytes)) -> Self {
        let (pre_op_gas, prefund, sig_failed, valid_after, valid_until, paymaster_context) = value;
        Self {
            pre_op_gas,
            prefund,
            sig_failed,
            valid_after,
            valid_until,
            paymaster_context,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StakeInfo {
    pub stake: U256,
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

#[derive(Clone, Copy, Debug)]
pub struct AggregatorInfo {
    pub address: Address,
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
