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

use std::fmt::Display;

use ethers::types::{Address, Bytes, U256};
use jsonrpsee::types::{
    error::{CALL_EXECUTION_FAILED_CODE, INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE},
    ErrorObjectOwned,
};
use rundler_provider::ProviderError;
use rundler_sim::GasEstimationError;
use rundler_types::{
    pool::{MempoolError, PoolError, PrecheckViolation, SimulationViolation},
    Entity, EntityType, Opcode, Timestamp, ValidationRevert,
};
use serde::Serialize;

use crate::error::{rpc_err, rpc_err_with_data};

// Error codes borrowed from jsonrpsee
// INVALID_REQUEST_CODE = -32600
// INVALID_PARAMS_CODE = -32602
// INTERNAL_ERROR_CODE = -32603

// Custom ERC-4337 error codes
const ENTRYPOINT_VALIDATION_REJECTED_CODE: i32 = -32500;
const PAYMASTER_VALIDATION_REJECTED_CODE: i32 = -32501;
const OPCODE_VIOLATION_CODE: i32 = -32502;
const OUT_OF_TIME_RANGE_CODE: i32 = -32503;
const THROTTLED_OR_BANNED_CODE: i32 = -32504;
const STAKE_TOO_LOW_CODE: i32 = -32505;
const UNSUPORTED_AGGREGATOR_CODE: i32 = -32506;
const SIGNATURE_CHECK_FAILED_CODE: i32 = -32507;
const PAYMASTER_DEPOSIT_TOO_LOW: i32 = -32508;
const EXECUTION_REVERTED: i32 = -32521;

pub(crate) type EthResult<T> = Result<T, EthRpcError>;

/// Error returned by the RPC server eth namespace
#[derive(Debug, thiserror::Error)]
pub enum EthRpcError {
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
    /// Invalid parameters
    #[error("{0}")]
    InvalidParams(String),
    /// Validation rejected the operation in entrypoint or during
    /// wallet creation or validation
    #[error("{0}")]
    EntryPointValidationRejected(String),
    /// Paymaster rejected the operation
    #[error("{}", .0.reason)]
    PaymasterValidationRejected(PaymasterValidationRejectedData),
    /// Multiple roles violation
    #[error("A {} at {} in this UserOperation is used as a sender entity in another UserOperation currently in mempool.", .0.kind, .0.address)]
    MultipleRolesViolation(Entity),
    /// Paymaster balance too low
    #[error("Paymaster balance too low. Required balance: {0}. Current balance {1}")]
    PaymasterBalanceTooLow(U256, U256),
    /// An Associated storage slot that is accessed in the UserOperation is being used as a sender by another UserOperation in the mempool.
    #[error("An Associated storage slot that is accessed in the UserOperation is being used as a sender by another UserOperation in the mempool")]
    AssociatedStorageIsAlternateSender,
    /// Sender address used as different entity in another UserOperation currently in the mempool.
    #[error("The sender address {0} is used as a different entity in another UserOperation currently in mempool")]
    SenderAddressUsedAsAlternateEntity(Address),
    /// Simulation ran out of gas
    #[error("Simulation ran out of gas for entity: {0}")]
    OutOfGas(Entity),
    /// Opcode violation
    #[error("{0} uses banned opcode: {1:?}")]
    OpcodeViolation(EntityType, Opcode),
    /// Used for other simulation violations that map to Opcode Violations
    #[error("{0}")]
    OpcodeViolationMap(SimulationViolation),
    /// Associated storage accessed during deployment with unstaked factory or accessing entity
    #[error("Sender storage at (address: {1:?} slot: {2:#032x}) accessed during deployment. Factory (or {0:?}) must be staked")]
    AssociatedStorageDuringDeploy(Option<EntityType>, Address, U256),
    /// Invalid storage access, maps to Opcode Violation
    #[error("{0} accesses inaccessible storage at address: {1:?} slot: {2:#032x}")]
    InvalidStorageAccess(EntityType, Address, U256),
    /// Operation is out of time range
    #[error("operation is out of time range")]
    OutOfTimeRange(OutOfTimeRangeData),
    /// Max operations reached for this sender
    #[error("Max operations ({0}) reached for {1} due to being unstaked")]
    MaxOperationsReached(usize, Entity),
    /// Entity throttled or banned
    #[error("{} {:#032x} throttled or banned", .0.kind, .0.address)]
    ThrottledOrBanned(Entity),
    /// Entity stake/unstake delay too low
    #[error("entity stake/unstake delay too low")]
    StakeTooLow(Box<StakeTooLowData>),
    /// The user operation uses a paymaster that returns a context while being unstaked
    #[error("Unstaked paymaster must not return context")]
    UnstakedPaymasterContext,
    /// The user operation uses an aggregator entity and it is not staked
    #[error("An aggregator must be staked, regardless of storager usage")]
    UnstakedAggregator,
    /// Unsupported aggregator
    #[error("unsupported aggregator")]
    UnsupportedAggregator(UnsupportedAggregatorData),
    /// Replacement underpriced
    #[error("replacement underpriced")]
    ReplacementUnderpriced(ReplacementUnderpricedData),
    /// Operation already known
    #[error("already known")]
    OperationAlreadyKnown,
    /// Other internal errors
    #[error("Invalid UserOp signature or paymaster signature")]
    SignatureCheckFailed,
    #[error("Invalid account signature")]
    AccountSignatureCheckFailed,
    #[error("Invalid paymaster signature")]
    PaymasterSignatureCheckFailed,
    #[error("precheck failed: {0}")]
    PrecheckFailed(PrecheckViolation),
    #[error("validation simulation failed: {0}")]
    SimulationFailed(SimulationViolation),
    #[error("validation reverted: {0}")]
    ValidationRevert(ValidationRevertData),
    #[error("{0}")]
    ExecutionReverted(String),
    #[error("execution reverted")]
    ExecutionRevertedWithBytes(ExecutionRevertedWithBytesData),
    #[error("operation rejected by mempool: {0}")]
    OperationRejected(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct PaymasterValidationRejectedData {
    pub paymaster: Address,
    #[serde(skip_serializing)] // this is included in the message
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutOfTimeRangeData {
    pub valid_until: Timestamp,
    pub valid_after: Timestamp,
    pub paymaster: Option<Address>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StakeTooLowData {
    needs_stake: Entity,
    accessing_entity: EntityType,
    accessed_address: Address,
    accessed_entity: Option<EntityType>,
    slot: U256,
    minimum_stake: U256,
    minimum_unstake_delay: U256,
}

impl StakeTooLowData {
    pub fn new(
        needs_stake: Entity,
        accessing_entity: EntityType,
        accessed_address: Address,
        accessed_entity: Option<EntityType>,
        slot: U256,
        minimum_stake: U256,
        minimum_unstake_delay: U256,
    ) -> Self {
        Self {
            needs_stake,
            accessing_entity,
            accessed_address,
            accessed_entity,
            slot,
            minimum_stake,
            minimum_unstake_delay,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationRevertData {
    reason: Option<String>,
    inner_reason: Option<String>,
    revert_data: Option<Bytes>,
}

impl Display for ValidationRevertData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(reason) = &self.reason {
            write!(f, "[reason]: {}", reason)?;
        }
        if let Some(inner_reason) = &self.inner_reason {
            write!(f, " | [inner reason]: {}", inner_reason)?;
        }
        Ok(())
    }
}

impl From<ValidationRevert> for ValidationRevertData {
    fn from(value: ValidationRevert) -> Self {
        match value {
            ValidationRevert::EntryPoint(reason) => Self {
                reason: Some(reason),
                inner_reason: None,
                revert_data: None,
            },
            ValidationRevert::Operation {
                entry_point_reason,
                inner_revert_data,
                inner_revert_reason,
            } => Self {
                reason: Some(entry_point_reason),
                inner_reason: inner_revert_reason,
                revert_data: Some(inner_revert_data),
            },
            ValidationRevert::Unknown(data) => Self {
                reason: None,
                inner_reason: None,
                revert_data: Some(data),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacementUnderpricedData {
    pub current_max_priority_fee: U256,
    pub current_max_fee: U256,
}

impl ReplacementUnderpricedData {
    pub fn new(current_max_priority_fee: U256, current_max_fee: U256) -> Self {
        Self {
            current_max_priority_fee,
            current_max_fee,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct UnsupportedAggregatorData {
    pub aggregator: Address,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionRevertedWithBytesData {
    pub revert_data: Bytes,
}

impl From<PoolError> for EthRpcError {
    fn from(value: PoolError) -> Self {
        match value {
            PoolError::MempoolError(e) => e.into(),
            PoolError::UnexpectedResponse => {
                Self::Internal(anyhow::anyhow!("unexpected response from pool server"))
            }
            PoolError::Other(e) => Self::Internal(e),
        }
    }
}

impl From<MempoolError> for EthRpcError {
    fn from(value: MempoolError) -> Self {
        match value {
            MempoolError::Other(e) => Self::Internal(e),
            MempoolError::OperationAlreadyKnown => Self::OperationAlreadyKnown,
            MempoolError::ReplacementUnderpriced(priority_fee, fee) => {
                Self::ReplacementUnderpriced(ReplacementUnderpricedData {
                    current_max_priority_fee: priority_fee,
                    current_max_fee: fee,
                })
            }
            MempoolError::MaxOperationsReached(count, address) => {
                Self::MaxOperationsReached(count, address)
            }
            MempoolError::EntityThrottled(entity) => Self::ThrottledOrBanned(entity),
            MempoolError::MultipleRolesViolation(entity) => Self::MultipleRolesViolation(entity),
            MempoolError::PaymasterBalanceTooLow(current_balance, required_balance) => {
                Self::PaymasterBalanceTooLow(current_balance, required_balance)
            }
            MempoolError::AssociatedStorageIsAlternateSender => {
                Self::AssociatedStorageIsAlternateSender
            }
            MempoolError::SenderAddressUsedAsAlternateEntity(address) => {
                Self::SenderAddressUsedAsAlternateEntity(address)
            }
            MempoolError::DiscardedOnInsert => {
                Self::OperationRejected("discarded on insert".to_owned())
            }
            MempoolError::PrecheckViolation(violation) => violation.into(),
            MempoolError::SimulationViolation(violation) => violation.into(),
            MempoolError::UnsupportedAggregator(a) => {
                Self::UnsupportedAggregator(UnsupportedAggregatorData { aggregator: a })
            }
            MempoolError::UnknownEntryPoint(a) => {
                Self::EntryPointValidationRejected(format!("unknown entry point: {}", a))
            }
            MempoolError::OperationDropTooSoon(_, _, _) => Self::InvalidParams(value.to_string()),
        }
    }
}

impl From<PrecheckViolation> for EthRpcError {
    fn from(value: PrecheckViolation) -> Self {
        Self::PrecheckFailed(value)
    }
}

impl From<SimulationViolation> for EthRpcError {
    fn from(value: SimulationViolation) -> Self {
        match value {
            SimulationViolation::InvalidSignature => Self::SignatureCheckFailed,
            SimulationViolation::InvalidAccountSignature => Self::AccountSignatureCheckFailed,
            SimulationViolation::InvalidPaymasterSignature => Self::PaymasterSignatureCheckFailed,
            SimulationViolation::UnintendedRevertWithMessage(
                EntityType::Paymaster,
                reason,
                Some(paymaster),
            ) => Self::PaymasterValidationRejected(PaymasterValidationRejectedData {
                paymaster,
                reason,
            }),
            SimulationViolation::UnintendedRevertWithMessage(_, reason, _) => {
                Self::EntryPointValidationRejected(reason)
            }
            SimulationViolation::UsedForbiddenOpcode(entity, _, op) => {
                Self::OpcodeViolation(entity.kind, op.0)
            }
            SimulationViolation::UsedForbiddenPrecompile(_, _, _)
            | SimulationViolation::AccessedUndeployedContract(_, _)
            | SimulationViolation::AccessedUnsupportedContractType(_, _)
            | SimulationViolation::CalledBannedEntryPointMethod(_)
            | SimulationViolation::CallHadValue(_) => Self::OpcodeViolationMap(value),
            SimulationViolation::FactoryCalledCreate2Twice(_) => {
                Self::OpcodeViolation(EntityType::Factory, Opcode::CREATE2)
            }
            SimulationViolation::UnstakedPaymasterContext => Self::UnstakedPaymasterContext,
            SimulationViolation::AssociatedStorageDuringDeploy(e, s) => {
                Self::AssociatedStorageDuringDeploy(e.map(|e| e.kind), s.address, s.slot)
            }
            SimulationViolation::InvalidStorageAccess(entity, slot) => {
                Self::InvalidStorageAccess(entity.kind, slot.address, slot.slot)
            }
            SimulationViolation::NotStaked(stake_data) => {
                Self::StakeTooLow(Box::new(StakeTooLowData::new(
                    stake_data.needs_stake,
                    stake_data.accessing_entity,
                    stake_data.accessed_address,
                    stake_data.accessed_entity,
                    stake_data.slot,
                    stake_data.min_stake,
                    stake_data.min_unstake_delay,
                )))
            }
            SimulationViolation::AggregatorValidationFailed => Self::SignatureCheckFailed,
            SimulationViolation::OutOfGas(entity) => Self::OutOfGas(entity),
            SimulationViolation::ValidationRevert(revert) => Self::ValidationRevert(revert.into()),
            _ => Self::SimulationFailed(value),
        }
    }
}

impl From<EthRpcError> for ErrorObjectOwned {
    fn from(error: EthRpcError) -> Self {
        let msg = error.to_string();

        match error {
            EthRpcError::Internal(_) => rpc_err(INTERNAL_ERROR_CODE, msg),
            EthRpcError::InvalidParams(_) => rpc_err(INVALID_PARAMS_CODE, msg),
            EthRpcError::EntryPointValidationRejected(_) | EthRpcError::SimulationFailed(_) => {
                rpc_err(ENTRYPOINT_VALIDATION_REJECTED_CODE, msg)
            }
            EthRpcError::PaymasterValidationRejected(data) => {
                rpc_err_with_data(PAYMASTER_VALIDATION_REJECTED_CODE, msg, data)
            }
            EthRpcError::PaymasterBalanceTooLow(_, _) => rpc_err(PAYMASTER_DEPOSIT_TOO_LOW, msg),
            EthRpcError::OpcodeViolation(_, _)
            | EthRpcError::OpcodeViolationMap(_)
            | EthRpcError::OutOfGas(_)
            | EthRpcError::UnstakedAggregator
            | EthRpcError::MultipleRolesViolation(_)
            | EthRpcError::UnstakedPaymasterContext
            | EthRpcError::SenderAddressUsedAsAlternateEntity(_)
            | EthRpcError::AssociatedStorageIsAlternateSender
            | EthRpcError::AssociatedStorageDuringDeploy(_, _, _)
            | EthRpcError::InvalidStorageAccess(_, _, _) => rpc_err(OPCODE_VIOLATION_CODE, msg),
            EthRpcError::OutOfTimeRange(data) => {
                rpc_err_with_data(OUT_OF_TIME_RANGE_CODE, msg, data)
            }
            EthRpcError::ThrottledOrBanned(data) => {
                rpc_err_with_data(THROTTLED_OR_BANNED_CODE, msg, data)
            }
            EthRpcError::StakeTooLow(data) => rpc_err_with_data(OPCODE_VIOLATION_CODE, msg, data),
            EthRpcError::UnsupportedAggregator(data) => {
                rpc_err_with_data(UNSUPORTED_AGGREGATOR_CODE, msg, data)
            }
            EthRpcError::ReplacementUnderpriced(data) => {
                rpc_err_with_data(INVALID_PARAMS_CODE, msg, data)
            }
            EthRpcError::OperationAlreadyKnown => rpc_err(INVALID_PARAMS_CODE, msg),
            EthRpcError::MaxOperationsReached(_, _) => rpc_err(STAKE_TOO_LOW_CODE, msg),
            EthRpcError::SignatureCheckFailed
            | EthRpcError::AccountSignatureCheckFailed
            | EthRpcError::PaymasterSignatureCheckFailed => {
                rpc_err(SIGNATURE_CHECK_FAILED_CODE, msg)
            }
            EthRpcError::PrecheckFailed(_) => rpc_err(CALL_EXECUTION_FAILED_CODE, msg),
            EthRpcError::ExecutionReverted(_) => rpc_err(EXECUTION_REVERTED, msg),
            EthRpcError::ExecutionRevertedWithBytes(data) => {
                rpc_err_with_data(EXECUTION_REVERTED, msg, data)
            }
            EthRpcError::ValidationRevert(data) => {
                rpc_err_with_data(ENTRYPOINT_VALIDATION_REJECTED_CODE, msg, data)
            }
            EthRpcError::OperationRejected(_) => rpc_err(INVALID_PARAMS_CODE, msg),
        }
    }
}

impl From<tonic::Status> for EthRpcError {
    fn from(status: tonic::Status) -> Self {
        Self::Internal(anyhow::anyhow!(
            "internal server error code: {} message: {}",
            status.code(),
            status.message()
        ))
    }
}

impl From<ProviderError> for EthRpcError {
    fn from(e: ProviderError) -> Self {
        Self::Internal(anyhow::anyhow!("provider error: {e:?}"))
    }
}

impl From<GasEstimationError> for EthRpcError {
    fn from(e: GasEstimationError) -> Self {
        match e {
            GasEstimationError::RevertInValidation(revert) => Self::ValidationRevert(revert.into()),
            GasEstimationError::RevertInCallWithMessage(message) => {
                Self::ExecutionReverted(message)
            }
            GasEstimationError::RevertInCallWithBytes(b) => {
                Self::ExecutionRevertedWithBytes(ExecutionRevertedWithBytesData { revert_data: b })
            }
            error @ GasEstimationError::GasUsedTooLarge => {
                Self::EntryPointValidationRejected(error.to_string())
            }
            error @ GasEstimationError::GasTotalTooLarge(_, _) => {
                Self::InvalidParams(error.to_string())
            }
            error @ GasEstimationError::GasFieldTooLarge(_, _) => {
                Self::InvalidParams(error.to_string())
            }
            GasEstimationError::Other(error) => Self::Internal(error),
        }
    }
}
