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

use ethers::types::{Address, Bytes, Opcode, U256};
use jsonrpsee::types::{
    error::{CALL_EXECUTION_FAILED_CODE, INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE},
    ErrorObjectOwned,
};
use rundler_pool::{MempoolError, PoolServerError};
use rundler_provider::ProviderError;
use rundler_sim::{GasEstimationError, PrecheckViolation, SimulationViolation};
use rundler_types::{Entity, EntityType, Timestamp};
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
    /// Invalid storage access, maps to Opcode Violation
    #[error("{0} accesses inaccessible storage at address: {1:?} slot: {2:#032x}")]
    InvalidStorageAccess(EntityType, Address, U256),
    /// Operation is out of time range
    #[error("operation is out of time range")]
    OutOfTimeRange(OutOfTimeRangeData),
    /// Max operations reached for this sender
    #[error("Max operations ({0}) reached for sender {1:#032x} due to being unstaked")]
    MaxOperationsReached(usize, Address),
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
    #[error("precheck failed: {0}")]
    PrecheckFailed(PrecheckViolation),
    #[error("validation simulation failed: {0}")]
    SimulationFailed(SimulationViolation),
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

impl From<PoolServerError> for EthRpcError {
    fn from(value: PoolServerError) -> Self {
        match value {
            PoolServerError::MempoolError(e) => e.into(),
            PoolServerError::UnexpectedResponse => {
                EthRpcError::Internal(anyhow::anyhow!("unexpected response from pool server"))
            }
            PoolServerError::Other(e) => EthRpcError::Internal(e),
        }
    }
}

impl From<MempoolError> for EthRpcError {
    fn from(value: MempoolError) -> Self {
        match value {
            MempoolError::Other(e) => EthRpcError::Internal(e),
            MempoolError::OperationAlreadyKnown => EthRpcError::OperationAlreadyKnown,
            MempoolError::ReplacementUnderpriced(priority_fee, fee) => {
                EthRpcError::ReplacementUnderpriced(ReplacementUnderpricedData {
                    current_max_priority_fee: priority_fee,
                    current_max_fee: fee,
                })
            }
            MempoolError::MaxOperationsReached(count, address) => {
                EthRpcError::MaxOperationsReached(count, address)
            }
            MempoolError::EntityThrottled(entity) => EthRpcError::ThrottledOrBanned(entity),
            MempoolError::MultipleRolesViolation(entity) => {
                EthRpcError::MultipleRolesViolation(entity)
            }
            MempoolError::PaymasterBalanceTooLow(current_balance, required_balance) => {
                EthRpcError::PaymasterBalanceTooLow(current_balance, required_balance)
            }
            MempoolError::AssociatedStorageIsAlternateSender => {
                EthRpcError::AssociatedStorageIsAlternateSender
            }
            MempoolError::SenderAddressUsedAsAlternateEntity(address) => {
                EthRpcError::SenderAddressUsedAsAlternateEntity(address)
            }
            MempoolError::DiscardedOnInsert => {
                EthRpcError::OperationRejected("discarded on insert".to_owned())
            }
            MempoolError::PrecheckViolation(violation) => violation.into(),
            MempoolError::SimulationViolation(violation) => violation.into(),
            MempoolError::UnsupportedAggregator(a) => {
                EthRpcError::UnsupportedAggregator(UnsupportedAggregatorData { aggregator: a })
            }
            MempoolError::UnknownEntryPoint(a) => {
                EthRpcError::EntryPointValidationRejected(format!("unknown entry point: {}", a))
            }
            MempoolError::OperationDropTooSoon(_, _, _) => {
                EthRpcError::InvalidParams(value.to_string())
            }
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
            | SimulationViolation::CalledBannedEntryPointMethod(_)
            | SimulationViolation::CallHadValue(_) => Self::OpcodeViolationMap(value),
            SimulationViolation::FactoryCalledCreate2Twice(_) => {
                Self::OpcodeViolation(EntityType::Factory, Opcode::CREATE2)
            }
            SimulationViolation::UnstakedPaymasterContext => Self::UnstakedPaymasterContext,
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
            EthRpcError::OpcodeViolation(_, _)
            | EthRpcError::OpcodeViolationMap(_)
            | EthRpcError::OutOfGas(_)
            | EthRpcError::UnstakedAggregator
            | EthRpcError::MultipleRolesViolation(_)
            | EthRpcError::UnstakedPaymasterContext
            | EthRpcError::SenderAddressUsedAsAlternateEntity(_)
            | EthRpcError::PaymasterBalanceTooLow(_, _)
            | EthRpcError::AssociatedStorageIsAlternateSender
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
            EthRpcError::SignatureCheckFailed => rpc_err(SIGNATURE_CHECK_FAILED_CODE, msg),
            EthRpcError::PrecheckFailed(_) => rpc_err(CALL_EXECUTION_FAILED_CODE, msg),
            EthRpcError::ExecutionReverted(_) => rpc_err(EXECUTION_REVERTED, msg),
            EthRpcError::ExecutionRevertedWithBytes(data) => {
                rpc_err_with_data(EXECUTION_REVERTED, msg, data)
            }
            EthRpcError::OperationRejected(_) => rpc_err(INVALID_PARAMS_CODE, msg),
        }
    }
}

impl From<tonic::Status> for EthRpcError {
    fn from(status: tonic::Status) -> Self {
        EthRpcError::Internal(anyhow::anyhow!(
            "internal server error code: {} message: {}",
            status.code(),
            status.message()
        ))
    }
}

impl From<ProviderError> for EthRpcError {
    fn from(e: ProviderError) -> Self {
        EthRpcError::Internal(anyhow::anyhow!("provider error: {e:?}"))
    }
}

impl From<GasEstimationError> for EthRpcError {
    fn from(e: GasEstimationError) -> Self {
        match e {
            GasEstimationError::RevertInValidation(message) => {
                EthRpcError::EntryPointValidationRejected(message)
            }
            GasEstimationError::RevertInCallWithMessage(message) => {
                EthRpcError::ExecutionReverted(message)
            }
            GasEstimationError::RevertInCallWithBytes(b) => {
                EthRpcError::ExecutionRevertedWithBytes(ExecutionRevertedWithBytesData {
                    revert_data: b,
                })
            }
            GasEstimationError::Other(error) => EthRpcError::Internal(error),
        }
    }
}
