use ethers::types::{Address, Opcode, U256};
use jsonrpsee::{
    core::Error as RpcError,
    types::{
        error::{CallError, CALL_EXECUTION_FAILED_CODE, INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE},
        ErrorObject,
    },
};
use serde::Serialize;

use crate::common::{
    precheck::PrecheckError,
    simulation::SimulationError,
    types::{Entity, EntityType, Timestamp},
};

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

/// Error returned by the RPC server eth namespace
#[derive(Debug, thiserror::Error)]
pub enum EthRpcError {
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
    /// Opcode violation
    #[error("{0} uses banned opcode: {1:?}")]
    OpcodeViolation(EntityType, Opcode),
    /// Precompile violation, maps to Opcode Violation
    #[error("{0} uses banned precompile: {1:?}")]
    PrecompileViolation(EntityType, Address),
    /// Invalid storage access, maps to Opcode Violation
    #[error("{0} accesses inaccessible storage at address: {1:?} slot: {2:#032x}")]
    InvalidStorageAccess(EntityType, Address, U256),
    /// Operation is out of time range
    #[error("operation is out of time range")]
    OutOfTimeRange(OutOfTimeRangeData),
    /// Entity throttled or banned
    #[error("entity throttled or banned")]
    ThrottledOrBanned(Entity),
    /// Entity stake/unstake delay too low
    #[error("entity stake/unstake delay too low")]
    StakeTooLow(StakeTooLowData),
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
    PrecheckFailed(PrecheckError),
    #[error("validation simulation failed: {0}")]
    SimulationFailed(SimulationError),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
    #[error("{0}")]
    ExecutionReverted(String),
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
    entity: Entity,
    minimum_stake: U256,
    minimum_unstake_delay: U256,
}

impl StakeTooLowData {
    pub fn new(entity: Entity, minimum_stake: U256, minimum_unstake_delay: U256) -> Self {
        Self {
            entity,
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

impl From<EthRpcError> for RpcError {
    fn from(error: EthRpcError) -> Self {
        let msg = error.to_string();

        match error {
            EthRpcError::InvalidParams(_) => rpc_err(INVALID_PARAMS_CODE, msg),
            EthRpcError::EntryPointValidationRejected(_) => {
                rpc_err(ENTRYPOINT_VALIDATION_REJECTED_CODE, msg)
            }
            EthRpcError::PaymasterValidationRejected(data) => {
                rpc_err_with_data(PAYMASTER_VALIDATION_REJECTED_CODE, msg, data)
            }
            EthRpcError::OpcodeViolation(_, _)
            | EthRpcError::PrecompileViolation(_, _)
            | EthRpcError::InvalidStorageAccess(_, _, _) => rpc_err(OPCODE_VIOLATION_CODE, msg),
            EthRpcError::OutOfTimeRange(data) => {
                rpc_err_with_data(OUT_OF_TIME_RANGE_CODE, msg, data)
            }
            EthRpcError::ThrottledOrBanned(data) => {
                rpc_err_with_data(THROTTLED_OR_BANNED_CODE, msg, data)
            }
            EthRpcError::StakeTooLow(data) => rpc_err_with_data(STAKE_TOO_LOW_CODE, msg, data),
            EthRpcError::UnsupportedAggregator(data) => {
                rpc_err_with_data(UNSUPORTED_AGGREGATOR_CODE, msg, data)
            }
            EthRpcError::ReplacementUnderpriced(data) => {
                rpc_err_with_data(INVALID_PARAMS_CODE, msg, data)
            }
            EthRpcError::OperationAlreadyKnown => rpc_err(INVALID_PARAMS_CODE, msg),
            EthRpcError::SignatureCheckFailed => rpc_err(SIGNATURE_CHECK_FAILED_CODE, msg),
            EthRpcError::PrecheckFailed(_) => rpc_err(CALL_EXECUTION_FAILED_CODE, msg),
            EthRpcError::SimulationFailed(_) => rpc_err(CALL_EXECUTION_FAILED_CODE, msg),
            EthRpcError::Internal(_) => rpc_err(INTERNAL_ERROR_CODE, msg),
            EthRpcError::ExecutionReverted(_) => rpc_err(EXECUTION_REVERTED, msg),
        }
    }
}

fn rpc_err(code: i32, msg: impl Into<String>) -> RpcError {
    create_rpc_err(code, msg, None::<()>)
}

fn rpc_err_with_data<S: Serialize>(code: i32, msg: impl Into<String>, data: S) -> RpcError {
    create_rpc_err(code, msg, Some(data))
}

fn create_rpc_err<S: Serialize>(code: i32, msg: impl Into<String>, data: Option<S>) -> RpcError {
    RpcError::Call(CallError::Custom(ErrorObject::owned(
        code,
        msg.into(),
        data,
    )))
}
