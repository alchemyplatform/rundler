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

use ethers::types::{Address, U256};

use crate::{
    validation_results::ValidationRevert, Entity, EntityType, StorageSlot, Timestamp,
    ViolationOpCode,
};

/// Pool server error type
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// Mempool error occurred
    #[error(transparent)]
    MempoolError(MempoolError),
    /// Unexpected response from PoolServer
    #[error("Unexpected response from PoolServer")]
    UnexpectedResponse,
    /// Internal error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<MempoolError> for PoolError {
    fn from(error: MempoolError) -> Self {
        match error {
            MempoolError::Other(e) => Self::Other(e),
            _ => Self::MempoolError(error),
        }
    }
}

/// Mempool error type.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    /// Some other error occurred
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    /// Operation with the same hash already in pool
    #[error("Operation already known")]
    OperationAlreadyKnown,
    /// Operation with same sender/nonce already in pool
    /// and the replacement operation has lower gas price.
    #[error("Replacement operation underpriced. Existing priority fee: {0}. Existing fee: {1}")]
    ReplacementUnderpriced(U256, U256),
    /// Max operations reached for unstaked sender [UREP-010] or unstaked non-sender entity [UREP-020]
    #[error("Max operations ({0}) reached for entity {1}")]
    MaxOperationsReached(usize, Entity),
    /// Multiple roles violation
    /// Spec rule: STO-040
    #[error("A {} at {} in this UserOperation is used as a sender entity in another UserOperation currently in mempool.", .0.kind, .0.address)]
    MultipleRolesViolation(Entity),
    /// An associated storage slot that is accessed in the UserOperation is being used as a sender by another UserOperation in the mempool.
    /// Spec rule: STO-041
    #[error("An associated storage slot that is accessed in the UserOperation is being used as a sender by another UserOperation in the mempool")]
    AssociatedStorageIsAlternateSender,
    /// Sender address used as different entity in another UserOperation currently in the mempool.
    /// Spec rule: STO-040
    #[error("The sender address {0} is used as a different entity in another UserOperation currently in mempool")]
    SenderAddressUsedAsAlternateEntity(Address),
    /// An entity associated with the operation is throttled/banned.
    #[error("Entity {0} is throttled/banned")]
    EntityThrottled(Entity),
    /// Operation was discarded on inserting due to size limit
    #[error("Operation was discarded on inserting")]
    DiscardedOnInsert,
    /// Paymaster balance too low
    /// Spec rule: EREP-010
    #[error("Paymaster balance too low. Required balance: {0}. Current balance {1}")]
    PaymasterBalanceTooLow(U256, U256),
    /// Operation was rejected due to a precheck violation
    #[error("Operation violation during precheck {0}")]
    PrecheckViolation(PrecheckViolation),
    /// Operation was rejected due to a simulation violation
    #[error("Operation violation during simulation {0}")]
    SimulationViolation(SimulationViolation),
    /// Operation was rejected because it used an unsupported aggregator
    #[error("Unsupported aggregator {0}")]
    UnsupportedAggregator(Address),
    /// An unknown entry point was specified
    #[error("Unknown entry point {0}")]
    UnknownEntryPoint(Address),
    /// The operation drop attempt too soon after being added to the pool
    #[error("Operation drop attempt too soon after being added to the pool. Added at {0}, attempted to drop at {1}, must wait {2} blocks.")]
    OperationDropTooSoon(u64, u64, u64),
}

/// Precheck violation enumeration
///
/// All possible errors that can be returned from a precheck.
#[derive(Clone, Debug, parse_display::Display, Eq, PartialEq, Ord, PartialOrd)]
pub enum PrecheckViolation {
    /// The sender is not deployed, and no init code is provided.
    #[display("sender {0:?} is not a contract and initCode is empty")]
    SenderIsNotContractAndNoInitCode(Address),
    /// The sender is already deployed, and an init code is provided.
    #[display("sender {0:?} is an existing contract, but initCode is nonempty")]
    ExistingSenderWithInitCode(Address),
    /// An init code contains a factory address that is not deployed.
    #[display("initCode indicates factory with no code: {0:?}")]
    FactoryIsNotContract(Address),
    /// The total gas limit of the user operation is too high.
    /// See `gas::user_operation_execution_gas_limit` for calculation.
    #[display("total gas limit is {0} but must be at most {1}")]
    TotalGasLimitTooHigh(U256, U256),
    /// The verification gas limit of the user operation is too high.
    #[display("verificationGasLimit is {0} but must be at most {1}")]
    VerificationGasLimitTooHigh(U256, U256),
    /// The pre-verification gas of the user operation is too low.
    #[display("preVerificationGas is {0} but must be at least {1}")]
    PreVerificationGasTooLow(U256, U256),
    /// A paymaster is provided, but the address is not deployed.
    #[display("paymasterAndData indicates paymaster with no code: {0:?}")]
    PaymasterIsNotContract(Address),
    /// The paymaster deposit is too low to pay for the user operation's maximum cost.
    #[display("paymaster deposit is {0} but must be at least {1} to pay for this operation")]
    PaymasterDepositTooLow(U256, U256),
    /// The sender balance is too low to pay for the user operation's maximum cost.
    /// (when not using a paymaster)
    #[display("sender balance and deposit together is {0} but must be at least {1} to pay for this operation")]
    SenderFundsTooLow(U256, U256),
    /// The provided max priority fee per gas is too low based on the current network rate.
    #[display("maxPriorityFeePerGas is {0} but must be at least {1}")]
    MaxPriorityFeePerGasTooLow(U256, U256),
    /// The provided max fee per gas is too low based on the current network rate.
    #[display("maxFeePerGas is {0} but must be at least {1}")]
    MaxFeePerGasTooLow(U256, U256),
    /// The call gas limit is too low to account for any possible call.
    #[display("callGasLimit is {0} but must be at least {1}")]
    CallGasLimitTooLow(U256, U256),
}

/// All possible simulation violations
#[derive(Clone, Debug, parse_display::Display, Ord, Eq, PartialOrd, PartialEq)]
pub enum SimulationViolation {
    // Make sure to maintain the order here based on the importance
    // of the violation for converting to an JSON RPC error
    /// The signature is invalid for either the account or paymaster
    /// This is used in v0.6 where the error is not attributable
    #[display("invalid signature")]
    InvalidSignature,
    /// The signature is invalid for the account
    #[display("invalid account signature")]
    InvalidAccountSignature,
    /// The user operation has an invalid time range based on the `valid_until` and `valid_after` fields
    #[display(
        "User Operation expired or has an invalid time range. validUntil: {0}, validAfter: {1}"
    )]
    InvalidTimeRange(Timestamp, Timestamp),
    /// The signature is invalid for the paymaster
    #[display("invalid paymaster signature")]
    InvalidPaymasterSignature,
    /// The user operation used an opcode that is not allowed
    #[display("{0.kind} uses banned opcode: {2} in contract {1:?}")]
    UsedForbiddenOpcode(Entity, Address, ViolationOpCode),
    /// The user operation used a precompile that is not allowed
    #[display("{0.kind} uses banned precompile: {2:?} in contract {1:?}")]
    UsedForbiddenPrecompile(Entity, Address, Address),
    /// The user operation accessed a contract that has not been deployed
    #[display(
        "{0.kind} tried to access code at {1} during validation, but that address is not a contract"
    )]
    AccessedUndeployedContract(Entity, Address),
    /// The user operation factory entity called CREATE2 more than once during initialization
    #[display("factory may only call CREATE2 once during initialization")]
    FactoryCalledCreate2Twice(Address),
    /// The user operation accessed a storage slot that is not allowed
    #[display("{0.kind} accessed forbidden storage at address {1:?} during validation")]
    InvalidStorageAccess(Entity, StorageSlot),
    /// The user operation accessed a storage slot on the sender while being deployed
    /// and the accessing entity or the factory is not staked
    #[display("Sender storage at slot {1:?} accessed during deployment. Factory or accessing entity ({0:?}) must be staked")]
    AssociatedStorageDuringDeploy(Option<Entity>, StorageSlot),
    /// The user operation called an entry point method that is not allowed
    #[display("{0.kind} called entry point method other than depositTo")]
    CalledBannedEntryPointMethod(Entity),
    /// The user operation made a call that contained value to a contract other than the entrypoint
    /// during validation
    #[display("{0.kind} must not send ETH during validation (except from account to entry point)")]
    CallHadValue(Entity),
    /// The code hash of accessed contracts changed on the second simulation
    #[display("code accessed by validation has changed since the last time validation was run")]
    CodeHashChanged,
    /// The user operation contained an entity that accessed storage without being staked
    #[display("{0.needs_stake} needs to be staked: {0.accessing_entity} accessed storage at {0.accessed_address} slot {0.slot} (associated with {0.accessed_entity:?})")]
    NotStaked(Box<NeedsStakeInformation>),
    /// The user operation uses a paymaster that returns a context while being unstaked
    #[display("Unstaked paymaster must not return context")]
    UnstakedPaymasterContext,
    /// The user operation uses an aggregator entity and it is not staked
    #[display("An aggregator must be staked, regardless of storager usage")]
    UnstakedAggregator,
    /// Simulation reverted with an unintended reason, containing a message
    #[display("reverted while simulating {0} validation: {1}")]
    UnintendedRevertWithMessage(EntityType, String, Option<Address>),
    /// Simulation reverted with an unintended reason
    #[display("reverted while simulating {0} validation")]
    UnintendedRevert(EntityType, Option<Address>),
    /// Validation revert (only used for unsafe sim)
    #[display("validation revert: {0}")]
    ValidationRevert(ValidationRevert),
    /// Simulation did not revert, a revert is always expected
    #[display("simulateValidation did not revert. Make sure your EntryPoint is valid")]
    DidNotRevert,
    /// Simulation had the wrong number of phases
    #[display("simulateValidation should have 3 parts but had {0} instead. Make sure your EntryPoint is valid")]
    WrongNumberOfPhases(u32),
    /// The user operation ran out of gas during validation
    #[display("ran out of gas during {0.kind} validation")]
    OutOfGas(Entity),
    /// The user operation aggregator signature validation failed
    #[display("aggregator signature validation failed")]
    AggregatorValidationFailed,
    /// Verification gas limit doesn't have the required buffer on the measured gas
    #[display("verification gas limit doesn't have the required buffer on the measured gas, limit: {0}, needed: {1}")]
    VerificationGasLimitBufferTooLow(U256, U256),
    /// Unsupported contract type
    #[display("accessed unsupported contract type: {0:?} at {1:?}. Address must be whitelisted")]
    AccessedUnsupportedContractType(String, Address),
}

/// Information about a storage violation based on stake status
#[derive(Debug, PartialEq, Clone, PartialOrd, Eq, Ord)]
pub struct NeedsStakeInformation {
    /// Entity needing stake info
    pub needs_stake: Entity,
    /// The entity that accessed the storage requiring stake
    pub accessing_entity: EntityType,
    /// Type of accessed entity, if it is a known entity
    pub accessed_entity: Option<EntityType>,
    /// Address that was accessed while unstaked
    pub accessed_address: Address,
    /// The accessed slot number
    pub slot: U256,
    /// Minumum stake
    pub min_stake: U256,
    /// Minumum delay after an unstake event
    pub min_unstake_delay: U256,
}
