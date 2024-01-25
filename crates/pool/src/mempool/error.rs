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

use std::mem;

use ethers::{abi::Address, types::U256};
use rundler_sim::{
    PrecheckError, PrecheckViolation, SimulationError, SimulationViolation, ViolationError,
};
use rundler_types::Entity;

/// Mempool result type.
pub(crate) type MempoolResult<T> = std::result::Result<T, MempoolError>;

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
    MaxOperationsReached(usize, Address),
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
}

impl From<SimulationError> for MempoolError {
    fn from(mut error: SimulationError) -> Self {
        let SimulationError {
            violation_error, ..
        } = &mut error;
        let ViolationError::Violations(violations) = violation_error else {
            return Self::Other((*violation_error).clone().into());
        };

        let Some(violation) = violations.iter_mut().min() else {
            return Self::Other((*violation_error).clone().into());
        };

        // extract violation and replace with dummy
        Self::SimulationViolation(mem::replace(violation, SimulationViolation::DidNotRevert))
    }
}

impl From<PrecheckError> for MempoolError {
    fn from(mut error: PrecheckError) -> Self {
        let PrecheckError::Violations(violations) = &mut error else {
            return Self::Other(error.into());
        };

        let Some(violation) = violations.iter_mut().min() else {
            return Self::Other(error.into());
        };

        // extract violation and replace with dummy
        Self::PrecheckViolation(mem::replace(
            violation,
            PrecheckViolation::InitCodeTooShort(0),
        ))
    }
}
