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
    /// Max operations reached for this sender
    #[error("Max operations ({0}) reached for sender {1}")]
    MaxOperationsReached(usize, Address),
    /// An entity associated with the operation is throttled/banned.
    #[error("Entity {0} is throttled/banned")]
    EntityThrottled(Entity),
    /// Operation was discarded on inserting due to size limit
    #[error("Operation was discarded on inserting")]
    DiscardedOnInsert,
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
        let (violation_error, _) = &mut error;
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
