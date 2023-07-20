use std::mem;

use ethers::{abi::Address, types::U256};

use crate::common::{
    precheck::{PrecheckError, PrecheckViolation},
    simulation::{SimulationError, SimulationViolation},
    types::Entity,
};

/// Mempool result type.
pub type MempoolResult<T> = std::result::Result<T, MempoolError>;

/// Mempool error type.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    /// Some other error occurred
    #[error(transparent)]
    Other(#[from] anyhow::Error),
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
    #[error("Operation was discarded on inserting")]
    DiscardedOnInsert,
    #[error("Operation violation during precheck {0}")]
    PrecheckViolation(PrecheckViolation),
    #[error("Operation violation during simulation {0}")]
    SimulationViolation(SimulationViolation),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Unsupported aggregator {0}")]
    UnsupportedAggregator(Address),
}

impl From<SimulationError> for MempoolError {
    fn from(mut error: SimulationError) -> Self {
        let SimulationError::Violations(violations) = &mut error else {
            return Self::Other(error.into());
        };

        let Some(violation) = violations.iter_mut().min() else {
            return Self::Other(error.into());
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
