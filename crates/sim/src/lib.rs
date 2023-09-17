#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
//! Traits and implementations for interacting with ERC-4337 contracts and operations.
//!
//! Includes implementations for:
//!
//! - User operation prechecks
//! - User operation simulation and violation checking
//! - User operation gas and fee estimation
//! - Alternative mempool configurations and assignment
//!
//! ## Feature Flags
//!
//! - `test-utils`: Export mocks and utilities for testing.

mod estimation;
pub use estimation::{
    GasEstimate, GasEstimationError, GasEstimator, GasEstimatorImpl,
    Settings as EstimationSettings, UserOperationOptionalGas,
};

pub mod gas;
pub use gas::{FeeEstimator, PriorityFeeMode};

mod precheck;
#[cfg(feature = "test-utils")]
pub use precheck::MockPrechecker;
pub use precheck::{
    PrecheckError, PrecheckViolation, Prechecker, PrecheckerImpl, Settings as PrecheckSettings,
    MIN_CALL_GAS_LIMIT,
};

mod simulation;
#[cfg(feature = "test-utils")]
pub use simulation::MockSimulator;
pub use simulation::{
    MempoolConfig, Settings as SimulationSettings, SimulateValidationTracer,
    SimulateValidationTracerImpl, SimulationError, SimulationSuccess, SimulationViolation,
    Simulator, SimulatorImpl, ViolationOpCode,
};

mod types;
pub use types::ExpectedStorage;

mod utils;
