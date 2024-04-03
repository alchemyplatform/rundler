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

/// Gas estimation
mod estimation;
#[cfg(feature = "test-utils")]
pub use estimation::MockGasEstimator;
pub use estimation::{
    CallGasEstimator, CallGasEstimatorImpl, CallGasEstimatorSpecialization, GasEstimationError,
    GasEstimator, GasEstimatorV0_6, GasEstimatorV0_7, Settings as EstimationSettings,
    VerificationGasEstimator, VerificationGasEstimatorImpl,
};

pub mod gas;
pub use gas::{FeeEstimator, PriorityFeeMode};

mod precheck;
#[cfg(feature = "test-utils")]
pub use precheck::MockPrechecker;
pub use precheck::{
    PrecheckError, Prechecker, PrecheckerImpl, Settings as PrecheckSettings, MIN_CALL_GAS_LIMIT,
};

/// Simulation and violation checking
pub mod simulation;
#[cfg(feature = "test-utils")]
pub use simulation::MockSimulator;
pub use simulation::{
    MempoolConfig, MempoolConfigs, Settings as SimulationSettings, SimulationError,
    SimulationResult, Simulator,
};

mod types;
pub use types::{ExpectedStorage, ViolationError};

mod utils;
