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

use std::collections::HashSet;

use anyhow::Error;
use ethers::types::{Address, H256, U256};
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_provider::AggregatorSimOut;
use rundler_types::{
    pool::{MempoolError, SimulationViolation},
    EntityInfos, UserOperation, ValidTimeRange,
};

mod context;
pub use context::ValidationContextProvider;

mod mempool;
pub use mempool::{MempoolConfig, MempoolConfigs};

mod simulator;
pub use simulator::{new_v0_6_simulator, new_v0_7_simulator, SimulatorImpl};

mod unsafe_sim;
pub use unsafe_sim::UnsafeSimulator;

/// Entry Point v0.6 Tracing
pub mod v0_6;
/// Entry Point v0.7 Tracing
pub mod v0_7;

use crate::{ExpectedStorage, ViolationError};

/// The result of a successful simulation
#[derive(Clone, Debug, Default)]
pub struct SimulationResult {
    /// The mempool IDs that support this operation
    pub mempools: Vec<H256>,
    /// Block hash this operation was simulated against
    pub block_hash: H256,
    /// Block number this operation was simulated against
    pub block_number: Option<u64>,
    /// Gas used in the pre-op phase of simulation measured
    /// by the entry point
    pub pre_op_gas: U256,
    /// The time range for which this operation is valid
    pub valid_time_range: ValidTimeRange,
    /// If using an aggregator, the result of the aggregation
    /// simulation
    pub aggregator: Option<AggregatorSimOut>,
    /// Code hash of all accessed contracts
    pub code_hash: H256,
    /// Whether the sender account is staked
    pub account_is_staked: bool,
    /// List of all addresses accessed during validation
    pub accessed_addresses: HashSet<Address>,
    /// List of addresses that have associated storage slots
    /// accessed within the simulation
    pub associated_addresses: HashSet<Address>,
    /// Expected storage values for all accessed slots during validation
    pub expected_storage: ExpectedStorage,
    /// Whether the operation requires a post-op
    pub requires_post_op: bool,
    /// All the entities used in this operation and their staking state
    pub entity_infos: EntityInfos,
}

impl SimulationResult {
    /// Get the aggregator address if one was used
    pub fn aggregator_address(&self) -> Option<Address> {
        self.aggregator.as_ref().map(|agg| agg.address)
    }
}

/// The result of a failed simulation. We return a list of the violations that ocurred during the failed simulation
/// and also information about all the entities used in the op to handle entity penalties
#[derive(Clone, Debug)]
pub struct SimulationError {
    /// A list of violations that occurred during simulation, or some other error that occurred not directly related to simulation rules
    pub violation_error: ViolationError<SimulationViolation>,
    /// The addresses and staking states of all the entities involved in an op. This value is None when simulation fails at a point where we are no
    pub entity_infos: Option<EntityInfos>,
}

impl From<Error> for SimulationError {
    fn from(error: Error) -> Self {
        SimulationError {
            violation_error: ViolationError::Other(error),
            entity_infos: None,
        }
    }
}

impl From<ViolationError<SimulationViolation>> for SimulationError {
    fn from(violation_error: ViolationError<SimulationViolation>) -> Self {
        SimulationError {
            violation_error,
            entity_infos: None,
        }
    }
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
        Self::SimulationViolation(std::mem::replace(
            violation,
            SimulationViolation::DidNotRevert,
        ))
    }
}

/// Simulator trait for running user operation simulations
#[cfg_attr(feature = "test-utils", automock(type UO = rundler_types::v0_6::UserOperation;))]
#[async_trait::async_trait]
pub trait Simulator: Send + Sync + 'static {
    /// The type of user operation that this simulator can handle
    type UO: UserOperation;

    /// Simulate a user operation, returning simulation information
    /// upon success, or simulation violations.
    async fn simulate_validation(
        &self,
        op: Self::UO,
        block_hash: Option<H256>,
        expected_code_hash: Option<H256>,
    ) -> Result<SimulationResult, SimulationError>;
}

/// Simulation Settings
#[derive(Debug, Clone)]
pub struct Settings {
    /// The minimum amount of time that a staked entity must have configured as
    /// their unstake delay on the entry point contract in order to be considered staked.
    pub min_unstake_delay: u32,
    /// The minimum amount of stake that a staked entity must have on the entry point
    /// contract in order to be considered staked.
    pub min_stake_value: u128,
    /// The maximum amount of gas that can be used during the simulation call
    pub max_simulate_handle_ops_gas: u64,
    /// The maximum amount of verification gas that can be used during the simulation call
    pub max_verification_gas: u64,
    /// The max duration of the custom javascript tracer. Must be in a format parseable by the
    /// ParseDuration function on an ethereum node. See Docs: https://pkg.go.dev/time#ParseDuration
    pub tracer_timeout: String,
}

impl Settings {
    /// Create new settings
    pub fn new(
        min_unstake_delay: u32,
        min_stake_value: u128,
        max_simulate_handle_ops_gas: u64,
        max_verification_gas: u64,
        tracer_timeout: String,
    ) -> Self {
        Self {
            min_unstake_delay,
            min_stake_value,
            max_simulate_handle_ops_gas,
            max_verification_gas,
            tracer_timeout,
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for Settings {
    fn default() -> Self {
        Self {
            // one day in seconds: defined in the ERC-4337 spec
            min_unstake_delay: 84600,
            // 10^18 wei = 1 eth
            min_stake_value: 1_000_000_000_000_000_000,
            // 550 million gas: currently the defaults for Alchemy eth_call
            max_simulate_handle_ops_gas: 550_000_000,
            max_verification_gas: 5_000_000,
            tracer_timeout: "10s".to_string(),
        }
    }
}
