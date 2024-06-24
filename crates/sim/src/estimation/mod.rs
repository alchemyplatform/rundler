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

use ethers::types::{Bytes, U128};
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_types::{GasEstimate, ValidationRevert};

use crate::precheck::MIN_CALL_GAS_LIMIT;

mod estimate_verification_gas;
pub use estimate_verification_gas::{VerificationGasEstimator, VerificationGasEstimatorImpl};
mod estimate_call_gas;
pub use estimate_call_gas::{
    CallGasEstimator, CallGasEstimatorImpl, CallGasEstimatorSpecialization,
};

/// Gas estimation module for Entry Point v0.6
mod v0_6;
pub use v0_6::GasEstimator as GasEstimatorV0_6;
mod v0_7;
pub use v0_7::GasEstimator as GasEstimatorV0_7;

/// Percentage by which to increase the verification gas limit after binary search
const VERIFICATION_GAS_BUFFER_PERCENT: u64 = 10;
/// Absolute value by which to increase the call gas limit after binary search
const CALL_GAS_BUFFER_VALUE: U128 = U128([3000, 0]);

/// Error type for gas estimation
#[derive(Debug, thiserror::Error)]
pub enum GasEstimationError {
    /// Validation reverted
    #[error("{0}")]
    RevertInValidation(ValidationRevert),
    /// Call reverted with a string message
    #[error("user operation's call reverted: {0}")]
    RevertInCallWithMessage(String),
    /// Call reverted with bytes
    #[error("user operation's call reverted: {0:#x}")]
    RevertInCallWithBytes(Bytes),
    /// Call used too much gas
    #[error("gas_used cannot be larger than a u64 integer")]
    GasUsedTooLarge,
    /// Supplied gas was too large
    #[error("{0} cannot be larger than {1}")]
    GasFieldTooLarge(&'static str, u64),
    /// The total amount of gas used by the UO is greater than allowed
    #[error("total gas used by the user operation {0} is greater than the allowed limit: {1}")]
    GasTotalTooLarge(u64, u64),
    /// Other error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Gas estimator trait
#[cfg_attr(feature = "test-utils", automock(type UserOperationOptionalGas = rundler_types::v0_6::UserOperationOptionalGas;))]
#[async_trait::async_trait]
pub trait GasEstimator: Send + Sync + 'static {
    /// The user operation type estimated by this gas estimator
    type UserOperationOptionalGas;

    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.
    async fn estimate_op_gas(
        &self,
        op: Self::UserOperationOptionalGas,
        state_override: ethers::types::spoof::State,
    ) -> Result<GasEstimate, GasEstimationError>;
}

/// Settings for gas estimation
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// The maximum amount of gas that can be used for the verification step of a user operation
    pub max_verification_gas: u64,
    /// The maximum amount of gas that can be used for the call step of a user operation
    pub max_call_gas: u64,
    /// The maximum amount of gas that can be used for the paymaster verification step of a user operation
    pub max_paymaster_verification_gas: u64,
    /// The maximum amount of gas that can be used for the paymaster post op step of a user operation
    pub max_paymaster_post_op_gas: u64,
    /// The maximum amount of total execution gas to check after estimation
    pub max_total_execution_gas: u64,
    /// The maximum amount of gas that can be used in a call to `simulateHandleOps`
    pub max_simulate_handle_ops_gas: u64,
    /// The gas fee to use during verification gas estimation, required to be held by the fee-payer
    /// during estimation. If using a paymaster, the fee-payer must have 3x this value.
    /// As the gas limit is varied during estimation, the fee is held constant by varying the
    /// gas price.
    /// Clients can use state overrides to set the balance of the fee-payer to at least this value.
    pub verification_estimation_gas_fee: u64,
}

impl Settings {
    /// Check if the settings are valid
    pub fn validate(&self) -> Option<String> {
        if U128::from(self.max_call_gas)
            .cmp(&MIN_CALL_GAS_LIMIT)
            .is_lt()
        {
            return Some("max_call_gas field cannot be lower than MIN_CALL_GAS_LIMIT".to_string());
        }
        None
    }
}
