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

use ethers::types::spoof;
use rundler_types::{v0_7::UserOperationOptionalGas, GasEstimate};

use super::GasEstimationError;

/// Gas estimator for entry point v0.7
#[derive(Debug)]
pub struct GasEstimator {}

#[async_trait::async_trait]
impl super::GasEstimator for GasEstimator {
    type UserOperationOptionalGas = UserOperationOptionalGas;

    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.
    async fn estimate_op_gas(
        &self,
        _op: UserOperationOptionalGas,
        _state_override: spoof::State,
    ) -> Result<GasEstimate, GasEstimationError> {
        unimplemented!()
    }
}
