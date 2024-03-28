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

use std::cmp;

use ethers::types::{spoof, U256};
use rundler_provider::{EntryPoint, L1GasProvider, Provider, SimulationProvider};
use rundler_types::{
    chain::ChainSpec,
    v0_7::{UserOperation, UserOperationOptionalGas},
    GasEstimate,
};

use super::{GasEstimationError, Settings};
use crate::{gas, FeeEstimator};

/// Gas estimator for entry point v0.7
#[derive(Debug)]
pub struct GasEstimator<P, E> {
    chain_spec: ChainSpec,
    entry_point: E,
    settings: Settings,
    fee_estimator: FeeEstimator<P>,
}

#[async_trait::async_trait]
impl<P, E> super::GasEstimator for GasEstimator<P, E>
where
    P: Provider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + L1GasProvider<UO = UserOperation>,
{
    type UserOperationOptionalGas = UserOperationOptionalGas;

    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
        _state_override: spoof::State,
    ) -> Result<GasEstimate, GasEstimationError> {
        // TODO(danc): Implement this for real

        // Estimate pre verification gas at the current fees
        // If the user provides fees, use them, otherwise use the current bundle fees
        let (bundle_fees, base_fee) = self.fee_estimator.required_bundle_fees(None).await?;
        let gas_price = if let (Some(max_fee), Some(prio_fee)) =
            (op.max_fee_per_gas, op.max_priority_fee_per_gas)
        {
            cmp::min(U256::from(max_fee), base_fee + prio_fee)
        } else {
            base_fee + bundle_fees.max_priority_fee_per_gas
        };
        let pre_verification_gas = self.estimate_pre_verification_gas(&op, gas_price).await?;

        Ok(GasEstimate {
            pre_verification_gas,
            call_gas_limit: 1_000_000.into(),
            verification_gas_limit: 1_000_000.into(),
            paymaster_verification_gas_limit: op.paymaster.map(|_| 1_000_000.into()),
            paymaster_post_op_gas_limit: op.paymaster.map(|_| 1_000_000.into()),
        })
    }
}

impl<P, E> GasEstimator<P, E>
where
    P: Provider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + L1GasProvider<UO = UserOperation>,
{
    /// Create a new gas estimator
    pub fn new(
        chain_spec: ChainSpec,
        entry_point: E,
        settings: Settings,
        fee_estimator: FeeEstimator<P>,
    ) -> Self {
        Self {
            chain_spec,
            entry_point,
            settings,
            fee_estimator,
        }
    }

    async fn estimate_pre_verification_gas(
        &self,
        op: &UserOperationOptionalGas,
        gas_price: U256,
    ) -> Result<U256, GasEstimationError> {
        Ok(gas::estimate_pre_verification_gas(
            &self.chain_spec,
            &self.entry_point,
            &op.max_fill(
                self.entry_point.address(),
                self.chain_spec.id,
                self.settings.max_call_gas.into(),
                self.settings.max_verification_gas.into(),
            ),
            &op.random_fill(
                self.entry_point.address(),
                self.chain_spec.id,
                self.settings.max_call_gas.into(),
                self.settings.max_verification_gas.into(),
            ),
            gas_price,
        )
        .await?
        // TODO(danc): figure out why this is needed
        + U256::from(5000))
    }
}
