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

use std::{cmp, sync::Arc};

use ethers::types::{spoof, Bytes, H256, U128, U256};
use rundler_provider::{EntryPoint, L1GasProvider, Provider, SimulationProvider};
use rundler_types::{
    chain::ChainSpec,
    contracts::v0_7::entry_point_simulations,
    v0_7::{UserOperation, UserOperationOptionalGas},
    GasEstimate,
};
use tokio::join;

use super::{estimate_verification_gas::GetOpWithLimitArgs, GasEstimationError, Settings};
use crate::{
    gas, CallGasEstimator, CallGasEstimatorImpl, CallGasEstimatorSpecialization, FeeEstimator,
    VerificationGasEstimator, VerificationGasEstimatorImpl,
};

/// Gas estimator for entry point v0.7
#[derive(Debug)]
pub struct GasEstimator<P, E, VGE, CGE> {
    chain_spec: ChainSpec,
    provider: Arc<P>,
    entry_point: E,
    settings: Settings,
    fee_estimator: FeeEstimator<P>,
    verification_gas_estimator: VGE,
    call_gas_estimator: CGE,
}

#[async_trait::async_trait]
impl<P, E, VGE, CGE> super::GasEstimator for GasEstimator<P, E, VGE, CGE>
where
    P: Provider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + L1GasProvider<UO = UserOperation>,
    VGE: VerificationGasEstimator<UO = UserOperation>,
    CGE: CallGasEstimator<UO = UserOperation>,
{
    type UserOperationOptionalGas = UserOperationOptionalGas;

    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
        state_override: spoof::State,
    ) -> Result<GasEstimate, GasEstimationError> {
        let Self {
            provider, settings, ..
        } = self;

        let (block_hash, _) = provider
            .get_latest_block_hash_and_number()
            .await
            .map_err(anyhow::Error::from)?;

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

        let op = op
            .into_user_operation_builder(
                self.entry_point.address(),
                self.chain_spec.id,
                settings.max_call_gas.into(),
                settings.max_verification_gas.into(),
                settings.max_paymaster_verification_gas.into(),
                settings.max_paymaster_post_op_gas.into(),
            )
            .pre_verification_gas(pre_verification_gas)
            .build();

        let verification_gas_future =
            self.estimate_verification_gas(&op, block_hash, &state_override);
        let paymaster_verification_gas_future =
            self.estimate_paymaster_verification_gas(&op, block_hash, &state_override);
        let call_gas_future = self.call_gas_estimator.estimate_call_gas(
            op.clone(),
            block_hash,
            state_override.clone(),
        );

        // Not try_join! because then the output is nondeterministic if multiple
        // calls fail.
        let timer = std::time::Instant::now();
        let (verification_gas_limit, paymaster_verification_gas_limit, call_gas_limit) = join!(
            verification_gas_future,
            paymaster_verification_gas_future,
            call_gas_future
        );
        tracing::debug!("gas estimation took {}ms", timer.elapsed().as_millis());

        let verification_gas_limit = verification_gas_limit?.into();
        let paymaster_verification_gas_limit = paymaster_verification_gas_limit?.into();
        let call_gas_limit = call_gas_limit?.into();

        Ok(GasEstimate {
            pre_verification_gas,
            call_gas_limit,
            verification_gas_limit,
            paymaster_verification_gas_limit: op
                .paymaster
                .map(|_| paymaster_verification_gas_limit),
            paymaster_post_op_gas_limit: op.paymaster.map(|_| 1_000_000.into()),
        })
    }
}

impl<P, E>
    GasEstimator<
        P,
        E,
        VerificationGasEstimatorImpl<P, E>,
        CallGasEstimatorImpl<E, CallGasEstimatorSpecializationV07>,
    >
where
    P: Provider,
    E: EntryPoint
        + SimulationProvider<UO = UserOperation>
        + L1GasProvider<UO = UserOperation>
        + Clone,
{
    /// Create a new gas estimator
    pub fn new(
        chain_spec: ChainSpec,
        provider: Arc<P>,
        entry_point: E,
        settings: Settings,
        fee_estimator: FeeEstimator<P>,
    ) -> Self {
        let verification_gas_estimator = VerificationGasEstimatorImpl::new(
            chain_spec.clone(),
            Arc::clone(&provider),
            entry_point.clone(),
            settings,
        );
        let call_gas_estimator = CallGasEstimatorImpl::new(
            entry_point.clone(),
            settings,
            CallGasEstimatorSpecializationV07,
        );
        Self {
            chain_spec,
            provider,
            entry_point,
            settings,
            fee_estimator,
            verification_gas_estimator,
            call_gas_estimator,
        }
    }
}

impl<P, E, VGE, CGE> GasEstimator<P, E, VGE, CGE>
where
    P: Provider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + L1GasProvider<UO = UserOperation>,
    VGE: VerificationGasEstimator<UO = UserOperation>,
    CGE: CallGasEstimator<UO = UserOperation>,
{
    async fn estimate_verification_gas(
        &self,
        op: &UserOperation,
        block_hash: H256,
        state_override: &spoof::State,
    ) -> Result<U128, GasEstimationError> {
        let max_paymaster_gas = self.settings.max_paymaster_verification_gas;

        let get_op_with_limit = |op: UserOperation, args: GetOpWithLimitArgs| {
            let GetOpWithLimitArgs { gas, fee } = args;
            let paymaster_verification_gas_limit = if op.paymaster.is_some() {
                max_paymaster_gas.into()
            } else {
                U128::zero()
            };
            op.into_builder()
                .verification_gas_limit(gas)
                .max_fee_per_gas(fee)
                .max_priority_fee_per_gas(fee)
                .paymaster_verification_gas_limit(paymaster_verification_gas_limit)
                .paymaster_post_op_gas_limit(U128::zero())
                .call_gas_limit(U128::zero())
                .build()
        };

        self.verification_gas_estimator
            .estimate_verification_gas(
                op,
                block_hash,
                state_override,
                self.settings.max_verification_gas.into(),
                get_op_with_limit,
            )
            .await
    }

    async fn estimate_paymaster_verification_gas(
        &self,
        op: &UserOperation,
        block_hash: H256,
        state_override: &spoof::State,
    ) -> Result<U128, GasEstimationError> {
        if op.paymaster.is_none() {
            return Ok(U128::zero());
        }

        let get_op_with_limit = |op: UserOperation, args: GetOpWithLimitArgs| {
            let GetOpWithLimitArgs { gas, fee } = args;
            op.into_builder()
                .verification_gas_limit(self.settings.max_verification_gas.into())
                .max_fee_per_gas(fee)
                .max_priority_fee_per_gas(fee)
                .paymaster_verification_gas_limit(gas)
                .paymaster_post_op_gas_limit(U128::zero())
                .call_gas_limit(U128::zero())
                .build()
        };

        self.verification_gas_estimator
            .estimate_verification_gas(
                op,
                block_hash,
                state_override,
                self.settings.max_paymaster_verification_gas.into(),
                get_op_with_limit,
            )
            .await
    }

    async fn estimate_pre_verification_gas(
        &self,
        op: &UserOperationOptionalGas,
        gas_price: U256,
    ) -> Result<U256, GasEstimationError> {
        Ok(gas::estimate_pre_verification_gas(
            &self.chain_spec,
            &self.entry_point,
            &op.max_fill(self.entry_point.address(), self.chain_spec.id),
            &op.random_fill(self.entry_point.address(), self.chain_spec.id),
            gas_price,
        )
        .await?)
    }
}

/// Implementation of functions that specialize the call gas estimator to the
/// v0.7 entry point.
#[derive(Debug)]
pub struct CallGasEstimatorSpecializationV07;

impl CallGasEstimatorSpecialization for CallGasEstimatorSpecializationV07 {
    type UO = UserOperation;

    fn get_op_with_verification_gas_but_no_call_gas(
        &self,
        op: Self::UO,
        settings: Settings,
    ) -> Self::UO {
        op.into_builder()
            .verification_gas_limit(settings.max_verification_gas.into())
            .paymaster_verification_gas_limit(settings.max_verification_gas.into())
            .paymaster_post_op_gas_limit(settings.max_paymaster_post_op_gas.into())
            .call_gas_limit(U128::zero())
            .max_fee_per_gas(U128::zero())
            .build()
    }

    fn entry_point_simulations_code(&self) -> Bytes {
        entry_point_simulations::ENTRYPOINTSIMULATIONS_DEPLOYED_BYTECODE.clone()
    }
}
