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

use std::{future::Future, pin::Pin};

use alloy_primitives::{Address, Bytes, B256, U256};
use async_trait::async_trait;
use rundler_provider::{EvmProvider, StateOverride, TransactionBuilder, TransactionRequest};
use rundler_types::{chain::ChainSpec, UserOperation};
use rundler_utils::authorization_utils;
use tracing::instrument;

use super::Settings;
use crate::GasEstimationError;

/// Estimates a verification gas limit for a user operation. Can be used to
/// estimate both verification gas and, in the v0.7 case, paymaster verification
/// gas.
#[async_trait]
pub trait VerificationGasEstimator: Send + Sync {
    /// The user operation type estimated by this estimator
    type UO: UserOperation;

    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.
    ///
    /// By passing different functions for the `get_op_with_limit` argument,
    /// the same estimator instance can be used to separately estimate the
    /// account and paymaster verification gas limits.
    async fn estimate_verification_gas(
        &self,
        op: &Self::UO,
        block_hash: B256,
        state_override: StateOverride,
    ) -> Result<u128, GasEstimationError>;
}

pub trait VerificationGasEstimatorSpecialization: Send + Sync {
    /// The user operation type estimated by this specialization
    type UO: UserOperation;

    fn add_proxy_to_overrides(&self, to_override: Address, state_override: &mut StateOverride);

    fn get_call(&self, op: Self::UO, args: &EstimateGasArgs) -> Bytes;
}

#[derive(Debug, Clone)]
pub struct EstimateGasArgs {
    pub block_hash: B256,
    pub min_gas: u128,
    pub max_gas: u128,
    pub allowed_error_pct: u128,
    pub is_continuation: bool,
    pub constant_fee: U256,
}

/// Implementation of a verification gas estimator
#[derive(Clone)]
pub struct VerificationGasEstimatorImpl<S, P> {
    chain_spec: ChainSpec,
    settings: Settings,
    specialization: S,
    provider: P,
}

#[async_trait]
impl<S, P> VerificationGasEstimator for VerificationGasEstimatorImpl<S, P>
where
    S: VerificationGasEstimatorSpecialization + Clone + 'static,
    P: EvmProvider + Clone + 'static,
{
    type UO = S::UO;

    #[instrument(skip_all)]
    async fn estimate_verification_gas(
        &self,
        op: &Self::UO,
        block_hash: B256,
        mut state_override: StateOverride,
    ) -> Result<u128, GasEstimationError> {
        if let Some(au) = &op.authorization_tuple() {
            authorization_utils::apply_7702_overrides(&mut state_override, op.sender(), au.address);
        }

        let helper_addr = Address::random();
        self.specialization
            .add_proxy_to_overrides(helper_addr, &mut state_override);

        let round_fn = |min_gas: u128, max_gas: u128, is_continuation: bool| {
            Box::pin(self.clone().run_binary_search_round(
                op.clone(),
                block_hash,
                helper_addr,
                state_override.clone(),
                min_gas,
                max_gas,
                is_continuation,
            ))
                as Pin<Box<dyn Future<Output = Result<Bytes, GasEstimationError>> + Send>>
        };

        let timer = std::time::Instant::now();
        let (estimate, num_rounds) = super::run_binary_search(
            round_fn,
            self.settings.max_verification_gas,
            self.settings.max_gas_estimation_rounds,
        )
        .await?;
        tracing::debug!(
            "verification gas estimation took {} ms with {} rounds",
            timer.elapsed().as_millis(),
            num_rounds
        );

        if op.paymaster().is_none() {
            Ok(estimate + self.chain_spec.deposit_transfer_overhead())
        } else {
            Ok(estimate)
        }
    }
}

impl<S, P> VerificationGasEstimatorImpl<S, P>
where
    S: VerificationGasEstimatorSpecialization,
    P: EvmProvider,
{
    /// Create a new instance
    pub fn new(chain_spec: ChainSpec, settings: Settings, provider: P, specialization: S) -> Self {
        Self {
            chain_spec,
            settings,
            provider,
            specialization,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_binary_search_round(
        self,
        op: S::UO,
        block_hash: B256,
        helper_addr: Address,
        state_overrides: StateOverride,
        min_gas: u128,
        max_gas: u128,
        is_continuation: bool,
    ) -> Result<Bytes, GasEstimationError> {
        let call = self.specialization.get_call(
            op,
            &EstimateGasArgs {
                block_hash,
                min_gas,
                max_gas,
                allowed_error_pct: self.settings.verification_gas_allowed_error_pct,
                is_continuation,
                constant_fee: U256::from(self.settings.verification_estimation_gas_fee),
            },
        );

        let call = TransactionRequest::default()
            .with_input(call)
            .with_gas_limit(self.settings.max_bundle_execution_gas.try_into().unwrap())
            .with_to(helper_addr);

        let ret = self
            .provider
            .call(call, Some(block_hash.into()), Some(state_overrides))
            .await;

        match ret {
            Ok(_) => Err(GasEstimationError::Other(anyhow::anyhow!(
                "expected revert in verification gas estimation"
            ))),
            Err(e) => {
                if let Some(e) = e.as_revert_data() {
                    Ok(e)
                } else {
                    Err(e.into())
                }
            }
        }
    }
}
