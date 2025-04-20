use std::{future::Future, marker::PhantomData};

use alloy_primitives::{Bytes, B256, U256};
use alloy_sol_types::{Revert, SolError, SolInterface};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use rundler_contracts::v0_7::VerificationGasEstimationHelper::{
    EstimateGasResult, VerificationGasEstimationHelperErrors,
};
use rundler_provider::StateOverride;
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
    async fn estimate_verification_gas<F, Fut>(
        &self,
        op: &Self::UO,
        block_hash: B256,
        state_override: StateOverride,
        call_contract: F,
    ) -> Result<u128, GasEstimationError>
    where
        F: Send + Sync + Fn(Self::UO, EstimateGasArgs) -> Fut,
        Fut: Send + Future<Output = Result<Result<EstimateGasResult, Bytes>, GasEstimationError>>;
}

#[derive(Debug, Clone)]
pub struct EstimateGasArgs {
    pub block_hash: B256,
    pub state_overrides: StateOverride,
    pub min_gas: u128,
    pub max_gas: u128,
    pub rounding: u128,
    pub is_continuation: bool,
    pub constant_fee: U256,
}

/// Implementation of a verification gas estimator
pub struct VerificationGasEstimatorImpl<UO> {
    chain_spec: ChainSpec,
    settings: Settings,
    _phantom: PhantomData<UO>,
}

#[async_trait]
impl<UO> VerificationGasEstimator for VerificationGasEstimatorImpl<UO>
where
    UO: UserOperation,
{
    type UO = UO;

    #[instrument(skip_all)]
    async fn estimate_verification_gas<F, Fut>(
        &self,
        op: &UO,
        block_hash: B256,
        state_override: StateOverride,
        call_contract: F,
    ) -> Result<u128, GasEstimationError>
    where
        F: Send + Sync + Fn(UO, EstimateGasArgs) -> Fut,
        Fut: Send + Future<Output = Result<Result<EstimateGasResult, Bytes>, GasEstimationError>>,
    {
        let mut local_state_override = state_override.clone();
        if let Some(au) = &op.authorization_tuple() {
            authorization_utils::apply_7702_overrides(
                &mut local_state_override,
                op.sender(),
                au.address,
            );
        }

        let mut min_gas = 0;
        let mut max_gas = self.settings.max_verification_gas;
        let mut is_continuation = false;
        let mut num_rounds = 0_u32;

        loop {
            // make a call to the smart contract
            let call_contract_result = call_contract(
                op.clone(),
                EstimateGasArgs {
                    block_hash,
                    state_overrides: local_state_override.clone(),
                    min_gas,
                    max_gas,
                    rounding: 4096,
                    is_continuation,
                    constant_fee: U256::from(self.settings.verification_estimation_gas_fee),
                },
            )
            .await?;

            match call_contract_result {
                Ok(result) => {
                    tracing::info!("verification gas estimation result: {:?}", result);

                    let gas_estimate = result
                        .gasEstimate
                        .try_into()
                        .context("gasEstimate return overflow")?;
                    let ret_num_rounds: u32 = result
                        .numRounds
                        .try_into()
                        .context("num rounds return overflow")?;

                    tracing::info!(
                        "gas estimation succeeded after {} rounds",
                        num_rounds + ret_num_rounds
                    );

                    if op.paymaster().is_none() {
                        return Ok(gas_estimate + self.chain_spec.deposit_transfer_overhead());
                    } else {
                        return Ok(gas_estimate);
                    }
                }
                Err(revert_data) => {
                    let error_result =
                        VerificationGasEstimationHelperErrors::abi_decode(&revert_data, false)
                            .context("should decode revert data")?;

                    match error_result {
                        VerificationGasEstimationHelperErrors::EstimateGasContinuation(
                            continuation,
                        ) => {
                            tracing::info!(
                                "verification gas estimation continuation: {:?}",
                                continuation
                            );

                            let ret_min_gas = continuation
                                .minGas
                                .try_into()
                                .context("min gas return overflow")?;
                            let ret_max_gas = continuation
                                .maxGas
                                .try_into()
                                .context("max gas return overflow")?;
                            let ret_num_rounds: u32 = continuation
                                .numRounds
                                .try_into()
                                .context("num rounds return overflow")?;

                            if is_continuation && ret_min_gas <= min_gas && ret_max_gas >= max_gas {
                                // This should never happen, but if it does, bail so we
                                // don't end up in an infinite loop!
                                Err(anyhow!(
                                        "estimateVerificationGas should make progress each time it is called"
                                    ))?;
                            }
                            is_continuation = true;
                            min_gas = min_gas.max(ret_min_gas);
                            max_gas = max_gas.min(ret_max_gas);
                            num_rounds += ret_num_rounds;
                        }
                        VerificationGasEstimationHelperErrors::EstimateGasRevertAtMax(revert) => {
                            let error =
                                if let Ok(revert) = Revert::abi_decode(&revert.revertData, false) {
                                    GasEstimationError::RevertInCallWithMessage(revert.reason)
                                } else {
                                    GasEstimationError::RevertInCallWithBytes(revert.revertData)
                                };
                            tracing::info!(
                                "verification gas estimation revert at max: {:?}",
                                error
                            );
                            return Err(error);
                        }
                    }
                }
            }
        }
    }
}

impl<UO> VerificationGasEstimatorImpl<UO>
where
    UO: UserOperation,
{
    /// Create a new instance
    pub fn new(chain_spec: ChainSpec, settings: Settings) -> Self {
        Self {
            chain_spec,
            settings,
            _phantom: PhantomData,
        }
    }
}
