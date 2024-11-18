use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use rundler_provider::{EntryPoint, EvmProvider, SimulationProvider, StateOverride};
use rundler_types::{chain::ChainSpec, UserOperation};

use super::Settings;
use crate::GasEstimationError;

/// Gas estimation will stop when the binary search bounds are within
/// `GAS_ESTIMATION_ERROR_MARGIN` of each other.
const GAS_ESTIMATION_ERROR_MARGIN: f64 = 0.1;
/// Error codes returned by the entry point when validation runs out of gas.
/// These appear as the start of the "reason" string in the revert data.
const OUT_OF_GAS_ERROR_CODES: &[&str] = &[
    "AA13", "AA23", "AA26", "AA33", "AA36", "AA40", "AA41", "AA51",
];

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
    async fn estimate_verification_gas<
        F: Send + Sync + Fn(Self::UO, GetOpWithLimitArgs) -> Self::UO,
    >(
        &self,
        op: &Self::UO,
        block_hash: B256,
        state_override: StateOverride,
        max_guess: u128,
        get_op_with_limit: F,
    ) -> Result<u128, GasEstimationError>;
}

#[derive(Debug, Clone, Copy)]
pub struct GetOpWithLimitArgs {
    pub gas: u128,
    pub fee: u128,
}

/// Implementation of a verification gas estimator
pub struct VerificationGasEstimatorImpl<P, E> {
    chain_spec: ChainSpec,
    provider: P,
    entry_point: E,
    settings: Settings,
}

#[async_trait]
impl<UO, P, E> VerificationGasEstimator for VerificationGasEstimatorImpl<P, E>
where
    UO: UserOperation,
    P: EvmProvider,
    E: EntryPoint + SimulationProvider<UO = UO>,
{
    type UO = UO;

    async fn estimate_verification_gas<F: Send + Sync + Fn(UO, GetOpWithLimitArgs) -> UO>(
        &self,
        op: &UO,
        block_hash: B256,
        state_override: StateOverride,
        max_guess: u128,
        get_op_with_limit: F,
    ) -> Result<u128, GasEstimationError> {
        let timer = std::time::Instant::now();
        let paymaster_gas_fee = self.settings.verification_estimation_gas_fee;

        // TODO(andy): apply the authorization fee to pvg.
        let _authorization_list_gas = match op.authorization_tuple() {
            Some(_) => alloy_eips::eip7702::constants::PER_AUTH_BASE_COST,
            None => 0,
        };

        // Fee logic for gas estimation:
        //
        // If there is no paymaster, verification estimation is always performed
        // with zero fees. The cost of the native transfer is added to the verification gas
        // at the end of estimation.
        //
        // If using a paymaster, the total cost is kept constant, and the fee is adjusted
        // based on the gas used in the simulation. The total cost is set by a configuration
        // setting.
        let get_op = |gas: u128| -> UO {
            let fee = if op.paymaster().is_none() {
                0
            } else {
                paymaster_gas_fee
                    .checked_div(gas + op.pre_verification_gas())
                    .unwrap_or(u128::MAX)
            };
            get_op_with_limit(op.clone(), GetOpWithLimitArgs { gas, fee })
        };

        // Make one attempt at max gas, to see if success is possible.
        // Capture the gas usage of this attempt and use as the initial guess in the binary search
        let initial_op = get_op(max_guess);
        let call = self
            .entry_point
            .get_simulate_handle_op_call(initial_op, state_override.clone());
        let gas_used = self
            .provider
            .get_gas_used(call)
            .await
            .context("failed to run initial guess")?;

        if gas_used.success {
            if self.entry_point.simulation_should_revert() {
                Err(anyhow!(
                    "simulateHandleOp succeeded but should always revert. Make sure the entry point contract is deployed and the address is correct"
                ))?;
            }
        } else if let Some(revert) = E::decode_simulate_handle_ops_revert(&gas_used.result)?.err() {
            return Err(GasEstimationError::RevertInValidation(revert));
        }

        let run_attempt_returning_error = |gas: u128, state_override: StateOverride| async move {
            let op = get_op(gas);
            let revert = self
                .entry_point
                .simulate_handle_op(
                    op,
                    Address::ZERO,
                    Bytes::new(),
                    block_hash.into(),
                    state_override,
                )
                .await?
                .err();

            if let Some(revert) = revert {
                if let Some(error_code) = revert.entry_point_error_code() {
                    if OUT_OF_GAS_ERROR_CODES.contains(&error_code) {
                        // This error occurs when out of gas, return false.
                        return Ok(false);
                    }
                }
                // This is a different error, return it
                Err(GasEstimationError::RevertInValidation(revert))
            } else {
                // This succeeded, return true
                Ok(true)
            }
        };

        let mut max_failure_gas = 1;

        let mut min_success_gas = self.settings.max_verification_gas;

        if gas_used.gasUsed.gt(&U256::from(u128::MAX)) {
            return Err(GasEstimationError::GasUsedTooLarge);
        }

        let ret_gas_used: u128 = gas_used.gasUsed.try_into().unwrap();
        let mut guess = ret_gas_used.saturating_mul(2);
        let mut num_rounds = 0;
        while (min_success_gas as f64) / (max_failure_gas as f64)
            > (1.0 + GAS_ESTIMATION_ERROR_MARGIN)
        {
            num_rounds += 1;
            if run_attempt_returning_error(guess, state_override.clone()).await? {
                min_success_gas = guess;
            } else {
                max_failure_gas = guess;
            }
            guess = max_failure_gas.saturating_add(min_success_gas) / 2;
        }

        tracing::debug!(
            "binary search for verification gas took {num_rounds} rounds, {}ms",
            timer.elapsed().as_millis()
        );

        // If not using a paymaster, always add the cost of a native transfer to the verification gas.
        // This may cause an over estimation when the account does have enough deposit to pay for the
        // max cost, but it is better to overestimate than underestimate.
        if op.paymaster().is_none() {
            min_success_gas += self.chain_spec.deposit_transfer_overhead();
        }

        Ok(min_success_gas)
    }
}

impl<UO, P, E> VerificationGasEstimatorImpl<P, E>
where
    UO: UserOperation,
    P: EvmProvider,
    E: EntryPoint + SimulationProvider<UO = UO>,
{
    /// Create a new instance
    pub fn new(chain_spec: ChainSpec, provider: P, entry_point: E, settings: Settings) -> Self {
        Self {
            chain_spec,
            provider,
            entry_point,
            settings,
        }
    }
}
