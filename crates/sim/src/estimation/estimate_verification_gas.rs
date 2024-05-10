use std::sync::Arc;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use ethers::types::{spoof, Address, Bytes, H256, U128, U256};
use rundler_provider::{EntryPoint, Provider, SimulateOpCallData, SimulationProvider};
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
pub trait VerificationGasEstimator: Send + Sync + 'static {
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
        block_hash: H256,
        state_override: &spoof::State,
        max_guess: U128,
        get_op_with_limit: F,
    ) -> Result<U128, GasEstimationError>;
}

#[derive(Debug, Clone, Copy)]
pub struct GetOpWithLimitArgs {
    pub gas: U128,
    pub fee: U128,
}

/// Implementation of a verification gas estimator
#[derive(Debug)]
pub struct VerificationGasEstimatorImpl<P, E> {
    chain_spec: ChainSpec,
    provider: Arc<P>,
    entry_point: E,
    settings: Settings,
}

#[async_trait]
impl<UO, P, E> VerificationGasEstimator for VerificationGasEstimatorImpl<P, E>
where
    UO: UserOperation,
    P: Provider,
    E: EntryPoint + SimulationProvider<UO = UO>,
{
    type UO = UO;

    async fn estimate_verification_gas<F: Send + Sync + Fn(UO, GetOpWithLimitArgs) -> UO>(
        &self,
        op: &UO,
        block_hash: H256,
        state_override: &spoof::State,
        max_guess: U128,
        get_op_with_limit: F,
    ) -> Result<U128, GasEstimationError> {
        let timer = std::time::Instant::now();
        let paymaster_gas_fee = U128::from(self.settings.verification_estimation_gas_fee);

        // Fee logic for gas estimation:
        //
        // If there is no paymaster, verification estimation is always performed
        // with zero fees. The cost of the native transfer is added to the verification gas
        // at the end of estimation.
        //
        // If using a paymaster, the total cost is kept constant, and the fee is adjusted
        // based on the gas used in the simulation. The total cost is set by a configuration
        // setting.
        let get_op = |gas: U128| -> UO {
            let fee = if op.paymaster().is_none() {
                U128::zero()
            } else {
                U128::try_from(
                    U256::from(paymaster_gas_fee)
                        .checked_div(U256::from(gas) + op.pre_verification_gas())
                        .unwrap_or(U256::MAX),
                )
                .unwrap_or(U128::MAX)
            };
            get_op_with_limit(op.clone(), GetOpWithLimitArgs { gas, fee })
        };

        // Make one attempt at max gas, to see if success is possible.
        // Capture the gas usage of this attempt and use as the initial guess in the binary search
        let initial_op = get_op(max_guess);
        let SimulateOpCallData {
            call_data,
            spoofed_state,
        } = self
            .entry_point
            .get_simulate_op_call_data(initial_op, state_override);
        let gas_used = self
            .provider
            .get_gas_used(
                self.entry_point.address(),
                U256::zero(),
                call_data,
                spoofed_state.clone(),
            )
            .await
            .context("failed to run initial guess")?;

        if gas_used.success {
            if self.entry_point.simulation_should_revert() {
                Err(anyhow!(
                    "simulateHandleOp succeeded but should always revert. Make sure the entry point contract is deployed and the address is correct"
                ))?;
            }
        } else if let Some(revert) = self
            .entry_point
            .decode_simulate_handle_ops_revert(gas_used.result)
            .err()
        {
            return Err(GasEstimationError::RevertInValidation(revert));
        }

        let run_attempt_returning_error = |gas: u64| async move {
            let op = get_op(gas.into());
            let revert = self
                .entry_point
                .call_spoofed_simulate_op(
                    op,
                    Address::zero(),
                    Bytes::new(),
                    block_hash,
                    self.settings.max_simulate_handle_ops_gas.into(),
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

        if gas_used.gas_used.gt(&U256::from(u64::MAX)) {
            return Err(GasEstimationError::GasUsedTooLarge);
        }
        let mut guess = gas_used.gas_used.as_u64().saturating_mul(2);
        let mut num_rounds = 0;
        while (min_success_gas as f64) / (max_failure_gas as f64)
            > (1.0 + GAS_ESTIMATION_ERROR_MARGIN)
        {
            num_rounds += 1;
            if run_attempt_returning_error(guess).await? {
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

        let mut min_success_gas = U256::from(min_success_gas);

        // If not using a paymaster, always add the cost of a native transfer to the verification gas.
        // This may cause an over estimation when the account does have enough deposit to pay for the
        // max cost, but it is better to overestimate than underestimate.
        if op.paymaster().is_none() {
            min_success_gas += self.chain_spec.deposit_transfer_overhead;
        }

        Ok(U128::try_from(min_success_gas)
            .ok()
            .context("min success gas should fit in 128-bit int")?)
    }
}

impl<UO, P, E> VerificationGasEstimatorImpl<P, E>
where
    UO: UserOperation,
    P: Provider,
    E: EntryPoint + SimulationProvider<UO = UO>,
{
    /// Create a new instance
    pub fn new(
        chain_spec: ChainSpec,
        provider: Arc<P>,
        entry_point: E,
        settings: Settings,
    ) -> Self {
        Self {
            chain_spec,
            provider,
            entry_point,
            settings,
        }
    }
}
