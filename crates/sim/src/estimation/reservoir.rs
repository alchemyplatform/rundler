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

//! Reservoir-mode gas: the state-gas reservoir a v0.7 op needs, found by simulations that give
//! the op a reservoir as its bundle transaction gets. Used by gas estimation, and by admission for
//! bundler-sponsored ops, whose zero PVG cannot carry a reservoir.

use std::{future::Future, pin::Pin, sync::Arc};

use alloy_primitives::{Address, B256, Bytes};
use alloy_sol_types::{SolCall, SolError};
use anyhow::Context;
use rundler_contracts::{
    common::EstimationTypes,
    v0_7::{
        IEntryPointSimulations::{simulateHandleOpCall, simulateHandleOpNoPostOpCall},
        RESERVOIR_PROBE_V0_7_DEPLOYED_BYTECODE,
        ReservoirProbe::probeCall,
    },
};
use rundler_provider::{
    AccountOverride, EntryPoint, EvmProvider, SimulatedCall, SimulationProvider, StateOverride,
    TransactionRequest, simulate_call, simulate_calls,
};
use rundler_types::{
    GasEstimate, PvgState, TX_MAX_GAS_LIMIT, UserOperation as _,
    chain::ChainSpec,
    constants::SIMULATION_SENDER,
    v0_7::{UserOperation, UserOperationBuilder, UserOperationOptionalGas},
};
use rundler_utils::guard_timer::CustomTimerGuard;
use tokio::sync::Semaphore;
use tracing::instrument;

use super::{
    BinarySearchResult, CALL_GAS_BUFFER_VALUE, GasEstimationError, Metrics, Settings,
    state_gas::{
        MIN_RESERVOIR_STATE_GAS, least_passing, metered_gas, padded_reservoir,
        user_operation_event, user_operation_event_success,
    },
    v0_7::{CallGasEstimatorSpecializationV07, decode_validation_revert},
};
use crate::{CallGasEstimatorSpecialization, MIN_CALL_GAS_LIMIT, gas};

/// Gas below `TX_MAX_GAS_LIMIT` a reservoir-mode simulation keeps for the entry point's own work
/// outside the op's limits
const RESERVOIR_SIMULATION_GAS_OVERHEAD: u128 = 1_000_000;

/// Gas `simulateHandleOp` uses outside what the entry point meters for the op and the
/// transaction's intrinsic gas: 20,783 on Sepolia for v0.7 (24,304 with a paymaster). A little
/// less, so the state gas measured stays at or above the op's.
pub(super) const SIMULATION_UNMETERED_GAS: u128 = 20_000;

/// The reservoir a `ReservoirProbe` call gets: enough for the new slot it writes
const RESERVOIR_PROBE_RESERVOIR_GAS: u64 = 200_000;

/// A transaction's intrinsic gas for calldata `input`
pub(super) fn transaction_intrinsic_gas(chain_spec: &ChainSpec, input: &[u8]) -> u128 {
    let non_zero_bytes = input.iter().filter(|&&byte| byte != 0).count() as u128;
    let zero_bytes = input.len() as u128 - non_zero_bytes;
    chain_spec.transaction_intrinsic_gas()
        + zero_bytes * chain_spec.calldata_zero_byte_gas()
        + non_zero_bytes * chain_spec.calldata_non_zero_byte_gas()
}

/// What a reservoir-mode fallback needs from the metered estimate it follows
pub(crate) struct ReservoirArgs<'a> {
    pub(crate) op: &'a UserOperationOptionalGas,
    pub(crate) full_op: &'a UserOperation,
    pub(crate) chain_spec: &'a ChainSpec,
    pub(crate) block_hash: B256,
    pub(crate) state_override: &'a StateOverride,
    pub(crate) da_gas: u128,
    pub(crate) pvg_state: PvgState,
    pub(crate) verification_gas_limit: u128,
    pub(crate) paymaster_verification_gas_limit: u128,
}

/// The state-gas reservoir a bundler-sponsored op needs, as admission finds it
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SponsoredReservoir {
    /// The op runs metered, within its own limits
    Metered,
    /// The op runs only with a reservoir of this much gas. It may exceed `max_reservoir_gas`, for
    /// admission to reject.
    Reservoir(u128),
    /// The op fails even with the most reservoir: admitted metered, as any sponsored op whose
    /// execution fails (its sponsor pays for the failure, within its max cost)
    Fails,
}

/// Finds the state-gas reservoir a v0.7 op needs, with `eth_simulateV1`
pub struct ReservoirEstimator<P, E> {
    provider: P,
    entry_point: E,
    settings: Settings,
    metrics: Metrics,
    /// Bounds the reservoir searches running at once (each traces at up to the node's gas cap)
    reservoir_permits: Arc<Semaphore>,
}

impl<P, E> ReservoirEstimator<P, E> {
    /// Create a new reservoir estimator
    pub fn new(provider: P, entry_point: E, settings: Settings) -> Self {
        Self {
            provider,
            entry_point,
            settings,
            metrics: Metrics::default(),
            reservoir_permits: Arc::new(Semaphore::new(
                settings.max_concurrent_reservoir_estimations,
            )),
        }
    }
}

/// Required PVG for an op with these limits, before the calldata floor top-up
#[allow(clippy::too_many_arguments)]
pub(super) fn base_pre_verification_gas(
    op: &UserOperationOptionalGas,
    chain_spec: &ChainSpec,
    da_gas: u128,
    pvg_state: &PvgState,
    verification_gas_limit: u128,
    paymaster_verification_gas_limit: u128,
    call_gas_limit: u128,
) -> u128 {
    // TODO(bundle): assuming a bundle size of 1
    let bundle_size = 1;
    let base_op = op.max_fill(chain_spec);
    if chain_spec.charge_gas_limit_via_pvg {
        let op_with_limits = UserOperationBuilder::from_uo(base_op, chain_spec)
            .verification_gas_limit(verification_gas_limit)
            .paymaster_verification_gas_limit(paymaster_verification_gas_limit)
            .call_gas_limit(call_gas_limit)
            .paymaster_post_op_gas_limit(op.paymaster_post_op_gas_limit.unwrap_or(0))
            .build();
        op_with_limits.required_pre_verification_gas(
            chain_spec,
            bundle_size,
            da_gas,
            None,
            pvg_state,
        )
    } else {
        base_op.required_pre_verification_gas(chain_spec, bundle_size, da_gas, None, pvg_state)
    }
}

impl<P, E> ReservoirEstimator<P, E>
where
    P: EvmProvider,
    E: EntryPoint + SimulationProvider<UO = UserOperation>,
{
    /// Estimates `args.op` in reservoir mode after its metered estimate failed with
    /// `metered_error`, which is returned if the op does not need (or cannot be estimated in)
    /// reservoir mode.
    ///
    /// The op's net state gas `S`, the reservoir `R` and the call gas limit come from
    /// `eth_simulateV1`, which gives a call above `TX_MAX_GAS_LIMIT` a reservoir as the bundle
    /// transaction gets, checked by a
    /// `ReservoirProbe`: the call gas search at `R = S`, with any state
    /// the op peaks at above `S` spilling into its call gas, or if that spill does not fit, the
    /// least `R` the op runs with at the most call gas, and the search at that `R`. VGL stays
    /// the metered estimate, and PVG pays for all of `R`, as the bundle's reservoir is the PVG
    /// surplus: state the reservoir pays is not metered by the entry point. See
    /// `test/pvg-calibration/docs/reservoir-mode-plan.md`.
    #[instrument(skip_all)]
    pub(super) async fn estimate_reservoir_mode(
        &self,
        args: ReservoirArgs<'_>,
        metered_error: GasEstimationError,
    ) -> Result<GasEstimate, GasEstimationError> {
        self.metrics.reservoir_fallbacks.increment(1);
        let Ok(_permit) = self.reservoir_permits.try_acquire() else {
            self.metrics.reservoir_fallbacks_busy.increment(1);
            return Err(metered_error);
        };

        let _timer = CustomTimerGuard::new(self.metrics.reservoir_trace_ms.clone());
        let deadline = tokio::time::Instant::now() + self.settings.reservoir_trace_timeout;
        let measured = tokio::time::timeout_at(deadline, self.simulate_state_gas(&args)).await;
        let state_gas = match measured {
            Ok(Ok(Some(state_gas))) => state_gas,
            // The op fails even with the most reservoir and call gas: a genuine failure.
            Ok(Ok(None)) => return Err(metered_error),
            Ok(Err(error)) => {
                tracing::warn!("reservoir-mode state-gas simulation failed: {error:#}");
                return Err(metered_error);
            }
            Err(_) => {
                tracing::warn!("reservoir-mode state-gas simulation timed out");
                return Err(metered_error);
            }
        };
        let ReservoirArgs {
            op,
            full_op,
            chain_spec,
            da_gas,
            pvg_state,
            verification_gas_limit,
            paymaster_verification_gas_limit,
            ..
        } = args;
        let max_bundle_execution_gas = self.settings.max_bundle_execution_gas;
        let max_reservoir_gas = u128::from(self.settings.max_reservoir_gas);
        if state_gas > max_reservoir_gas {
            return Err(GasEstimationError::StateGasTooLarge(
                state_gas,
                max_reservoir_gas,
            ));
        }
        let found =
            tokio::time::timeout_at(deadline, self.reservoir_and_call_gas(&args, state_gas)).await;
        let (op_reservoir_gas, call_gas_limit) = match found {
            Ok(Ok(Some(found))) => found,
            Ok(Ok(None)) => return Err(metered_error),
            Ok(Err(error)) => {
                tracing::warn!("reservoir-mode simulation failed: {error:#}");
                return Err(metered_error);
            }
            Err(_) => {
                tracing::warn!("reservoir-mode simulations timed out");
                return Err(metered_error);
            }
        };

        // Price the zero-deposit refund write whatever the deposit is now: it may be zero by
        // admission, and the reservoir is sized from the PVG surplus over the metered
        // requirement.
        let pvg_state = PvgState {
            sender_deposit_is_zero: if op.paymaster.is_none() {
                Some(true)
            } else {
                pvg_state.sender_deposit_is_zero
            },
            ..pvg_state
        };
        let base_pvg = base_pre_verification_gas(
            op,
            chain_spec,
            da_gas,
            &pvg_state,
            verification_gas_limit,
            paymaster_verification_gas_limit,
            call_gas_limit,
        );
        let op_with_gas = UserOperationBuilder::from_uo(full_op.clone(), chain_spec)
            .pre_verification_gas(base_pvg)
            .call_gas_limit(call_gas_limit)
            .verification_gas_limit(verification_gas_limit)
            .paymaster_verification_gas_limit(paymaster_verification_gas_limit)
            .build();
        let gas_limit = self.reservoir_computation_gas(&args, call_gas_limit);
        if gas_limit > max_bundle_execution_gas {
            return Err(GasEstimationError::GasTotalTooLarge(
                gas_limit,
                max_bundle_execution_gas,
            ));
        }
        // The metered estimate failed, yet the state may still fit under the cap next to the
        // op's computation gas: the metered call gas limit needs more than the state itself
        // (the binary search's error tolerance, and the 1/64 withheld at each nested call). Such
        // an op fits neither mode, so its PVG pays for a reservoir above the threshold, and
        // admission classifies it as reservoir mode. The unused part of that reservoir is
        // refunded to the bundler.
        let threshold =
            gas::reservoir_threshold(&op_with_gas, chain_spec, max_bundle_execution_gas);
        let base_pvg = rundler_types::increase_required_pvg_with_calldata_floor_gas(
            &op_with_gas,
            base_pvg - da_gas,
            da_gas,
            op.max_fill(chain_spec).calldata_floor_gas_limit(chain_spec),
            self.settings
                .verification_gas_limit_efficiency_reject_threshold,
        );
        // State charged to the reservoir before the op runs, which the simulations cannot see:
        // a new EIP-7702 authority is applied by state override, not by processing the
        // authorization.
        let needed_reservoir_gas =
            op_reservoir_gas + op_with_gas.authorization_state_gas(chain_spec, &pvg_state);
        let mut reservoir_gas = padded_reservoir(needed_reservoir_gas, threshold);
        // Classify the op as admission will, against its own threshold with the final PVG. A
        // larger PVG only raises the op's computation gas, which lowers the threshold, so one
        // adjustment suffices.
        let final_threshold = gas::reservoir_threshold(
            &UserOperationBuilder::from_uo(op_with_gas.clone(), chain_spec)
                .pre_verification_gas(base_pvg + reservoir_gas)
                .build(),
            chain_spec,
            max_bundle_execution_gas,
        );
        reservoir_gas = reservoir_gas.max(padded_reservoir(0, final_threshold));
        if reservoir_gas > needed_reservoir_gas {
            tracing::debug!(
                "reservoir mode: needs a reservoir of {needed_reservoir_gas}, threshold {final_threshold}, reservoir padded to {reservoir_gas}"
            );
        }
        if reservoir_gas > max_reservoir_gas {
            return Err(GasEstimationError::StateGasTooLarge(
                reservoir_gas,
                max_reservoir_gas,
            ));
        }

        self.metrics.reservoir_estimates.increment(1);
        self.metrics.reservoir_state_gas.record(state_gas as f64);
        tracing::debug!(
            "reservoir-mode estimate: net state gas {state_gas}, reservoir {reservoir_gas}, call gas limit {call_gas_limit}"
        );

        Ok(GasEstimate {
            pre_verification_gas: base_pvg + reservoir_gas,
            call_gas_limit,
            verification_gas_limit,
            paymaster_verification_gas_limit: op
                .paymaster
                .map(|_| paymaster_verification_gas_limit),
        })
    }

    /// The reservoir the op needs and its call gas limit, from simulations with a reservoir, given
    /// its net state gas. The least reservoir is the cheapest for the op: PVG pays for all of it,
    /// while state that spills into the call gas limit at a peak is refilled once cleared, and
    /// costs at most the unused-gas penalty. `None` if the op fails even with the most reservoir
    /// and call gas, or at the limits found, or if it has no net state and runs without a
    /// reservoir.
    async fn reservoir_and_call_gas(
        &self,
        args: &ReservoirArgs<'_>,
        state_gas: u128,
    ) -> anyhow::Result<Option<(u128, u128)>> {
        let max_call_gas = self.reservoir_max_call_gas(args);
        let max_reservoir_gas = u128::from(self.settings.max_reservoir_gas);
        // With the net state alone, any peak above it spills into the call gas limit.
        let (reservoir_gas, call_gas) = match self
            .reservoir_call_gas_search(args, state_gas, max_call_gas)
            .await?
        {
            // Without net state, an op that runs at R = S has no use for a reservoir: its metered
            // estimate failed for another reason. One that clears all the state it allocates
            // still needs a reservoir for its peak, which the search below finds.
            Some(_) if state_gas < MIN_RESERVOIR_STATE_GAS => {
                tracing::debug!("reservoir mode not needed: no state gas");
                return Ok(None);
            }
            Some(call_gas) => (state_gas, call_gas),
            None => {
                // The spill does not fit: the least reservoir the op runs with at the most call
                // gas.
                let passes =
                    |reservoir_gas| self.reservoir_runs_at(args, reservoir_gas, max_call_gas);
                if state_gas >= max_reservoir_gas || !passes(max_reservoir_gas).await? {
                    tracing::debug!("reservoir-mode op fails with the most reservoir and call gas");
                    return Ok(None);
                }
                self.metrics.reservoir_peak_searches.increment(1);
                let reservoir_gas = least_passing(state_gas, max_reservoir_gas, passes).await?;
                let Some(call_gas) = self
                    .reservoir_call_gas_search(args, reservoir_gas, max_call_gas)
                    .await?
                else {
                    tracing::debug!(
                        "reservoir-mode call gas search fails at a reservoir of {reservoir_gas}"
                    );
                    return Ok(None);
                };
                tracing::debug!(
                    "reservoir-mode state peaks: needs a reservoir of {reservoir_gas}, S {state_gas}"
                );
                (reservoir_gas, call_gas)
            }
        };
        let call_gas_limit = (call_gas + CALL_GAS_BUFFER_VALUE).max(MIN_CALL_GAS_LIMIT);
        // The searches leave postOp out: check the op as it will run.
        if !self
            .reservoir_op_succeeds(args, reservoir_gas, call_gas_limit)
            .await?
        {
            tracing::debug!(
                "reservoir-mode op fails with postOp at a reservoir of {reservoir_gas}, call gas limit {call_gas_limit}"
            );
            return Ok(None);
        }
        Ok(Some((reservoir_gas, call_gas_limit)))
    }

    /// The most call gas a reservoir-mode op's call gas search may find: what fits under
    /// `max_bundle_execution_gas` next to its other limits with the buffer added to the result,
    /// and what a simulation of it can give the sender out of the gas below `TX_MAX_GAS_LIMIT`,
    /// after the verification limits and the entry point's work, and the 1/64 kept at each of
    /// the three calls on the way (the simulation's target, the call gas proxy's guess, and its
    /// call into the sender).
    pub(super) fn reservoir_max_call_gas(&self, args: &ReservoirArgs<'_>) -> u128 {
        let max_bundle_execution_gas = self.settings.max_bundle_execution_gas;
        let computation_gas = |call_gas_limit| self.reservoir_computation_gas(args, call_gas_limit);
        // The entry point needs 64/63 of the call gas limit before execution (see
        // `required_pre_execution_buffer`), so the computation gas grows a little faster than it.
        let mut in_bundle = max_bundle_execution_gas.saturating_sub(computation_gas(0)) * 63 / 64;
        in_bundle -= computation_gas(in_bundle)
            .saturating_sub(max_bundle_execution_gas)
            .min(in_bundle);
        let in_simulation = u128::from(TX_MAX_GAS_LIMIT)
            .saturating_sub(args.verification_gas_limit)
            .saturating_sub(args.paymaster_verification_gas_limit)
            .saturating_sub(RESERVOIR_SIMULATION_GAS_OVERHEAD)
            * 63
            * 63
            * 63
            / (64 * 64 * 64);
        in_bundle
            .saturating_sub(CALL_GAS_BUFFER_VALUE)
            .min(in_simulation)
    }

    /// The op's computation gas (`bundle_computation_gas_limit`) at its limits and
    /// `call_gas_limit`, as admission will compute it for the op as sent. Its call gas limit is at
    /// the most that fits, so there is no headroom: priced with the worst-case calldata
    /// (`max_fill`), since the signature, paymaster data and PVG sent are not the estimate's.
    fn reservoir_computation_gas(&self, args: &ReservoirArgs<'_>, call_gas_limit: u128) -> u128 {
        UserOperationBuilder::from_uo(args.op.max_fill(args.chain_spec), args.chain_spec)
            .verification_gas_limit(args.verification_gas_limit)
            .paymaster_verification_gas_limit(args.paymaster_verification_gas_limit)
            .paymaster_post_op_gas_limit(args.op.paymaster_post_op_gas_limit.unwrap_or(0))
            .call_gas_limit(call_gas_limit)
            .build()
            .bundle_computation_gas_limit(args.chain_spec, Some(1))
    }

    /// The least call gas the op runs with at a reservoir of `reservoir_gas`, by the call gas
    /// search in `eth_simulateV1`, within its error tolerance. `None` if it fails at
    /// `max_call_gas`.
    async fn reservoir_call_gas_search(
        &self,
        args: &ReservoirArgs<'_>,
        reservoir_gas: u128,
        max_call_gas: u128,
    ) -> anyhow::Result<Option<u128>> {
        let (specialization, callless_op, state_override) = self.reservoir_call_gas_setup(args);
        let entry_point = *self.entry_point.address();
        let round_fn = |min_gas: u128, max_gas: u128, is_continuation: bool| {
            let target_call_data = specialization.get_estimate_call_gas_calldata(
                callless_op.clone(),
                min_gas,
                max_gas,
                self.settings.call_gas_allowed_error_pct,
                is_continuation,
            );
            Box::pin(self.simulate_reservoir_target(
                args,
                callless_op.clone(),
                target_call_data,
                state_override.clone(),
                reservoir_gas,
            ))
                as Pin<Box<dyn Future<Output = Result<Bytes, GasEstimationError>> + Send + '_>>
        };
        let result = super::run_binary_search(
            round_fn,
            max_call_gas,
            self.settings.max_gas_estimation_rounds,
            entry_point,
            "reservoir_call",
        )
        .await?;
        Ok(match result {
            BinarySearchResult::Success(call_gas, _) => Some(call_gas),
            BinarySearchResult::Revert(revert_data) => {
                tracing::debug!(
                    "reservoir-mode call fails at a reservoir of {reservoir_gas} with the most call gas: {revert_data}"
                );
                None
            }
        })
    }

    /// Whether the op's call succeeds with `call_gas` at a reservoir of `reservoir_gas`, in
    /// `eth_simulateV1`.
    async fn reservoir_runs_at(
        &self,
        args: &ReservoirArgs<'_>,
        reservoir_gas: u128,
        call_gas: u128,
    ) -> anyhow::Result<bool> {
        let (specialization, callless_op, state_override) = self.reservoir_call_gas_setup(args);
        let target_call_data =
            specialization.get_test_call_gas_calldata(callless_op.clone(), call_gas);
        let target_result = self
            .simulate_reservoir_target(
                args,
                callless_op,
                target_call_data,
                state_override,
                reservoir_gas,
            )
            .await?;
        let result = EstimationTypes::TestCallGasResult::abi_decode(&target_result)
            .context("should decode revert data as TestCallGasResult")?;
        Ok(result.success)
    }

    /// The call gas proxy, the op without call gas, and the overrides for a call gas search
    /// (see `CallGasEstimationProxy.sol`).
    fn reservoir_call_gas_setup(
        &self,
        args: &ReservoirArgs<'_>,
    ) -> (
        CallGasEstimatorSpecializationV07,
        UserOperation,
        StateOverride,
    ) {
        let specialization = CallGasEstimatorSpecializationV07 {
            chain_spec: args.chain_spec.clone(),
            simulations_bytecode: self.entry_point.get_simulations_bytecode().clone(),
        };
        let mut state_override = args.state_override.clone();
        specialization.add_proxy_to_overrides(*self.entry_point.address(), &mut state_override);
        let post_op_gas = args.op.paymaster_post_op_gas_limit.unwrap_or(0);
        let callless_op =
            specialization.get_op_with_no_call_gas(self.reservoir_copy(args, 0, post_op_gas));
        (specialization, callless_op, state_override)
    }

    /// The result of the target of `simulateHandleOpNoPostOp` of `op`, with the call gas proxy
    /// as its target, in `eth_simulateV1` at `TX_MAX_GAS_LIMIT + reservoir_gas`.
    async fn simulate_reservoir_target(
        &self,
        args: &ReservoirArgs<'_>,
        op: UserOperation,
        target_call_data: Bytes,
        state_override: StateOverride,
        reservoir_gas: u128,
    ) -> Result<Bytes, GasEstimationError> {
        let result = self
            .simulate_reservoir_copy(
                args,
                op,
                true,
                *self.entry_point.address(),
                target_call_data,
                state_override,
                reservoir_gas,
            )
            .await?;
        if !result.success {
            return Err(decode_validation_revert::<E>(&result.return_data));
        }
        let execution_result =
            simulateHandleOpNoPostOpCall::abi_decode_returns(&result.return_data)
                .context("should decode simulateHandleOpNoPostOp result")?;
        Ok(execution_result.targetResult)
    }

    /// The op's net state gas `S`, from `eth_simulateV1` of the op with the most reservoir and call
    /// gas: the transaction's gas used, less the gas the entry point metered (without its penalty
    /// on unused execution gas), the transaction's intrinsic gas and the simulation's own
    /// unmetered work.
    ///
    /// Approximate, and only a starting point for the searches, which run the op at the reservoir
    /// and limits it gets: refunds (e.g. for cleared slots) lower the gas used, so `S` errs low
    /// for an op that clears state. On Sepolia it is within about 5,000 above the traced `S`
    /// otherwise. `None` if the op fails even with the most reservoir and call gas.
    async fn simulate_state_gas(&self, args: &ReservoirArgs<'_>) -> anyhow::Result<Option<u128>> {
        let call_gas_limit = self.reservoir_max_call_gas(args);
        let post_op_gas_limit = args.op.paymaster_post_op_gas_limit.unwrap_or(0);
        let op = self.reservoir_copy(args, call_gas_limit, post_op_gas_limit);
        let (result, intrinsic_gas) = self
            .simulate_op_with_probe(args, op, u128::from(self.settings.max_reservoir_gas))
            .await?;
        let entry_point = *self.entry_point.address();
        let event = user_operation_event(&result.logs, entry_point);
        let succeeded = event.as_ref().map(|event| event.success);
        let Some(event) = event.filter(|event| result.success && event.success) else {
            tracing::debug!(
                "reservoir-mode op fails with the most reservoir and call gas: success {}, event {succeeded:?}",
                result.success,
            );
            return Ok(None);
        };
        let pre_op_gas: u128 = simulateHandleOpCall::abi_decode_returns(&result.return_data)
            .context("should decode simulateHandleOp result")?
            .preOpGas
            .saturating_to();
        let metered = metered_gas(
            event.actualGasUsed.saturating_to(),
            pre_op_gas,
            call_gas_limit + post_op_gas_limit,
        );
        Ok(Some(
            u128::from(result.gas_used)
                .saturating_sub(metered)
                .saturating_sub(intrinsic_gas)
                .saturating_sub(SIMULATION_UNMETERED_GAS),
        ))
    }

    /// Whether the op succeeds at a reservoir of `reservoir_gas` and its estimated limits, with
    /// postOp, in `eth_simulateV1`.
    async fn reservoir_op_succeeds(
        &self,
        args: &ReservoirArgs<'_>,
        reservoir_gas: u128,
        call_gas_limit: u128,
    ) -> anyhow::Result<bool> {
        let post_op_gas = args.op.paymaster_post_op_gas_limit.unwrap_or(0);
        let op = self.reservoir_copy(args, call_gas_limit, post_op_gas);
        let (result, _) = self.simulate_op_with_probe(args, op, reservoir_gas).await?;
        let entry_point = *self.entry_point.address();
        Ok(result.success && user_operation_event_success(&result.logs, entry_point) == Some(true))
    }

    /// Simulates `simulateHandleOp` of `op` with postOp at a reservoir of `reservoir_gas` in
    /// `eth_simulateV1`, and returns its result and the transaction's intrinsic gas. A
    /// `ReservoirProbe` call in the same request checks that the node's `eth_simulateV1` gives
    /// calls a state-gas reservoir, which all of the reservoir-mode simulations rely on (geth from
    /// v1.17.8 gives none): an error if it does not. The probe is its own call, not
    /// `simulateHandleOp`'s target, which would see what the op left of the reservoir.
    async fn simulate_op_with_probe(
        &self,
        args: &ReservoirArgs<'_>,
        op: UserOperation,
        reservoir_gas: u128,
    ) -> anyhow::Result<(SimulatedCall, u128)> {
        let mut state_override = args.state_override.clone();
        // A random address, so a user's override cannot collide with it.
        let probe = Address::random();
        state_override.insert(
            probe,
            AccountOverride {
                code: Some(RESERVOIR_PROBE_V0_7_DEPLOYED_BYTECODE.clone()),
                ..Default::default()
            },
        );
        let gas = (u128::from(TX_MAX_GAS_LIMIT) + reservoir_gas)
            .try_into()
            .unwrap_or(u64::MAX);
        let (tx, state_override) = self.entry_point.get_state_gas_simulate_handle_op_call(
            op,
            false,
            Address::ZERO,
            Bytes::new(),
            gas,
            state_override,
        )?;
        let intrinsic_gas = transaction_intrinsic_gas(
            args.chain_spec,
            tx.input.input().map(|input| &input[..]).unwrap_or_default(),
        );
        let probe_tx = TransactionRequest::default()
            .from(SIMULATION_SENDER)
            .to(probe)
            .input(Bytes::from(probeCall {}.abi_encode()).into())
            .gas_limit(TX_MAX_GAS_LIMIT + RESERVOIR_PROBE_RESERVOIR_GAS);
        let mut results = simulate_calls(
            &self.provider,
            vec![probe_tx, tx],
            Some(args.block_hash.into()),
            state_override,
        )
        .await?;
        let probe_result = &results[0];
        let reservoir_in_simulation = probe_result.success
            && probeCall::abi_decode_returns(&probe_result.return_data)
                .context("should decode the reservoir probe's result")?;
        if !reservoir_in_simulation {
            self.metrics
                .reservoir_simulation_without_reservoir
                .increment(1);
            anyhow::bail!("the node's eth_simulateV1 gives calls no state-gas reservoir");
        }
        Ok((results.remove(1), intrinsic_gas))
    }

    /// Simulates `simulateHandleOp` of `op` (without postOp if `skip_post_op`) with
    /// `eth_simulateV1`, which gives the call a reservoir of `reservoir_gas` as the bundle
    /// transaction gets.
    #[allow(clippy::too_many_arguments)]
    async fn simulate_reservoir_copy(
        &self,
        args: &ReservoirArgs<'_>,
        op: UserOperation,
        skip_post_op: bool,
        target: Address,
        target_call_data: Bytes,
        state_override: StateOverride,
        reservoir_gas: u128,
    ) -> anyhow::Result<SimulatedCall> {
        let gas = (u128::from(TX_MAX_GAS_LIMIT) + reservoir_gas)
            .try_into()
            .unwrap_or(u64::MAX);
        let (tx, state_override) = self.entry_point.get_state_gas_simulate_handle_op_call(
            op,
            skip_post_op,
            target,
            target_call_data,
            gas,
            state_override,
        )?;
        Ok(simulate_call(
            &self.provider,
            tx,
            Some(args.block_hash.into()),
            state_override,
        )
        .await?)
    }

    /// A copy of the op to simulate, with the metered verification limits and the given call and
    /// postOp limits.
    fn reservoir_copy(
        &self,
        args: &ReservoirArgs<'_>,
        call_gas_limit: u128,
        post_op_gas_limit: u128,
    ) -> UserOperation {
        // Fee 0 skips the deposit debit, which `deposit_transfer_overhead` already covers for
        // self-paying ops. A paymaster's debit is measured at 1 wei, which stays well within any
        // deposit despite the large limits (AA31 otherwise).
        let fee = u128::from(args.full_op.paymaster().is_some());
        // VGL is not raised: the metered estimate already covers validation state.
        UserOperationBuilder::from_uo(args.full_op.clone(), args.chain_spec)
            .verification_gas_limit(args.verification_gas_limit)
            .paymaster_verification_gas_limit(args.paymaster_verification_gas_limit)
            .call_gas_limit(call_gas_limit)
            .paymaster_post_op_gas_limit(post_op_gas_limit)
            .max_fee_per_gas(fee)
            .max_priority_fee_per_gas(fee)
            .pre_verification_gas(0)
            .build()
    }

    /// The least reservoir a bundler-sponsored op runs with at its own limits. A sponsored op's
    /// PVG is zero, so it cannot carry its reservoir as a paying op does; admission finds it with
    /// the simulations estimation runs. The op is first run without a reservoir, and only if it
    /// fails is one searched for, from its net state gas up to `max_reservoir_gas`, at the call
    /// gas limit the op was signed with.
    ///
    /// Unlike a paying op's, the reservoir is not padded up to the reservoir threshold: that
    /// padding lets admission classify a paying op by its PVG surplus, while a sponsored op's
    /// mode is decided here.
    #[instrument(skip_all)]
    pub async fn sponsored_reservoir_gas(
        &self,
        op: &UserOperation,
        chain_spec: &ChainSpec,
        block_hash: B256,
    ) -> anyhow::Result<SponsoredReservoir> {
        if self.settings.max_reservoir_gas == 0 {
            return Ok(SponsoredReservoir::Metered);
        }
        self.metrics.sponsored_reservoir_searches.increment(1);
        let Ok(_permit) = self.reservoir_permits.try_acquire() else {
            self.metrics.reservoir_fallbacks_busy.increment(1);
            anyhow::bail!("too many reservoir searches are running");
        };
        let _timer = CustomTimerGuard::new(self.metrics.reservoir_trace_ms.clone());

        let pvg_state = gas::load_pvg_state(
            chain_spec,
            &self.provider,
            &self.entry_point,
            op,
            Some(block_hash.into()),
        )
        .await?;
        let optional_op = UserOperationOptionalGas::from(op);
        let state_override = StateOverride::default();
        let args = ReservoirArgs {
            op: &optional_op,
            full_op: op,
            chain_spec,
            block_hash,
            state_override: &state_override,
            da_gas: 0,
            pvg_state,
            verification_gas_limit: op.verification_gas_limit(),
            paymaster_verification_gas_limit: op.paymaster_verification_gas_limit(),
        };
        let deadline = tokio::time::Instant::now() + self.settings.reservoir_trace_timeout;
        let reservoir = tokio::time::timeout_at(deadline, self.search_sponsored_reservoir(&args))
            .await
            .context("reservoir search for a sponsored op timed out")??;
        if let SponsoredReservoir::Reservoir(reservoir_gas) = reservoir {
            self.metrics.sponsored_reservoirs.increment(1);
            tracing::debug!("sponsored op needs a reservoir of {reservoir_gas}");
        }
        Ok(reservoir)
    }

    async fn search_sponsored_reservoir(
        &self,
        args: &ReservoirArgs<'_>,
    ) -> anyhow::Result<SponsoredReservoir> {
        let call_gas_limit = args.full_op.call_gas_limit();
        if self.reservoir_op_succeeds(args, 0, call_gas_limit).await? {
            return Ok(SponsoredReservoir::Metered);
        }
        let Some(state_gas) = self.simulate_state_gas(args).await? else {
            tracing::debug!("sponsored op fails with the most reservoir and call gas");
            return Ok(SponsoredReservoir::Fails);
        };
        let max_reservoir_gas = u128::from(self.settings.max_reservoir_gas);
        if state_gas > max_reservoir_gas {
            return Ok(SponsoredReservoir::Reservoir(state_gas));
        }
        let passes =
            |reservoir_gas| self.reservoir_op_succeeds(args, reservoir_gas, call_gas_limit);
        if !passes(max_reservoir_gas).await? {
            tracing::debug!(
                "sponsored op fails at its call gas limit {call_gas_limit} with the most reservoir"
            );
            return Ok(SponsoredReservoir::Fails);
        }
        let reservoir_gas = least_passing(state_gas, max_reservoir_gas, passes).await?;
        // State charged to the reservoir before the op runs, which the simulations cannot see: a
        // new EIP-7702 authority is applied by state override, not by processing the
        // authorization.
        Ok(SponsoredReservoir::Reservoir(
            reservoir_gas
                + args
                    .full_op
                    .authorization_state_gas(args.chain_spec, &args.pvg_state),
        ))
    }
}

#[async_trait::async_trait]
impl<P, E> crate::precheck::SponsoredReservoirEstimator<UserOperation> for ReservoirEstimator<P, E>
where
    P: EvmProvider,
    E: EntryPoint + SimulationProvider<UO = UserOperation>,
{
    async fn sponsored_reservoir_gas(
        &self,
        op: &UserOperation,
        chain_spec: &ChainSpec,
        block_hash: B256,
    ) -> anyhow::Result<SponsoredReservoir> {
        ReservoirEstimator::sponsored_reservoir_gas(self, op, chain_spec, block_hash).await
    }
}
