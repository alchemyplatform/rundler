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

use std::{ops::Add, sync::Arc, time::Instant};

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, SolInterface};
use rundler_contracts::v0_7::{
    CALL_GAS_ESTIMATION_PROXY_V0_7_DEPLOYED_BYTECODE,
    CallGasEstimationProxy::{
        CallGasEstimationProxyCalls, EstimateCallGasArgs, estimateCallGasCall, testCallGasCall,
    },
    VERIFICATION_GAS_ESTIMATION_HELPER_V0_7_DEPLOYED_BYTECODE,
    VerificationGasEstimationHelper::{
        EstimateGasArgs as ContractEstimateGasArgs, estimatePaymasterVerificationGasCall,
        estimateVerificationGasCall,
    },
};
use rundler_provider::{
    AccountOverride, DAGasProvider, EntryPoint, EvmProvider, FeeEstimator, ProviderResult,
    SimulationProvider, StateGasTrace, StateOverride, trace_call_state_gas,
};
use rundler_types::{
    GasEstimate, PvgState, UserOperation as _,
    chain::ChainSpec,
    v0_7::{UserOperation, UserOperationBuilder, UserOperationOptionalGas},
};
use rundler_utils::{guard_timer::CustomTimerGuard, math};
use tokio::{join, sync::Semaphore};
use tracing::instrument;

use super::{
    GasEstimationError, Metrics, Settings,
    estimate_verification_gas::{EstimateGasArgs, VerificationGasEstimatorSpecialization},
    state_gas::{find_execution_frame, reservoir_call_gas_limit, user_operation_succeeded},
};
use crate::{
    CallGasEstimator, CallGasEstimatorImpl, CallGasEstimatorSpecialization, MIN_CALL_GAS_LIMIT,
    VerificationGasEstimator, VerificationGasEstimatorImpl, gas,
};

/// Gas estimator for entry point v0.7
pub struct GasEstimator<P, E, VGE, PVGE, CGE, F> {
    chain_spec: ChainSpec,
    provider: P,
    entry_point: E,
    settings: Settings,
    fee_estimator: F,
    verification_gas_estimator: VGE,
    paymaster_verification_gas_estimator: PVGE,
    call_gas_estimator: CGE,
    metrics: Metrics,
    /// Bounds the reservoir-mode fallbacks running at once (each traces at up to the node's gas
    /// cap)
    reservoir_permits: Arc<Semaphore>,
}

#[async_trait::async_trait]
impl<P, E, VGE, PVGE, CGE, F> super::GasEstimator for GasEstimator<P, E, VGE, PVGE, CGE, F>
where
    P: EvmProvider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + DAGasProvider<UO = UserOperation>,
    VGE: VerificationGasEstimator<UO = UserOperation>,
    PVGE: VerificationGasEstimator<UO = UserOperation>,
    CGE: CallGasEstimator<UO = UserOperation>,
    F: FeeEstimator,
{
    type UserOperationOptionalGas = UserOperationOptionalGas;

    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.

    #[instrument(skip_all)]
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
        state_override: StateOverride,
    ) -> Result<GasEstimate, GasEstimationError> {
        let _timer = CustomTimerGuard::new(self.metrics.total_gas_estimate_ms.clone());
        self.check_provided_limits(&op)?;

        let Self {
            provider, settings, ..
        } = self;

        let agg = op
            .aggregator
            .map(|agg| {
                self.chain_spec
                    .get_signature_aggregator(&agg)
                    .ok_or(GasEstimationError::UnsupportedAggregator(agg))
            })
            .transpose()?;

        let (block_hash, _, block_timestamp) = provider
            .get_latest_block_hash_number_and_timestamp()
            .await
            .map_err(anyhow::Error::from)?;
        let chain_spec = self.chain_spec.for_bundle_inclusion_after(block_timestamp);

        let mut full_op = op
            .clone()
            .into_user_operation_builder(
                &chain_spec,
                settings.max_bundle_execution_gas,
                settings.max_verification_gas,
                settings.max_paymaster_verification_gas,
            )
            .pre_verification_gas(0)
            .build();
        if let Some(agg) = agg {
            full_op = full_op.transform_for_aggregator(
                agg.address(),
                agg.costs().clone(),
                agg.dummy_uo_signature().clone(),
            );
        }

        let random_op = op.random_fill(&chain_spec);
        let da_gas_future = gas::estimate_da_gas_with_fees(
            &chain_spec,
            &self.entry_point,
            &self.fee_estimator,
            &random_op,
            op.max_fee_per_gas,
            op.max_priority_fee_per_gas,
            block_hash.into(),
            self.metrics.pvg_estimate_ms.clone(),
        );

        let verification_gas_future = self.estimate_verification_gas(
            &op,
            &full_op,
            block_hash,
            &chain_spec,
            state_override.clone(),
        );

        let paymaster_verification_gas_future = self.estimate_paymaster_verification_gas(
            &op,
            &full_op,
            block_hash,
            state_override.clone(),
        );
        let call_gas_future =
            self.estimate_call_gas(&op, full_op.clone(), block_hash, state_override.clone());
        let pvg_state_future = gas::load_pvg_state(
            &chain_spec,
            provider,
            &self.entry_point,
            &full_op,
            Some(block_hash.into()),
        );

        // Not try_join! because then the output is nondeterministic if multiple calls fail.
        let (
            da_gas_result,
            verification_gas_limit_result,
            paymaster_verification_gas_limit_result,
            call_gas_limit_result,
            pvg_state_result,
        ) = join!(
            da_gas_future,
            verification_gas_future,
            paymaster_verification_gas_future,
            call_gas_future,
            pvg_state_future
        );

        let da_gas = da_gas_result.map_err(GasEstimationError::from)?;
        let pvg_state = pvg_state_result.map_err(anyhow::Error::from)?;
        let verification_gas_limit = verification_gas_limit_result?;
        let paymaster_verification_gas_limit = paymaster_verification_gas_limit_result?;

        // An op whose execution plus state gas does not fit under the 2^24 cap fails the
        // metered estimate; it may still fit in reservoir mode.
        let reservoir = self
            .reservoir_mode_possible(&op, &chain_spec, block_timestamp)
            .then(|| ReservoirArgs {
                op: &op,
                full_op: &full_op,
                chain_spec: &chain_spec,
                block_hash,
                state_override: &state_override,
                da_gas,
                pvg_state,
                verification_gas_limit,
                paymaster_verification_gas_limit,
            });
        let call_gas_limit = match call_gas_limit_result {
            Ok(call_gas_limit) => call_gas_limit,
            Err(error) => {
                return match reservoir {
                    Some(args) if may_need_reservoir(&error) => {
                        self.estimate_reservoir_mode(args, error).await
                    }
                    _ => Err(error),
                };
            }
        };

        // Calculate the final PVG now that we have all gas limits
        let pre_verification_gas = if op.pre_verification_gas.is_some_and(|pvg| pvg != 0) {
            op.pre_verification_gas.unwrap()
        } else {
            self.base_pre_verification_gas(
                &op,
                &chain_spec,
                da_gas,
                &pvg_state,
                verification_gas_limit,
                paymaster_verification_gas_limit,
                call_gas_limit,
            )
        };

        // check the total gas limit
        let op_with_gas = UserOperationBuilder::from_uo(full_op.clone(), &chain_spec)
            .pre_verification_gas(pre_verification_gas)
            .call_gas_limit(call_gas_limit)
            .verification_gas_limit(verification_gas_limit)
            .paymaster_verification_gas_limit(paymaster_verification_gas_limit)
            .build();

        // require that this can fit in a bundle of size 1
        let gas_limit = op_with_gas.bundle_computation_gas_limit(&chain_spec, Some(1));
        if gas_limit > self.settings.max_bundle_execution_gas {
            let error = GasEstimationError::GasTotalTooLarge(
                gas_limit,
                self.settings.max_bundle_execution_gas,
            );
            return match reservoir {
                Some(args) => self.estimate_reservoir_mode(args, error).await,
                None => Err(error),
            };
        } else if op_with_gas.calldata_floor_gas_limit(&chain_spec)
            > self.settings.max_bundle_execution_gas
        {
            return Err(GasEstimationError::GasTotalTooLarge(
                op_with_gas.calldata_floor_gas_limit(&chain_spec),
                self.settings.max_bundle_execution_gas,
            ));
        }

        // if pvg was originally provided, use it, otherwise calculate it using the gas limits from above
        let pre_verification_gas = if op.pre_verification_gas.is_some_and(|pvg| pvg != 0) {
            pre_verification_gas
        } else {
            rundler_types::increase_required_pvg_with_calldata_floor_gas(
                &op_with_gas,
                pre_verification_gas - da_gas,
                da_gas,
                op.max_fill(&chain_spec)
                    .calldata_floor_gas_limit(&chain_spec),
                self.settings
                    .verification_gas_limit_efficiency_reject_threshold,
            )
        };

        Ok(GasEstimate {
            pre_verification_gas,
            call_gas_limit,
            verification_gas_limit,
            paymaster_verification_gas_limit: op
                .paymaster
                .map(|_| paymaster_verification_gas_limit),
        })
    }
}

impl<P, E, F>
    GasEstimator<
        P,
        E,
        VerificationGasEstimatorImpl<VerificationGasEstimatorSpecializationV07<E>, P>,
        VerificationGasEstimatorImpl<PaymasterVerificationGasEstimatorSpecializationV07<E>, P>,
        CallGasEstimatorImpl<E, CallGasEstimatorSpecializationV07>,
        F,
    >
where
    P: EvmProvider + Clone,
    E: EntryPoint
        + SimulationProvider<UO = UserOperation>
        + DAGasProvider<UO = UserOperation>
        + Clone,
    F: FeeEstimator,
{
    /// Create a new gas estimator
    pub fn new(
        chain_spec: ChainSpec,
        provider: P,
        entry_point: E,
        settings: Settings,
        fee_estimator: F,
    ) -> Self {
        if let Some(err) = settings.validate() {
            panic!("Invalid gas estimator settings: {}", err);
        }

        let verification_gas_estimator = VerificationGasEstimatorImpl::new(
            settings,
            provider.clone(),
            VerificationGasEstimatorSpecializationV07 {
                entry_point: entry_point.clone(),
            },
        );

        let paymaster_verification_gas_estimator = VerificationGasEstimatorImpl::new(
            settings,
            provider.clone(),
            PaymasterVerificationGasEstimatorSpecializationV07 {
                entry_point: entry_point.clone(),
            },
        );

        let call_gas_estimator = CallGasEstimatorImpl::new(
            entry_point.clone(),
            settings,
            CallGasEstimatorSpecializationV07 {
                chain_spec: chain_spec.clone(),
                simulations_bytecode: entry_point.get_simulations_bytecode().clone(),
            },
        );
        Self {
            chain_spec,
            provider,
            entry_point,
            settings,
            fee_estimator,
            verification_gas_estimator,
            paymaster_verification_gas_estimator,
            call_gas_estimator,
            metrics: Metrics::default(),
            reservoir_permits: Arc::new(Semaphore::new(
                settings.max_concurrent_reservoir_estimations,
            )),
        }
    }
}

impl<P, E, VGE, PVGE, CGE, F> GasEstimator<P, E, VGE, PVGE, CGE, F>
where
    P: EvmProvider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + DAGasProvider<UO = UserOperation>,
    VGE: VerificationGasEstimator<UO = UserOperation>,
    PVGE: VerificationGasEstimator<UO = UserOperation>,
    CGE: CallGasEstimator<UO = UserOperation>,
    F: FeeEstimator,
{
    fn check_provided_limits(
        &self,
        optional_op: &UserOperationOptionalGas,
    ) -> Result<(), GasEstimationError> {
        if let Some(vl) = optional_op.verification_gas_limit
            && vl > self.settings.max_verification_gas
        {
            return Err(GasEstimationError::GasFieldTooLarge(
                "verificationGasLimit",
                self.settings.max_verification_gas,
            ));
        }
        if let Some(vl) = optional_op.paymaster_verification_gas_limit
            && vl > self.settings.max_verification_gas
        {
            return Err(GasEstimationError::GasFieldTooLarge(
                "paymasterVerificationGasLimit",
                self.settings.max_verification_gas,
            ));
        }
        if let Some(cl) = optional_op.call_gas_limit
            && cl > self.settings.max_bundle_execution_gas
        {
            return Err(GasEstimationError::GasFieldTooLarge(
                "callGasLimit",
                self.settings.max_bundle_execution_gas,
            ));
        }
        if let Some(cl) = optional_op.paymaster_post_op_gas_limit
            && cl > self.settings.max_bundle_execution_gas
        {
            return Err(GasEstimationError::GasFieldTooLarge(
                "paymasterPostOpGasLimit",
                self.settings.max_bundle_execution_gas,
            ));
        }

        Ok(())
    }

    /// True if a failed metered estimate of `op` may be retried in reservoir mode: Glamsterdam
    /// is active, and rundler estimates the call gas limit and PVG itself.
    fn reservoir_mode_possible(
        &self,
        op: &UserOperationOptionalGas,
        chain_spec: &ChainSpec,
        block_timestamp: u64,
    ) -> bool {
        chain_spec.reservoir_mode_enabled_at(block_timestamp)
            && self.settings.max_reservoir_gas > 0
            && op.call_gas_limit.is_none_or(|limit| limit == 0)
            && op.pre_verification_gas.is_none_or(|pvg| pvg == 0)
            && op.aggregator.is_none()
    }

    /// Required PVG for an op with these limits, before the calldata floor top-up
    #[allow(clippy::too_many_arguments)]
    fn base_pre_verification_gas(
        &self,
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

    /// Estimates `args.op` in reservoir mode after its metered estimate failed with
    /// `metered_error`, which is returned if the op does not need (or cannot be measured in)
    /// reservoir mode.
    ///
    /// The op's state gas `S` is traced on a copy with call gas and postOp limits far above
    /// execution plus state, since calls have no state-gas reservoir. Its call gas limit then
    /// covers execution only, VGL stays the metered estimate, and PVG carries `S`. See
    /// `test/pvg-calibration/docs/reservoir-mode-plan.md`.
    #[instrument(skip_all)]
    async fn estimate_reservoir_mode(
        &self,
        args: ReservoirArgs<'_>,
        metered_error: GasEstimationError,
    ) -> Result<GasEstimate, GasEstimationError> {
        self.metrics.reservoir_fallbacks.increment(1);
        let Ok(_permit) = self.reservoir_permits.try_acquire() else {
            self.metrics.reservoir_fallbacks_busy.increment(1);
            return Err(metered_error);
        };

        let measured = {
            let _timer = CustomTimerGuard::new(self.metrics.reservoir_trace_ms.clone());
            tokio::time::timeout(
                self.settings.reservoir_trace_timeout,
                self.measure_state_gas(&args),
            )
            .await
        };
        let measured = match measured {
            Ok(Ok(Some(measured))) => measured,
            // The op fails even with room for its state: a genuine failure.
            Ok(Ok(None)) => return Err(metered_error),
            Ok(Err(error)) => {
                tracing::warn!("reservoir-mode state-gas trace failed: {error:#}");
                return Err(metered_error);
            }
            Err(_) => {
                tracing::warn!("reservoir-mode state-gas trace timed out");
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
        let state_gas = measured.state_gas;
        let max_reservoir_gas = u128::from(self.settings.max_reservoir_gas);
        if state_gas > max_reservoir_gas {
            return Err(GasEstimationError::StateGasTooLarge(
                state_gas,
                max_reservoir_gas,
            ));
        }
        let call_gas_limit =
            reservoir_call_gas_limit(measured.execution_frame_gas, measured.execution_state_gas);

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
        let base_pvg = self.base_pre_verification_gas(
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
        let gas_limit = op_with_gas.bundle_computation_gas_limit(chain_spec, Some(1));
        if gas_limit > max_bundle_execution_gas {
            return Err(GasEstimationError::GasTotalTooLarge(
                gas_limit,
                max_bundle_execution_gas,
            ));
        }
        // An op whose state fits under the cap next to its computation gas needs no reservoir;
        // admission would put it on the metered path.
        let threshold =
            gas::reservoir_threshold(&op_with_gas, chain_spec, max_bundle_execution_gas);
        if state_gas < threshold {
            tracing::debug!(
                "reservoir mode not needed: state gas {state_gas} below threshold {threshold}"
            );
            return Err(metered_error);
        }

        let base_pvg = rundler_types::increase_required_pvg_with_calldata_floor_gas(
            &op_with_gas,
            base_pvg - da_gas,
            da_gas,
            op.max_fill(chain_spec).calldata_floor_gas_limit(chain_spec),
            self.settings
                .verification_gas_limit_efficiency_reject_threshold,
        );
        self.metrics.reservoir_estimates.increment(1);
        self.metrics.reservoir_state_gas.record(state_gas as f64);
        tracing::debug!(
            "reservoir-mode estimate: state gas {state_gas}, call gas limit {call_gas_limit}"
        );

        Ok(GasEstimate {
            pre_verification_gas: base_pvg + state_gas,
            call_gas_limit,
            verification_gas_limit,
            paymaster_verification_gas_limit: op
                .paymaster
                .map(|_| paymaster_verification_gas_limit),
        })
    }

    /// Traces the op's state gas on a max-limit copy, twice: as is, and with no call gas, so
    /// execution's state can be told apart. `None` if the copy fails, i.e. the op fails even
    /// with room for its state.
    async fn measure_state_gas(
        &self,
        args: &ReservoirArgs<'_>,
    ) -> anyhow::Result<Option<MeasuredStateGas>> {
        let max_reservoir_gas = u128::from(self.settings.max_reservoir_gas);
        let has_paymaster = args.full_op.paymaster().is_some();
        // Fee 0 skips the deposit debit, which `deposit_transfer_overhead` already covers for
        // self-paying ops. A paymaster's debit is measured at 1 wei, which stays well within any
        // deposit despite the large limits (AA31 otherwise).
        let fee = u128::from(has_paymaster);
        let call_gas = self.settings.max_bundle_execution_gas + max_reservoir_gas;
        let post_op_gas = if has_paymaster {
            args.op.paymaster_post_op_gas_limit.unwrap_or(0) + max_reservoir_gas
        } else {
            0
        };
        // VGL is not raised: the metered estimate already covers validation state.
        let copy = |call_gas_limit: u128| {
            UserOperationBuilder::from_uo(args.full_op.clone(), args.chain_spec)
                .verification_gas_limit(args.verification_gas_limit)
                .paymaster_verification_gas_limit(args.paymaster_verification_gas_limit)
                .call_gas_limit(call_gas_limit)
                .paymaster_post_op_gas_limit(post_op_gas)
                .max_fee_per_gas(fee)
                .max_priority_fee_per_gas(fee)
                .pre_verification_gas(0)
                .build()
        };
        // The entry point calls `innerHandleOp` (keeping 1/64), which then requires
        // `gasleft() * 63/64` to cover the call and postOp limits (AA95 otherwise).
        let limits = args.verification_gas_limit
            + args.paymaster_verification_gas_limit
            + call_gas
            + post_op_gas;
        let trace_gas: u64 = (limits * 64 * 64 / (63 * 63) + RESERVOIR_TRACE_GAS_OVERHEAD)
            .try_into()
            .unwrap_or(u64::MAX);

        let (full, no_call) = join!(
            self.trace_reservoir_copy(copy(call_gas), trace_gas, args),
            self.trace_reservoir_copy(copy(0), trace_gas, args),
        );
        let full = full?;
        let entry_point = *self.entry_point.address();
        if let Some(error) = full.error() {
            tracing::debug!(
                "reservoir-mode copy reverted: {error}, reason {:?}, output {:?}",
                full.frame.revert_reason,
                full.frame.output
            );
            return Ok(None);
        }
        let op_success = user_operation_succeeded(&full.frame, entry_point);
        if op_success != Some(true) {
            tracing::debug!("reservoir-mode copy did not succeed: {op_success:?}");
            return Ok(None);
        }
        let no_call = no_call?;
        if let Some(error) = no_call.error() {
            tracing::debug!("reservoir-mode copy without call gas reverted: {error}");
            return Ok(None);
        }
        let execution_frame = find_execution_frame(&full.frame, entry_point, args.full_op.sender())
            .ok_or_else(|| anyhow::anyhow!("state-gas trace has no execution call"))?;

        Ok(Some(MeasuredStateGas {
            state_gas: u128::from(full.state_gas_used),
            execution_state_gas: u128::from(
                full.state_gas_used.saturating_sub(no_call.state_gas_used),
            ),
            execution_frame_gas: execution_frame.gas_used.saturating_to(),
        }))
    }

    async fn trace_reservoir_copy(
        &self,
        op: UserOperation,
        gas: u64,
        args: &ReservoirArgs<'_>,
    ) -> ProviderResult<StateGasTrace> {
        let (tx, simulation_override) = self
            .entry_point
            .get_state_gas_simulate_handle_op_call(op, false, gas)?;
        let mut state_override = args.state_override.clone();
        state_override.extend(simulation_override);
        trace_call_state_gas(
            &self.provider,
            tx,
            Some(args.block_hash.into()),
            state_override,
        )
        .await
    }

    #[instrument(skip_all)]
    async fn estimate_verification_gas(
        &self,
        optional_op: &UserOperationOptionalGas,
        full_op: &UserOperation,
        block_hash: B256,
        chain_spec: &ChainSpec,
        state_override: StateOverride,
    ) -> Result<u128, GasEstimationError> {
        // if set and non-zero, don't estimate
        if let Some(vl) = optional_op.verification_gas_limit
            && vl != 0
        {
            // No need to do an extra simulation here, if the user provides a value that is
            // insufficient it will cause a revert during call gas estimation (or simulation).
            return Ok(vl);
        }

        let _timer = CustomTimerGuard::new(self.metrics.vgl_estimate_ms.clone());
        let now = Instant::now();

        let verification_gas_limit = self
            .verification_gas_estimator
            .estimate_verification_gas(full_op, block_hash, state_override)
            .await?;
        let verification_gas_limit = if full_op.paymaster().is_none() {
            verification_gas_limit + chain_spec.deposit_transfer_overhead()
        } else {
            verification_gas_limit
        };

        let buffered_verification_gas_limit = math::increase_by_percent(
            verification_gas_limit,
            super::VERIFICATION_GAS_BUFFER_PERCENT,
        );
        super::record_clamped_estimate(
            *self.entry_point.address(),
            "verification",
            buffered_verification_gas_limit,
            self.settings.max_verification_gas,
        );
        let verification_gas_limit =
            buffered_verification_gas_limit.min(self.settings.max_verification_gas);

        tracing::debug!(
            "verification_gas_limit: {} took {:?}ms",
            verification_gas_limit,
            now.elapsed().as_millis()
        );

        Ok(verification_gas_limit)
    }

    #[instrument(skip_all)]
    async fn estimate_paymaster_verification_gas(
        &self,
        optional_op: &UserOperationOptionalGas,
        full_op: &UserOperation,
        block_hash: B256,
        state_override: StateOverride,
    ) -> Result<u128, GasEstimationError> {
        // If not using paymaster, return zero, else if set and non-zero, don't estimate and return value
        if optional_op.paymaster.is_none() {
            return Ok(0);
        }

        if let Some(pvl) = optional_op.paymaster_verification_gas_limit
            && pvl != 0
        {
            return Ok(pvl);
        }

        let _timer = CustomTimerGuard::new(self.metrics.pvgl_estimate_ms.clone());
        let now = Instant::now();

        let paymaster_verification_gas_limit = self
            .paymaster_verification_gas_estimator
            .estimate_verification_gas(full_op, block_hash, state_override)
            .await?;

        let buffered_paymaster_verification_gas_limit = math::increase_by_percent(
            paymaster_verification_gas_limit,
            super::VERIFICATION_GAS_BUFFER_PERCENT,
        );
        super::record_clamped_estimate(
            *self.entry_point.address(),
            "paymaster_verification",
            buffered_paymaster_verification_gas_limit,
            self.settings.max_verification_gas,
        );
        let paymaster_verification_gas_limit =
            buffered_paymaster_verification_gas_limit.min(self.settings.max_verification_gas);

        tracing::debug!(
            "paymaster_verification_gas_limit: {} took {:?}ms",
            paymaster_verification_gas_limit,
            now.elapsed().as_millis()
        );

        Ok(paymaster_verification_gas_limit)
    }

    #[instrument(skip_all)]
    async fn estimate_call_gas(
        &self,
        optional_op: &UserOperationOptionalGas,
        full_op: UserOperation,
        block_hash: B256,
        state_override: StateOverride,
    ) -> Result<u128, GasEstimationError> {
        let _timer = CustomTimerGuard::new(self.metrics.cgl_estimate_ms.clone());
        // if set and non-zero, don't estimate
        if let Some(cl) = optional_op.call_gas_limit
            && cl != 0
        {
            // The user provided a non-zero value, simulate once
            self.call_gas_estimator
                .simulate_handle_op_with_result(full_op, block_hash, state_override)
                .await?;
            return Ok(cl);
        }

        let call_gas_limit = self
            .call_gas_estimator
            .estimate_call_gas(full_op, block_hash, state_override)
            .await?;

        // Add a buffer to the call gas limit and clamp
        let buffered_call_gas_limit = call_gas_limit.add(super::CALL_GAS_BUFFER_VALUE);
        super::record_clamped_estimate(
            *self.entry_point.address(),
            "call",
            buffered_call_gas_limit,
            self.settings.max_bundle_execution_gas,
        );
        let call_gas_limit = buffered_call_gas_limit
            .clamp(MIN_CALL_GAS_LIMIT, self.settings.max_bundle_execution_gas);

        Ok(call_gas_limit)
    }
}

/// Gas a reservoir-mode trace gets on top of the op's limits, for the entry point's own work
const RESERVOIR_TRACE_GAS_OVERHEAD: u128 = 1_000_000;

/// What a reservoir-mode fallback needs from the metered estimate it follows
struct ReservoirArgs<'a> {
    op: &'a UserOperationOptionalGas,
    full_op: &'a UserOperation,
    chain_spec: &'a ChainSpec,
    block_hash: B256,
    state_override: &'a StateOverride,
    da_gas: u128,
    pvg_state: PvgState,
    verification_gas_limit: u128,
    paymaster_verification_gas_limit: u128,
}

/// An op's state gas, traced on a max-limit copy
struct MeasuredStateGas {
    /// `S`: the op's net state gas
    state_gas: u128,
    /// The part of `S` created by execution
    execution_state_gas: u128,
    /// Gas used by the sender's execution call, which includes its state
    execution_frame_gas: u128,
}

/// True if a metered estimate failed in a way that more gas could fix. A revert with room for
/// the op's state (`None` from `measure_state_gas`) is still returned as this error.
fn may_need_reservoir(error: &GasEstimationError) -> bool {
    matches!(
        error,
        GasEstimationError::RevertInCallWithMessage(_)
            | GasEstimationError::RevertInCallWithBytes(_)
            | GasEstimationError::CallGasLimitTooLow(_)
            | GasEstimationError::GasTotalTooLarge(_, _)
    )
}

/// Implementation of functions that specialize the call gas estimator to the
/// v0.7 entry point.
#[derive(Debug, Clone)]
pub struct CallGasEstimatorSpecializationV07 {
    chain_spec: ChainSpec,
    simulations_bytecode: Bytes,
}

impl CallGasEstimatorSpecialization for CallGasEstimatorSpecializationV07 {
    type UO = UserOperation;

    fn add_proxy_to_overrides(&self, ep_to_override: Address, state_override: &mut StateOverride) {
        // For an explanation of what's going on here, see the comment at the
        // top of `CallGasEstimationProxy.sol`.
        // Use a random address for the moved entry point so that users can't
        // intentionally get bad estimates by interacting with the hardcoded
        // address.
        let moved_entry_point_address = Address::random();

        state_override.insert(
            moved_entry_point_address,
            AccountOverride {
                code: Some(self.simulations_bytecode.clone()),
                ..Default::default()
            },
        );

        state_override.insert(
            ep_to_override,
            AccountOverride {
                code: Some(estimation_proxy_bytecode_with_target(
                    moved_entry_point_address,
                )),
                ..Default::default()
            },
        );
    }

    fn get_op_with_no_call_gas(&self, op: Self::UO) -> Self::UO {
        // Don't clear the paymaster as verification may check that the paymaster is
        // some expected address. The modified entry point simulations will skip running
        // postOp, so the paymaster will not be called beyond its validation function.
        UserOperationBuilder::from_uo(op, &self.chain_spec)
            .call_gas_limit(0)
            .max_fee_per_gas(0)
            .build()
    }

    fn get_estimate_call_gas_calldata(
        &self,
        callless_op: Self::UO,
        min_gas: u128,
        max_gas: u128,
        allowed_error_pct: u128,
        is_continuation: bool,
    ) -> Bytes {
        let call = CallGasEstimationProxyCalls::estimateCallGas(estimateCallGasCall {
            args: EstimateCallGasArgs {
                userOp: callless_op.pack(),
                minGas: U256::from(min_gas),
                maxGas: U256::from(max_gas),
                allowedErrorPct: U256::from(allowed_error_pct),
                isContinuation: is_continuation,
            },
        });

        call.abi_encode().into()
    }

    fn get_test_call_gas_calldata(&self, callless_op: Self::UO, call_gas_limit: u128) -> Bytes {
        let call = CallGasEstimationProxyCalls::testCallGas(testCallGasCall {
            userOp: callless_op.pack(),
            callGasLimit: U256::from(call_gas_limit),
        });

        call.abi_encode().into()
    }
}

/// Offset at which the proxy target address appears in the proxy bytecode. Must
/// be updated whenever `CallGasEstimationProxy.sol` changes.
///
/// The easiest way to get the updated value is to run this module's tests. The
/// failure will tell you the new value.
const PROXY_TARGET_OFFSET: usize = 163;

// Replaces the address of the proxy target where it appears in the proxy
// bytecode so we don't need the same fixed address every time.
fn estimation_proxy_bytecode_with_target(target: Address) -> Bytes {
    let mut vec = CALL_GAS_ESTIMATION_PROXY_V0_7_DEPLOYED_BYTECODE.to_vec();
    let bytes: [u8; 20] = target.into();
    vec[PROXY_TARGET_OFFSET..PROXY_TARGET_OFFSET + 20].copy_from_slice(&bytes);
    vec.into()
}

fn construct_verification_args(
    entry_point: Address,
    op: UserOperation,
    args: &EstimateGasArgs,
) -> ContractEstimateGasArgs {
    ContractEstimateGasArgs {
        entryPointSimulations: entry_point,
        userOp: op.pack(),
        minGas: U256::from(args.min_gas),
        maxGas: U256::from(args.max_gas),
        allowedErrorPct: U256::from(args.allowed_error_pct),
        isContinuation: args.is_continuation,
        constantFee: U256::from(args.constant_fee),
    }
}

fn add_proxy_to_overrides(
    entry_point: Address,
    simulations_bytecode: Bytes,
    to_override: Address,
    state_override: &mut StateOverride,
) {
    state_override.insert(
        to_override,
        AccountOverride {
            code: Some(VERIFICATION_GAS_ESTIMATION_HELPER_V0_7_DEPLOYED_BYTECODE.clone()),
            ..Default::default()
        },
    );
    state_override.insert(
        entry_point,
        AccountOverride {
            code: Some(simulations_bytecode),
            ..Default::default()
        },
    );
}

fn decode_validation_revert<EP: SimulationProvider>(revert_data: &Bytes) -> GasEstimationError {
    match EP::decode_simulate_handle_ops_revert(revert_data) {
        Ok(Ok(res)) => GasEstimationError::Other(anyhow::anyhow!(
            "unexpected result from simulate_handle_ops: {:?}",
            res
        )),
        Ok(Err(e)) => GasEstimationError::RevertInValidation(e),
        Err(e) => GasEstimationError::ProviderError(e),
    }
}

/// Specialization for verification gas estimation
#[derive(Clone)]
pub struct VerificationGasEstimatorSpecializationV07<EP> {
    entry_point: EP,
}

impl<EP> VerificationGasEstimatorSpecialization for VerificationGasEstimatorSpecializationV07<EP>
where
    EP: EntryPoint + SimulationProvider,
{
    type UO = UserOperation;

    fn add_proxy_to_overrides(&self, to_override: Address, state_override: &mut StateOverride) {
        add_proxy_to_overrides(
            *self.entry_point.address(),
            self.entry_point.get_simulations_bytecode().clone(),
            to_override,
            state_override,
        );
    }

    fn get_call(&self, op: Self::UO, args: &EstimateGasArgs) -> Bytes {
        estimateVerificationGasCall {
            args: construct_verification_args(*self.entry_point.address(), op, args),
        }
        .abi_encode()
        .into()
    }

    fn decode_revert(&self, revert_data: &Bytes) -> GasEstimationError {
        decode_validation_revert::<EP>(revert_data)
    }

    fn entry_point(&self) -> Address {
        *self.entry_point.address()
    }
}

/// Specialization for paymaster verification gas estimation
#[derive(Clone)]
pub struct PaymasterVerificationGasEstimatorSpecializationV07<EP> {
    entry_point: EP,
}

impl<EP> VerificationGasEstimatorSpecialization
    for PaymasterVerificationGasEstimatorSpecializationV07<EP>
where
    EP: EntryPoint + SimulationProvider,
{
    type UO = UserOperation;

    fn add_proxy_to_overrides(&self, to_override: Address, state_override: &mut StateOverride) {
        add_proxy_to_overrides(
            *self.entry_point.address(),
            self.entry_point.get_simulations_bytecode().clone(),
            to_override,
            state_override,
        );
    }

    fn get_call(&self, op: Self::UO, args: &EstimateGasArgs) -> Bytes {
        estimatePaymasterVerificationGasCall {
            args: construct_verification_args(*self.entry_point.address(), op, args),
        }
        .abi_encode()
        .into()
    }

    fn decode_revert(&self, revert_data: &Bytes) -> GasEstimationError {
        decode_validation_revert::<EP>(revert_data)
    }

    fn entry_point(&self) -> Address {
        *self.entry_point.address()
    }

    fn estimated_field(&self) -> &'static str {
        "paymaster_verification"
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::{U256, hex};
    use alloy_sol_types::{Revert, SolError, SolEvent, SolValue};
    use rundler_contracts::{
        common::EstimationTypes::TestCallGasResult,
        v0_7::ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE,
    };
    use rundler_provider::{
        BlockId, ExecutionResult, MockEntryPointV0_7, MockEvmProvider, MockFeeEstimator,
        TransactionRequest,
    };
    use rundler_types::{EntryPointVersion, chain::ForkActivation, v0_7::UserOperationOptionalGas};

    use super::*;
    use crate::{
        GasEstimator as _, estimation::estimate_call_gas::PROXY_IMPLEMENTATION_ADDRESS_MARKER,
    };

    // Alises for complex types (which also satisfy Clippy)
    type VerificationGasEstimatorWithMocks = VerificationGasEstimatorImpl<
        VerificationGasEstimatorSpecializationV07<Arc<MockEntryPointV0_7>>,
        Arc<MockEvmProvider>,
    >;
    type PaymasterVerificationGasEstimatorWithMocks = VerificationGasEstimatorImpl<
        PaymasterVerificationGasEstimatorSpecializationV07<Arc<MockEntryPointV0_7>>,
        Arc<MockEvmProvider>,
    >;

    type CallGasEstimatorWithMocks =
        CallGasEstimatorImpl<Arc<MockEntryPointV0_7>, CallGasEstimatorSpecializationV07>;
    type GasEstimatorWithMocks = GasEstimator<
        Arc<MockEvmProvider>,
        Arc<MockEntryPointV0_7>,
        VerificationGasEstimatorWithMocks,
        PaymasterVerificationGasEstimatorWithMocks,
        CallGasEstimatorWithMocks,
        MockFeeEstimator,
    >;

    fn create_base_config() -> (MockEntryPointV0_7, MockEvmProvider) {
        let mut entry = MockEntryPointV0_7::new();
        let provider = MockEvmProvider::new();

        // Fill in concrete implementations of call data and
        // `simulation_should_revert`
        entry.expect_simulation_should_revert().return_const(true);

        entry.expect_address().return_const(Address::ZERO);
        entry
            .expect_get_simulations_bytecode()
            .return_const(ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE.clone());

        (entry, provider)
    }

    fn create_custom_estimator(
        chain_spec: ChainSpec,
        provider: MockEvmProvider,
        entry: MockEntryPointV0_7,
        settings: Settings,
    ) -> GasEstimatorWithMocks {
        let provider = Arc::new(provider);
        GasEstimator::new(
            chain_spec.clone(),
            Arc::clone(&provider),
            Arc::new(entry),
            settings,
            MockFeeEstimator::new(),
        )
    }

    const TEST_MAX_GAS_LIMITS: u128 = 10000000000;

    fn create_estimator(
        entry: MockEntryPointV0_7,
        provider: MockEvmProvider,
    ) -> (GasEstimatorWithMocks, Settings) {
        let settings = Settings {
            max_verification_gas: TEST_MAX_GAS_LIMITS,
            max_bundle_execution_gas: TEST_MAX_GAS_LIMITS,
            max_gas_estimation_gas: TEST_MAX_GAS_LIMITS.try_into().unwrap(),
            max_paymaster_verification_gas: TEST_MAX_GAS_LIMITS,
            max_paymaster_post_op_gas: TEST_MAX_GAS_LIMITS,
            verification_estimation_gas_fee: 1_000_000_000_000,
            verification_gas_limit_efficiency_reject_threshold: 0.5,
            verification_gas_allowed_error_pct: 15,
            call_gas_allowed_error_pct: 15,
            max_gas_estimation_rounds: 3,
            max_reservoir_gas: 60_000_000,
            reservoir_trace_timeout: std::time::Duration::from_secs(10),
            max_concurrent_reservoir_estimations: 4,
        };
        let estimator = create_custom_estimator(ChainSpec::default(), provider, entry, settings);
        (estimator, settings)
    }

    fn demo_user_op_optional_gas(pvg: Option<u128>) -> UserOperationOptionalGas {
        UserOperationOptionalGas {
            sender: Address::ZERO,
            nonce: U256::ZERO,
            call_data: Bytes::new(),
            call_gas_limit: None,
            verification_gas_limit: None,
            pre_verification_gas: pvg,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            signature: Bytes::new(),

            paymaster: None,
            paymaster_data: Bytes::new(),
            paymaster_verification_gas_limit: None,
            paymaster_post_op_gas_limit: None,

            factory: None,
            factory_data: Bytes::new(),
            eip7702_auth_address: None,
            aggregator: None,
            paymaster_signature: None,

            entry_point_version: EntryPointVersion::V0_7,
        }
    }

    #[tokio::test]
    async fn test_vgl_over_max() {
        let (entry, provider) = create_base_config();
        let (estimator, _) = create_estimator(entry, provider);

        let mut optional_op = demo_user_op_optional_gas(Some(10000));
        optional_op.verification_gas_limit = Some(TEST_MAX_GAS_LIMITS + 1);

        let estimation = estimator
            .estimate_op_gas(optional_op, StateOverride::default())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            estimation,
            GasEstimationError::GasFieldTooLarge("verificationGasLimit", TEST_MAX_GAS_LIMITS)
        ));
    }

    #[tokio::test]
    async fn test_pgl_over_max() {
        let (entry, provider) = create_base_config();
        let (estimator, _) = create_estimator(entry, provider);

        let mut optional_op = demo_user_op_optional_gas(Some(10000));
        optional_op.paymaster_verification_gas_limit = Some(TEST_MAX_GAS_LIMITS + 1);

        let estimation = estimator
            .estimate_op_gas(optional_op, StateOverride::default())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            estimation,
            GasEstimationError::GasFieldTooLarge(
                "paymasterVerificationGasLimit",
                TEST_MAX_GAS_LIMITS
            )
        ));
    }

    #[tokio::test]
    async fn test_cgl_over_max() {
        let (entry, provider) = create_base_config();
        let (estimator, _) = create_estimator(entry, provider);

        let mut optional_op = demo_user_op_optional_gas(Some(10000));
        optional_op.call_gas_limit = Some(TEST_MAX_GAS_LIMITS + 1);

        let estimation = estimator
            .estimate_op_gas(optional_op, StateOverride::default())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            estimation,
            GasEstimationError::GasFieldTooLarge("callGasLimit", TEST_MAX_GAS_LIMITS)
        ));
    }

    #[tokio::test]
    async fn test_postop_over_max() {
        let (entry, provider) = create_base_config();
        let (estimator, _) = create_estimator(entry, provider);

        let mut optional_op = demo_user_op_optional_gas(Some(10000));
        optional_op.paymaster_post_op_gas_limit = Some(TEST_MAX_GAS_LIMITS + 1);

        let estimation = estimator
            .estimate_op_gas(optional_op, StateOverride::default())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            estimation,
            GasEstimationError::GasFieldTooLarge("paymasterPostOpGasLimit", TEST_MAX_GAS_LIMITS)
        ));
    }

    /// Gas estimation with Glamsterdam pricing and a mocked sender deposit: the gas limits are
    /// provided, PVG is left to the estimator.
    async fn glamsterdam_estimated_pvg(
        sender_deposit: U256,
        charge_gas_limit_via_pvg: bool,
    ) -> u128 {
        let (mut entry, mut provider) = create_base_config();
        provider
            .expect_get_latest_block_hash_number_and_timestamp()
            .returning(|| Ok((B256::ZERO, 0, 0)));
        entry
            .expect_simulate_handle_op_estimate_gas()
            .returning(move |_a, _b, _c, _d, _e| {
                Ok(Ok(ExecutionResult {
                    target_result: TestCallGasResult {
                        success: true,
                        gasUsed: U256::ZERO,
                        revertData: Bytes::new(),
                    }
                    .abi_encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });
        entry
            .expect_balance_of()
            .returning(move |_, _| Ok(sender_deposit));

        let (base_entry, base_provider) = create_base_config();
        let (_, settings) = create_estimator(base_entry, base_provider);
        let chain_spec = ChainSpec {
            glamsterdam_activation: rundler_types::chain::ForkActivation::Genesis,
            charge_gas_limit_via_pvg,
            ..ChainSpec::default()
        };
        let estimator = create_custom_estimator(chain_spec, provider, entry, settings);

        let mut optional_op = demo_user_op_optional_gas(None);
        optional_op.call_gas_limit = Some(10000);
        optional_op.verification_gas_limit = Some(10000);

        estimator
            .estimate_op_gas(optional_op, StateOverride::default())
            .await
            .unwrap()
            .pre_verification_gas
    }

    #[tokio::test]
    async fn test_glamsterdam_pvg_prices_zero_sender_deposit() {
        let funded_deposit = U256::from(1_000_000_000_000_000_000_u128);
        // Also when the gas limits are charged through PVG.
        for charge_gas_limit_via_pvg in [false, true] {
            let zero = glamsterdam_estimated_pvg(U256::ZERO, charge_gas_limit_via_pvg).await;
            let funded = glamsterdam_estimated_pvg(funded_deposit, charge_gas_limit_via_pvg).await;
            assert_eq!(zero - funded, 97_920);
        }
    }

    #[tokio::test]
    async fn test_return_provided_limits() {
        let (mut entry, mut provider) = create_base_config();

        provider
            .expect_get_latest_block_hash_number_and_timestamp()
            .returning(|| Ok((B256::ZERO, 0, 0)));

        entry
            .expect_simulate_handle_op_estimate_gas()
            .returning(move |_a, _b, _c, _d, _e| {
                Ok(Ok(ExecutionResult {
                    target_result: TestCallGasResult {
                        success: true,
                        gasUsed: U256::ZERO,
                        revertData: Bytes::new(),
                    }
                    .abi_encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });

        let (estimator, _) = create_estimator(entry, provider);

        let mut optional_op = demo_user_op_optional_gas(Some(10000));
        optional_op.call_gas_limit = Some(10000);
        optional_op.verification_gas_limit = Some(10000);
        optional_op.paymaster = Some(Address::random());
        optional_op.paymaster_verification_gas_limit = Some(10000);
        optional_op.paymaster_post_op_gas_limit = Some(10000);

        let estimation = estimator
            .estimate_op_gas(optional_op.clone(), StateOverride::default())
            .await
            .unwrap();

        assert_eq!(
            estimation.pre_verification_gas,
            optional_op.pre_verification_gas.unwrap()
        );
        assert_eq!(
            estimation.verification_gas_limit,
            optional_op.verification_gas_limit.unwrap()
        );
        assert_eq!(
            estimation.paymaster_verification_gas_limit,
            optional_op.paymaster_verification_gas_limit
        );
        assert_eq!(
            estimation.call_gas_limit,
            optional_op.call_gas_limit.unwrap()
        );
    }

    #[tokio::test]
    async fn test_pvg_covers_bundle_inclusion_schedule() {
        const ACTIVATION: u64 = 1_000;

        let estimate_pvg_at = |activation: ForkActivation, block_timestamp: u64| {
            let (mut entry, mut provider) = create_base_config();
            provider
                .expect_get_latest_block_hash_number_and_timestamp()
                .returning(move || Ok((B256::ZERO, 0, block_timestamp)));
            entry
                .expect_simulate_handle_op_estimate_gas()
                .returning(move |_a, _b, _c, _d, _e| {
                    Ok(Ok(ExecutionResult {
                        target_result: TestCallGasResult {
                            success: true,
                            gasUsed: U256::ZERO,
                            revertData: Bytes::new(),
                        }
                        .abi_encode()
                        .into(),
                        target_success: true,
                        ..Default::default()
                    }))
                });
            // Read for the zero-deposit term after activation; a funded sender has none.
            entry
                .expect_balance_of()
                .returning(|_, _| Ok(U256::from(1_000_000)));
            let (_, settings) = {
                let (entry, provider) = create_base_config();
                create_estimator(entry, provider)
            };
            let chain_spec = ChainSpec {
                eip7623_enabled: true,
                glamsterdam_activation: activation,
                ..Default::default()
            };
            let estimator = create_custom_estimator(chain_spec, provider, entry, settings);

            let mut optional_op = demo_user_op_optional_gas(None);
            optional_op.call_data = Bytes::from(vec![1_u8; 2_000]);
            optional_op.call_gas_limit = Some(10000);
            optional_op.verification_gas_limit = Some(10000);
            async move {
                estimator
                    .estimate_op_gas(optional_op, StateOverride::default())
                    .await
                    .unwrap()
                    .pre_verification_gas
            }
        };

        let activation = ForkActivation::Timestamp(ACTIVATION);
        let never = estimate_pvg_at(ForkActivation::Never, ACTIVATION).await;
        let pre = estimate_pvg_at(activation, ACTIVATION - 1).await;
        let post = estimate_pvg_at(activation, ACTIVATION).await;

        // before the fork, the estimate covers inclusion on either side of it
        assert!(
            pre > never,
            "pre-fork pvg {pre} should exceed pvg without a fork {never}"
        );
        assert!(
            pre >= post,
            "pre-fork pvg {pre} should cover post-fork pvg {post}"
        );
    }

    #[tokio::test]
    async fn test_provided_reverts() {
        let (mut entry, mut provider) = create_base_config();

        provider
            .expect_get_latest_block_hash_number_and_timestamp()
            .returning(|| Ok((B256::ZERO, 0, 0)));

        let revert_msg = "test revert".to_string();
        let err = Revert {
            reason: revert_msg.clone(),
        };

        entry
            .expect_simulate_handle_op_estimate_gas()
            .returning(move |_a, _b, _c, _d, _e| {
                Ok(Ok(ExecutionResult {
                    target_result: TestCallGasResult {
                        success: false,
                        gasUsed: U256::ZERO,
                        revertData: err.clone().abi_encode().into(),
                    }
                    .abi_encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });

        let (estimator, _) = create_estimator(entry, provider);

        let mut optional_op = demo_user_op_optional_gas(Some(10000));
        optional_op.call_gas_limit = Some(10000);
        optional_op.verification_gas_limit = Some(10000);

        let estimation_error = estimator
            .estimate_op_gas(optional_op.clone(), StateOverride::default())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            estimation_error,
            GasEstimationError::RevertInCallWithMessage(msg) if msg == revert_msg
        ));
    }

    #[tokio::test]
    async fn test_total_limit() {
        let (mut entry, mut provider) = create_base_config();

        entry
            .expect_simulate_handle_op_estimate_gas()
            .returning(move |_a, _b, _c, _d, _e| {
                Ok(Ok(ExecutionResult {
                    target_result: TestCallGasResult {
                        success: true,
                        gasUsed: U256::from(TEST_MAX_GAS_LIMITS),
                        revertData: Bytes::new(),
                    }
                    .abi_encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });
        provider
            .expect_get_latest_block_hash_number_and_timestamp()
            .returning(|| Ok((B256::ZERO, 0, 0)));

        let (estimator, _) = create_estimator(entry, provider);

        let optional_op = UserOperationOptionalGas {
            sender: Address::ZERO,
            nonce: U256::ZERO,
            call_data: Bytes::new(),
            call_gas_limit: Some(TEST_MAX_GAS_LIMITS),
            verification_gas_limit: Some(TEST_MAX_GAS_LIMITS),
            pre_verification_gas: Some(TEST_MAX_GAS_LIMITS),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            signature: Bytes::new(),

            paymaster: None,
            paymaster_data: Bytes::new(),
            paymaster_verification_gas_limit: Some(TEST_MAX_GAS_LIMITS),
            paymaster_post_op_gas_limit: Some(TEST_MAX_GAS_LIMITS),

            factory: None,
            factory_data: Bytes::new(),
            eip7702_auth_address: None,
            aggregator: None,
            paymaster_signature: None,

            entry_point_version: EntryPointVersion::V0_7,
        };

        let estimation = estimator
            .estimate_op_gas(optional_op, StateOverride::default())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            estimation,
            GasEstimationError::GasTotalTooLarge(_, TEST_MAX_GAS_LIMITS)
        ));
    }

    #[tokio::test]
    async fn test_unsupported_aggregator() {
        let (entry, provider) = create_base_config();
        let (estimator, _) = create_estimator(entry, provider);
        let mut op = demo_user_op_optional_gas(None);
        let unsupported = Address::random();
        op.aggregator = Some(unsupported);

        let err = estimator
            .estimate_op_gas(op, StateOverride::default())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            err,
            GasEstimationError::UnsupportedAggregator(x) if x == unsupported,
        ));
    }

    #[test]
    fn test_proxy_target_offset() {
        let proxy_target_bytes = hex::decode(PROXY_IMPLEMENTATION_ADDRESS_MARKER).unwrap();
        let mut offsets = Vec::<usize>::new();
        for i in 0..CALL_GAS_ESTIMATION_PROXY_V0_7_DEPLOYED_BYTECODE.len() - 20 {
            if CALL_GAS_ESTIMATION_PROXY_V0_7_DEPLOYED_BYTECODE[i..i + 20] == proxy_target_bytes {
                offsets.push(i);
            }
        }
        assert_eq!(vec![PROXY_TARGET_OFFSET], offsets);
    }

    // ---- reservoir mode ----

    /// The traced copy with call gas (`FULL`) or without (`NO_CALL`), told apart by `to`.
    const FULL: Address = Address::with_last_byte(0xf1);
    const NO_CALL: Address = Address::with_last_byte(0xf0);
    const RESERVOIR_SENDER: Address = Address::with_last_byte(0x5e);

    /// A `callTracer` result of `simulateHandleOp` with the root frame's EIP-8037 fields.
    fn state_gas_trace(
        state_gas: u64,
        execution_frame_gas: u64,
        op_success: Option<bool>,
    ) -> serde_json::Value {
        let ep = Address::ZERO;
        let logs = match op_success {
            Some(success) => serde_json::json!([{
                "address": ep,
                "topics": [
                    rundler_contracts::v0_7::IEntryPoint::UserOperationEvent::SIGNATURE_HASH,
                    B256::ZERO, B256::ZERO, B256::ZERO
                ],
                "data": Bytes::from(
                    (U256::ZERO, success, U256::from(1), U256::from(2)).abi_encode_params()
                ),
            }]),
            None => serde_json::json!([]),
        };
        serde_json::json!({
            "from": rundler_types::constants::SIMULATION_SENDER,
            "to": ep,
            "gas": "0x0",
            "gasUsed": "0x0",
            "input": "0x",
            "type": "CALL",
            "calls": [
                { "from": ep, "to": RESERVOIR_SENDER, "gas": "0x0", "gasUsed": "0x100",
                  "input": "0x", "type": "CALL" },
                { "from": ep, "to": ep, "gas": "0x0", "gasUsed": "0x0", "input": "0x",
                  "type": "CALL", "calls": [
                    { "from": ep, "to": RESERVOIR_SENDER, "gas": "0x0",
                      "gasUsed": format!("{execution_frame_gas:#x}"), "input": "0x",
                      "type": "CALL" }
                  ] }
            ],
            "logs": logs,
            "executionGasUsed": "0x1",
            "stateGasUsed": format!("{state_gas:#x}"),
            "gasRefund": "0x0",
        })
    }

    /// Mocks for one reservoir-mode fallback: the simulation call builder, and traces of the
    /// copy with call gas (`full`) and without (`no_call`).
    fn reservoir_mocks(
        full: serde_json::Value,
        no_call: serde_json::Value,
    ) -> (MockEntryPointV0_7, MockEvmProvider) {
        let (mut entry, mut provider) = create_base_config();
        entry
            .expect_get_state_gas_simulate_handle_op_call()
            .returning(|op, _, gas| {
                // innerHandleOp needs gasleft() * 63/64 >= the call and postOp limits after the
                // entry point's own call into it kept 1/64 (AA95 otherwise).
                let limits = op.verification_gas_limit()
                    + op.paymaster_verification_gas_limit()
                    + op.call_gas_limit()
                    + op.paymaster_post_op_gas_limit();
                assert!(
                    u128::from(gas) * 63 * 63 / (64 * 64) > limits,
                    "trace gas {gas}"
                );
                let to = if op.call_gas_limit() == 0 {
                    NO_CALL
                } else {
                    FULL
                };
                Ok((
                    TransactionRequest::default().to(to),
                    StateOverride::default(),
                ))
            });
        provider
            .expect_request::<(TransactionRequest, BlockId, serde_json::Value), serde_json::Value>()
            .returning(move |method, (tx, _, _)| {
                assert_eq!(method, "debug_traceCall");
                Ok(if tx.to == Some(FULL.into()) {
                    full.clone()
                } else {
                    no_call.clone()
                })
            });
        (entry, provider)
    }

    fn reservoir_settings() -> Settings {
        Settings {
            max_verification_gas: 5_000_000,
            max_bundle_execution_gas: 15_099_494,
            max_gas_estimation_gas: 550_000_000,
            max_paymaster_verification_gas: 5_000_000,
            max_paymaster_post_op_gas: 15_099_494,
            verification_estimation_gas_fee: 1_000_000_000_000,
            verification_gas_limit_efficiency_reject_threshold: 0.5,
            verification_gas_allowed_error_pct: 15,
            call_gas_allowed_error_pct: 15,
            max_gas_estimation_rounds: 3,
            max_reservoir_gas: 60_000_000,
            reservoir_trace_timeout: std::time::Duration::from_secs(10),
            max_concurrent_reservoir_estimations: 4,
        }
    }

    async fn run_reservoir(
        entry: MockEntryPointV0_7,
        provider: MockEvmProvider,
        settings: Settings,
    ) -> Result<GasEstimate, GasEstimationError> {
        let chain_spec = ChainSpec {
            glamsterdam_activation: ForkActivation::Genesis,
            ..Default::default()
        };
        let chain_spec = chain_spec.at_timestamp(0).into_owned();
        let estimator = create_custom_estimator(chain_spec.clone(), provider, entry, settings);
        let mut op = demo_user_op_optional_gas(None);
        op.sender = RESERVOIR_SENDER;
        let full_op = op
            .clone()
            .into_user_operation_builder(
                &chain_spec,
                settings.max_bundle_execution_gas,
                settings.max_verification_gas,
                settings.max_paymaster_verification_gas,
            )
            .pre_verification_gas(0)
            .build();
        let args = ReservoirArgs {
            op: &op,
            full_op: &full_op,
            chain_spec: &chain_spec,
            block_hash: B256::ZERO,
            state_override: &StateOverride::default(),
            da_gas: 0,
            pvg_state: PvgState {
                sender_deposit_is_zero: Some(false),
                authority: None,
            },
            verification_gas_limit: 100_000,
            paymaster_verification_gas_limit: 0,
        };
        estimator
            .estimate_reservoir_mode(args, GasEstimationError::CallGasLimitTooLow(1))
            .await
    }

    /// Phase 0's 24 kB deploy: S = 37,784,880, with 25,908 of execution gas in the frame.
    const DEPLOY_24KB_STATE_GAS: u64 = 37_784_880;

    #[tokio::test]
    async fn test_reservoir_mode_estimate() {
        let full = state_gas_trace(
            DEPLOY_24KB_STATE_GAS,
            DEPLOY_24KB_STATE_GAS + 25_908,
            Some(true),
        );
        let no_call = state_gas_trace(0, 0, Some(false));
        let (entry, provider) = reservoir_mocks(full, no_call);

        let estimate = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap();

        // CGL covers execution only; VGL is the metered estimate; PVG carries S.
        assert_eq!(
            estimate.call_gas_limit,
            reservoir_call_gas_limit(
                u128::from(DEPLOY_24KB_STATE_GAS) + 25_908,
                u128::from(DEPLOY_24KB_STATE_GAS)
            )
        );
        assert_eq!(estimate.verification_gas_limit, 100_000);
        assert!(estimate.pre_verification_gas > u128::from(DEPLOY_24KB_STATE_GAS));
        assert!(
            estimate.pre_verification_gas < u128::from(DEPLOY_24KB_STATE_GAS) + 200_000,
            "PVG should be base + S, got {}",
            estimate.pre_verification_gas
        );
    }

    /// Validation and postOp state (in the no-call trace) is not subtracted from call gas.
    #[tokio::test]
    async fn test_reservoir_mode_execution_state_only() {
        let validation_state = 1_650_870;
        let full = state_gas_trace(
            DEPLOY_24KB_STATE_GAS + validation_state,
            DEPLOY_24KB_STATE_GAS + 25_908,
            Some(true),
        );
        let no_call = state_gas_trace(validation_state, 0, Some(false));
        let (entry, provider) = reservoir_mocks(full, no_call);

        let estimate = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap();
        assert_eq!(
            estimate.call_gas_limit,
            reservoir_call_gas_limit(
                u128::from(DEPLOY_24KB_STATE_GAS) + 25_908,
                u128::from(DEPLOY_24KB_STATE_GAS)
            )
        );
        assert!(
            estimate.pre_verification_gas
                > u128::from(DEPLOY_24KB_STATE_GAS) + u128::from(validation_state)
        );
    }

    /// The copy also fails: a genuine revert, returned as the metered error.
    #[tokio::test]
    async fn test_reservoir_mode_copy_fails() {
        let full = state_gas_trace(0, 30_000, Some(false));
        let (entry, provider) = reservoir_mocks(full, state_gas_trace(0, 0, Some(false)));

        let error = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap_err();
        assert!(matches!(error, GasEstimationError::CallGasLimitTooLow(1)));
    }

    /// A node without EIP-8037 tracing: the metered error, not a provider error.
    #[tokio::test]
    async fn test_reservoir_mode_without_state_gas_tracing() {
        let mut full = state_gas_trace(DEPLOY_24KB_STATE_GAS, 40_000_000, Some(true));
        full.as_object_mut().unwrap().remove("stateGasUsed");
        let (entry, provider) = reservoir_mocks(full.clone(), full);

        let error = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap_err();
        assert!(matches!(error, GasEstimationError::CallGasLimitTooLow(1)));
    }

    #[tokio::test]
    async fn test_reservoir_mode_state_gas_too_large() {
        let full = state_gas_trace(70_000_000, 70_030_000, Some(true));
        let (entry, provider) = reservoir_mocks(full, state_gas_trace(0, 0, Some(false)));

        let error = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GasEstimationError::StateGasTooLarge(70_000_000, 60_000_000)
        ));
    }

    /// State that fits under the cap next to the op's computation gas needs no reservoir.
    #[tokio::test]
    async fn test_reservoir_mode_not_needed() {
        let full = state_gas_trace(500_000, 530_000, Some(true));
        let (entry, provider) = reservoir_mocks(full, state_gas_trace(0, 0, Some(false)));

        let error = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap_err();
        assert!(matches!(error, GasEstimationError::CallGasLimitTooLow(1)));
    }

    #[tokio::test]
    async fn test_reservoir_mode_busy() {
        let (entry, provider) = create_base_config();
        let settings = Settings {
            max_concurrent_reservoir_estimations: 0,
            ..reservoir_settings()
        };

        let error = run_reservoir(entry, provider, settings).await.unwrap_err();
        assert!(matches!(error, GasEstimationError::CallGasLimitTooLow(1)));
    }

    #[test]
    fn test_reservoir_mode_possible() {
        let (entry, provider) = create_base_config();
        let estimator =
            create_custom_estimator(ChainSpec::default(), provider, entry, reservoir_settings());
        let glamsterdam = ChainSpec {
            glamsterdam_activation: ForkActivation::Genesis,
            ..Default::default()
        };
        let op = demo_user_op_optional_gas(None);

        assert!(estimator.reservoir_mode_possible(&op, &glamsterdam, 0));
        assert!(!estimator.reservoir_mode_possible(&op, &ChainSpec::default(), 0));

        let mut with_call_gas = op.clone();
        with_call_gas.call_gas_limit = Some(100_000);
        assert!(!estimator.reservoir_mode_possible(&with_call_gas, &glamsterdam, 0));

        let mut with_pvg = op.clone();
        with_pvg.pre_verification_gas = Some(100_000);
        assert!(!estimator.reservoir_mode_possible(&with_pvg, &glamsterdam, 0));
    }

    #[test]
    fn test_may_need_reservoir() {
        assert!(may_need_reservoir(&GasEstimationError::CallGasLimitTooLow(
            1
        )));
        assert!(may_need_reservoir(&GasEstimationError::GasTotalTooLarge(
            2, 1
        )));
        assert!(may_need_reservoir(
            &GasEstimationError::RevertInCallWithMessage("deploy failed".into())
        ));
        assert!(!may_need_reservoir(&GasEstimationError::GasFieldTooLarge(
            "callGasLimit",
            1
        )));
        assert!(!may_need_reservoir(
            &GasEstimationError::RevertInValidation(rundler_types::ValidationRevert::EntryPoint(
                "AA23".into()
            ))
        ));
    }
}
