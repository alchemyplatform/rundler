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

use std::{ops::Add, time::Instant};

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
    AccountOverride, DAGasProvider, EntryPoint, EvmProvider, FeeEstimator, SimulationProvider,
    StateOverride,
};
use rundler_types::{
    GasEstimate, UserOperation as _,
    chain::ChainSpec,
    v0_7::{UserOperation, UserOperationBuilder, UserOperationOptionalGas},
};
use rundler_utils::{guard_timer::CustomTimerGuard, math};
use tokio::join;
use tracing::instrument;

use super::{
    GasEstimationError, Metrics, Settings,
    estimate_verification_gas::{EstimateGasArgs, VerificationGasEstimatorSpecialization},
    reservoir::{self, ReservoirArgs, ReservoirEstimator},
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
    reservoir: ReservoirEstimator<P, E>,
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
            reservoir::base_pre_verification_gas(
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
        let reservoir = ReservoirEstimator::new(provider.clone(), entry_point.clone(), settings);
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
            reservoir,
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

    /// See [`ReservoirEstimator::estimate_reservoir_mode`]
    async fn estimate_reservoir_mode(
        &self,
        args: ReservoirArgs<'_>,
        metered_error: GasEstimationError,
    ) -> Result<GasEstimate, GasEstimationError> {
        self.reservoir
            .estimate_reservoir_mode(args, metered_error)
            .await
    }

    #[cfg(test)]
    fn reservoir_max_call_gas(&self, args: &ReservoirArgs<'_>) -> u128 {
        self.reservoir.reservoir_max_call_gas(args)
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
    pub(super) chain_spec: ChainSpec,
    pub(super) simulations_bytecode: Bytes,
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

pub(super) fn decode_validation_revert<EP: SimulationProvider>(
    revert_data: &Bytes,
) -> GasEstimationError {
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
use rundler_contracts::{
    common::EstimationTypes,
    v0_7::{
        IEntryPointSimulations::{simulateHandleOpCall, simulateHandleOpNoPostOpCall},
        ReservoirProbe::probeCall,
    },
};
#[cfg(test)]
use rundler_types::{PvgState, TX_MAX_GAS_LIMIT};

#[cfg(test)]
use super::{
    CALL_GAS_BUFFER_VALUE, SponsoredReservoir, SponsoredReservoirError,
    reservoir::{SIMULATION_UNMETERED_GAS, transaction_intrinsic_gas},
};

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
        GasEstimator as _,
        estimation::{
            estimate_call_gas::PROXY_IMPLEMENTATION_ADDRESS_MARKER,
            state_gas::RESERVOIR_THRESHOLD_MARGIN,
        },
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
            max_concurrent_sponsored_reservoir_searches: 4,
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

    const RESERVOIR_SENDER: Address = Address::with_last_byte(0x5e);
    const RESERVOIR_PAYMASTER: Address = Address::with_last_byte(0xaa);

    /// What a reservoir-mode op does in the mocked `eth_simulateV1` calls: its call runs if its
    /// call gas covers its execution, plus the state it peaks at beyond the reservoir (which
    /// spills into its gas).
    #[derive(Clone, Copy, Debug)]
    struct OpModel {
        execution_gas: u128,
        /// The state gas the op nets at the end
        net_state_gas: u128,
        peak_state_gas: u128,
        /// Whether the op, with postOp, succeeds when its call does
        post_op_succeeds: bool,
        /// Whether the node's `eth_simulateV1` gives calls a reservoir
        reservoir_in_simulation: bool,
    }

    impl OpModel {
        /// An op whose state peaks at its net amount
        fn new(execution_gas: u128, state_gas: u128) -> Self {
            Self {
                execution_gas,
                net_state_gas: state_gas,
                peak_state_gas: state_gas,
                post_op_succeeds: true,
                reservoir_in_simulation: true,
            }
        }

        fn call_gas_need(&self, reservoir_gas: u128) -> u128 {
            self.execution_gas + self.peak_state_gas.saturating_sub(reservoir_gas)
        }
    }

    /// The `eth_simulateV1` result of `simulateHandleOp(NoPostOp)` of a call that returns
    /// `target_result` from its target.
    fn simulated_call(target_result: Bytes) -> serde_json::Value {
        let return_data = Bytes::from(simulateHandleOpNoPostOpCall::abi_encode_returns(
            &rundler_contracts::v0_7::IEntryPointSimulations::ExecutionResult {
                targetResult: target_result,
                ..Default::default()
            },
        ));
        serde_json::json!({ "status": "0x1", "returnData": return_data, "gasUsed": "0x0" })
    }

    /// The `eth_simulateV1` result of `simulateHandleOp` of the op itself. If it succeeds, the
    /// entry point charges it all of its execution limits (so no penalty), and the transaction's
    /// gas used adds its net state, its intrinsic gas and the simulation's unmetered work.
    fn simulated_op(
        success: bool,
        execution_gas_limit: u128,
        net_state_gas: u128,
    ) -> serde_json::Value {
        let return_data = Bytes::from(simulateHandleOpCall::abi_encode_returns(
            &rundler_contracts::v0_7::IEntryPointSimulations::ExecutionResult::default(),
        ));
        let gas_used = transaction_intrinsic_gas(&reservoir_chain_spec(), &[])
            + execution_gas_limit
            + net_state_gas
            + SIMULATION_UNMETERED_GAS;
        serde_json::json!({
            "status": "0x1",
            "returnData": return_data,
            "gasUsed": format!("{gas_used:#x}"),
            "logs": [{
                "address": Address::ZERO,
                "topics": [
                    rundler_contracts::v0_7::IEntryPoint::UserOperationEvent::SIGNATURE_HASH,
                    B256::ZERO, B256::ZERO, B256::ZERO
                ],
                "data": Bytes::from(
                    (U256::ZERO, success, U256::ZERO, U256::from(execution_gas_limit))
                        .abi_encode_params()
                ),
            }],
        })
    }

    /// Mocks for one reservoir-mode fallback: the `eth_simulateV1` calls from `model`. Returns
    /// how many simulations ran.
    fn reservoir_mocks(
        model: OpModel,
    ) -> (
        MockEntryPointV0_7,
        MockEvmProvider,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let (mut entry, mut provider) = create_base_config();
        entry
            .expect_get_state_gas_simulate_handle_op_call()
            .returning(
                |op, skip_post_op, target, target_call_data, gas, state_override| {
                    // innerHandleOp needs gasleft() * 63/64 >= the call and postOp limits after
                    // the entry point's own call into it kept 1/64 (AA95 otherwise).
                    let limits = op.verification_gas_limit()
                        + op.paymaster_verification_gas_limit()
                        + op.call_gas_limit()
                        + op.paymaster_post_op_gas_limit();
                    assert!(u128::from(gas) * 63 * 63 / (64 * 64) > limits, "gas {gas}");
                    assert!(
                        target.is_zero() || target_call_data != (probeCall {}).abi_encode(),
                        "the probe is not simulateHandleOp's target"
                    );
                    // The call's arguments, for the provider mock.
                    let tx = TransactionRequest::default()
                        .to(Address::with_last_byte(u8::from(skip_post_op)))
                        .gas_limit(gas)
                        .input(target_call_data.into())
                        .value(U256::from(op.call_gas_limit()))
                        // (not a price: the postOp limit, for the provider mock)
                        .gas_price(op.paymaster_post_op_gas_limit());
                    Ok((tx, state_override))
                },
            );
        let simulations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&simulations);
        provider
            .expect_request::<(serde_json::Value, BlockId), serde_json::Value>()
            .returning(move |method, (payload, _)| {
                assert_eq!(method, "eth_simulateV1");
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let block = &payload["blockStateCalls"][0];
                let calls = block["calls"].as_array().unwrap();
                // a `ReservoirProbe` call first, with the op itself
                let probe = (calls.len() == 2).then(|| {
                    let probe: TransactionRequest =
                        serde_json::from_value(calls[0].clone()).unwrap();
                    let to = *probe.to.unwrap().to().unwrap();
                    assert!(
                        block["stateOverrides"]
                            .as_object()
                            .unwrap()
                            .keys()
                            .any(|key| key.parse::<Address>().ok() == Some(to)),
                        "probe has no code"
                    );
                    assert_eq!(
                        probe.input.into_input().unwrap(),
                        Bytes::from((probeCall {}).abi_encode())
                    );
                    serde_json::json!({
                        "status": "0x1",
                        "returnData": Bytes::from(model.reservoir_in_simulation.abi_encode()),
                        "gasUsed": "0x0",
                    })
                });
                let tx: TransactionRequest =
                    serde_json::from_value(calls[calls.len() - 1].clone()).unwrap();
                let gas = tx.gas.unwrap();
                let block_gas_limit: U256 =
                    serde_json::from_value(block["blockOverrides"]["gasLimit"].clone()).unwrap();
                assert!(block_gas_limit >= U256::from(gas), "block gas limit");
                let reservoir_gas = u128::from(gas.saturating_sub(TX_MAX_GAS_LIMIT));
                let need = model.call_gas_need(reservoir_gas);
                let skip_post_op = tx.to.unwrap().to().unwrap().0[19] == 1;
                let input = tx.input.into_input().unwrap_or_default();
                if input.is_empty() {
                    // the op itself, with postOp, and the probe
                    assert!(!skip_post_op);
                    let call_gas_limit: u128 = tx.value.unwrap().to();
                    let post_op_gas_limit = tx.gas_price.unwrap();
                    let success = call_gas_limit >= need && model.post_op_succeeds;
                    let op = simulated_op(
                        success,
                        call_gas_limit + post_op_gas_limit,
                        model.net_state_gas,
                    );
                    if reservoir_gas == 0 {
                        assert!(probe.is_none(), "no probe without a reservoir");
                        return Ok(serde_json::json!([{ "calls": [op] }]));
                    }
                    let probe =
                        probe.expect("a simulation of the op with a reservoir runs the probe");
                    return Ok(serde_json::json!([{ "calls": [probe, op] }]));
                }
                assert!(
                    probe.is_none(),
                    "only a simulation of the op runs the probe"
                );
                assert!(skip_post_op, "a call gas search skips postOp");
                let target_result = match CallGasEstimationProxyCalls::abi_decode(&input).unwrap() {
                    CallGasEstimationProxyCalls::estimateCallGas(call) => {
                        if need <= call.args.maxGas.to::<u128>() {
                            EstimationTypes::EstimateGasResult {
                                gas: U256::from(need),
                                numRounds: U256::from(1),
                            }
                            .abi_encode()
                        } else {
                            EstimationTypes::EstimateGasRevertAtMax {
                                revertData: Bytes::new(),
                            }
                            .abi_encode()
                        }
                    }
                    CallGasEstimationProxyCalls::testCallGas(call) => TestCallGasResult {
                        success: call.callGasLimit.to::<u128>() >= need,
                        gasUsed: U256::ZERO,
                        revertData: Bytes::new(),
                    }
                    .abi_encode(),
                };
                Ok(serde_json::json!([{ "calls": [simulated_call(target_result.into())] }]))
            });
        (entry, provider, simulations)
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
            max_concurrent_sponsored_reservoir_searches: 4,
        }
    }

    fn reservoir_chain_spec() -> ChainSpec {
        ChainSpec {
            glamsterdam_activation: ForkActivation::Genesis,
            ..Default::default()
        }
        .at_timestamp(0)
        .into_owned()
    }

    fn reservoir_op(
        chain_spec: &ChainSpec,
        settings: &Settings,
    ) -> (UserOperationOptionalGas, UserOperation) {
        let mut op = demo_user_op_optional_gas(None);
        op.sender = RESERVOIR_SENDER;
        reservoir_full_op(op, chain_spec, settings)
    }

    fn reservoir_full_op(
        op: UserOperationOptionalGas,
        chain_spec: &ChainSpec,
        settings: &Settings,
    ) -> (UserOperationOptionalGas, UserOperation) {
        let full_op = op
            .clone()
            .into_user_operation_builder(
                chain_spec,
                settings.max_bundle_execution_gas,
                settings.max_verification_gas,
                settings.max_paymaster_verification_gas,
            )
            .pre_verification_gas(0)
            .build();
        (op, full_op)
    }

    /// Admission's classification of the estimated op: its PVG surplus over the metered
    /// requirement (with a zero deposit, the larger requirement), if in reservoir mode.
    fn admitted_reservoir_gas(estimate: &GasEstimate, settings: &Settings) -> Option<u128> {
        let chain_spec = reservoir_chain_spec();
        let (_, full_op) = reservoir_op(&chain_spec, settings);
        let op = UserOperationBuilder::from_uo(full_op, &chain_spec)
            .pre_verification_gas(estimate.pre_verification_gas)
            .call_gas_limit(estimate.call_gas_limit)
            .verification_gas_limit(estimate.verification_gas_limit)
            .build();
        let required = op.required_pre_verification_gas(
            &chain_spec,
            1,
            0,
            Some(settings.verification_gas_limit_efficiency_reject_threshold),
            &PvgState {
                sender_deposit_is_zero: Some(true),
                authority: None,
            },
        );
        let surplus = op.pre_verification_gas().checked_sub(required)?;
        let threshold =
            gas::reservoir_threshold(&op, &chain_spec, settings.max_bundle_execution_gas);
        (surplus >= threshold).then_some(surplus)
    }

    async fn run_reservoir(
        entry: MockEntryPointV0_7,
        provider: MockEvmProvider,
        settings: Settings,
    ) -> Result<GasEstimate, GasEstimationError> {
        let mut op = demo_user_op_optional_gas(None);
        op.sender = RESERVOIR_SENDER;
        run_reservoir_op(entry, provider, settings, op, Some(false)).await
    }

    async fn run_reservoir_op(
        entry: MockEntryPointV0_7,
        provider: MockEvmProvider,
        settings: Settings,
        op: UserOperationOptionalGas,
        sender_deposit_is_zero: Option<bool>,
    ) -> Result<GasEstimate, GasEstimationError> {
        let chain_spec = reservoir_chain_spec();
        let estimator = create_custom_estimator(chain_spec.clone(), provider, entry, settings);
        let (op, full_op) = reservoir_full_op(op, &chain_spec, &settings);
        let args = ReservoirArgs {
            op: &op,
            full_op: &full_op,
            chain_spec: &chain_spec,
            block_hash: B256::ZERO,
            state_override: &StateOverride::default(),
            da_gas: 0,
            pvg_state: PvgState {
                sender_deposit_is_zero,
                authority: None,
            },
            verification_gas_limit: 100_000,
            paymaster_verification_gas_limit: 0,
        };
        estimator
            .estimate_reservoir_mode(args, GasEstimationError::CallGasLimitTooLow(1))
            .await
    }

    /// Phase 0's 24 kB deploy: S = 37,784,880, with 25,908 of execution gas.
    const DEPLOY_24KB_STATE_GAS: u64 = 37_784_880;
    const DEPLOY_24KB_EXECUTION_GAS: u128 = 25_908;

    fn deploy_24kb() -> OpModel {
        OpModel::new(DEPLOY_24KB_EXECUTION_GAS, u128::from(DEPLOY_24KB_STATE_GAS))
    }

    /// The call gas limit for a call gas search result
    fn buffered(call_gas: u128) -> u128 {
        (call_gas + CALL_GAS_BUFFER_VALUE).max(MIN_CALL_GAS_LIMIT)
    }

    #[tokio::test]
    async fn test_reservoir_mode_estimate() {
        let (entry, provider, simulations) = reservoir_mocks(deploy_24kb());

        let estimate = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap();

        // CGL covers execution only; VGL is the metered estimate; PVG carries S.
        assert_eq!(estimate.call_gas_limit, buffered(DEPLOY_24KB_EXECUTION_GAS));
        assert_eq!(estimate.verification_gas_limit, 100_000);
        assert!(estimate.pre_verification_gas > u128::from(DEPLOY_24KB_STATE_GAS));
        assert!(
            estimate.pre_verification_gas < u128::from(DEPLOY_24KB_STATE_GAS) + 200_000,
            "PVG should be base + S, got {}",
            estimate.pre_verification_gas
        );
        // admission classifies the estimated op as reservoir mode, with R >= S
        let reservoir_gas = admitted_reservoir_gas(&estimate, &reservoir_settings()).unwrap();
        assert!(reservoir_gas >= u128::from(DEPLOY_24KB_STATE_GAS));
        // S, the call gas search at R = S, and the check with postOp
        assert_eq!(simulations.load(std::sync::atomic::Ordering::Relaxed), 3);
    }

    /// The state the op peaks at above S spills into its call gas at R = S, and fits there.
    #[tokio::test]
    async fn test_reservoir_mode_small_peak_in_call_gas() {
        let model = OpModel {
            peak_state_gas: u128::from(DEPLOY_24KB_STATE_GAS) + 100_000,
            ..deploy_24kb()
        };
        let (entry, provider, _) = reservoir_mocks(model);

        let estimate = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap();

        assert_eq!(
            estimate.call_gas_limit,
            buffered(DEPLOY_24KB_EXECUTION_GAS + 100_000)
        );
        // the reservoir is S, not the peak
        let reservoir_gas = admitted_reservoir_gas(&estimate, &reservoir_settings()).unwrap();
        assert!(reservoir_gas < model.peak_state_gas);
    }

    /// Sepolia's SlotChurn `churn(400, 200)`: 400 new slots, then 200 cleared. About 5.0M of
    /// execution; the state peaks at 400 slots, and nets 200.
    const CHURN_EXECUTION_GAS: u128 = 5_000_000;
    const CHURN_NET_STATE_GAS: u128 = 200 * 97_920;
    const CHURN_PEAK_STATE_GAS: u128 = 400 * 97_920;

    fn churn() -> OpModel {
        OpModel {
            net_state_gas: CHURN_NET_STATE_GAS,
            ..OpModel::new(CHURN_EXECUTION_GAS, CHURN_PEAK_STATE_GAS)
        }
    }

    /// The peak's spill above S does not fit the call gas: the least reservoir the op runs with
    /// at the most call gas, which PVG pays for, well below the peak.
    #[tokio::test]
    async fn test_reservoir_mode_state_peak() {
        let model = churn();
        let (entry, provider, _) = reservoir_mocks(model);

        let settings = reservoir_settings();
        let estimate = run_reservoir(entry, provider, settings).await.unwrap();

        // the reservoir and call gas cover the peak, within the search's tolerance
        let reservoir_gas = admitted_reservoir_gas(&estimate, &settings).unwrap();
        assert!(estimate.call_gas_limit >= model.call_gas_need(reservoir_gas));
        let spill = estimate.call_gas_limit - CHURN_EXECUTION_GAS;
        assert!(reservoir_gas + spill >= CHURN_PEAK_STATE_GAS);
        assert!(
            reservoir_gas + spill <= CHURN_PEAK_STATE_GAS + CHURN_PEAK_STATE_GAS / 50,
            "reservoir {reservoir_gas}, call gas limit {}",
            estimate.call_gas_limit
        );
        // most of the spill is in the call gas limit, which fits the bundle
        assert!(spill > 9_000_000, "spill {spill}");
        assert!(
            100_000 + estimate.call_gas_limit < settings.max_bundle_execution_gas,
            "call gas limit {}",
            estimate.call_gas_limit
        );
    }

    /// The most call gas is at the cap, so the op as sent must still fit under it when its
    /// paymaster data, signature and gas fields have more non-zero bytes than the estimate's
    /// (on Sepolia, a paymaster stub with zero bytes put an op 287 gas over the cap).
    #[test]
    fn test_reservoir_max_call_gas_fits_with_sent_calldata() {
        let paymaster_data: Bytes = [[0xff; 28].as_slice(), &[0; 16], &[0x7a; 32], &[0x1c]]
            .concat()
            .into();
        let mut op = demo_user_op_optional_gas(None);
        op.sender = RESERVOIR_SENDER;
        op.paymaster = Some(RESERVOIR_PAYMASTER);
        op.paymaster_data = paymaster_data.clone();
        op.paymaster_post_op_gas_limit = Some(0);
        op.signature = [[0; 64].as_slice(), &[0x1c]].concat().into();
        let settings = reservoir_settings();
        let chain_spec = reservoir_chain_spec();
        let (entry, provider) = create_base_config();
        let estimator = create_custom_estimator(chain_spec.clone(), provider, entry, settings);
        let (op, full_op) = reservoir_full_op(op, &chain_spec, &settings);
        let args = ReservoirArgs {
            op: &op,
            full_op: &full_op,
            chain_spec: &chain_spec,
            block_hash: B256::ZERO,
            state_override: &StateOverride::default(),
            da_gas: 0,
            pvg_state: PvgState::default(),
            verification_gas_limit: 40_637,
            paymaster_verification_gas_limit: 40_637,
        };

        let call_gas_limit = buffered(estimator.reservoir_max_call_gas(&args));

        let sent = UserOperationBuilder::new(
            &chain_spec,
            EntryPointVersion::V0_7,
            rundler_types::v0_7::UserOperationRequiredFields {
                sender: RESERVOIR_SENDER,
                nonce: op.nonce,
                call_data: Bytes::new(),
                signature: vec![0xff; 65].into(),
                call_gas_limit,
                verification_gas_limit: 40_637,
                pre_verification_gas: 29_711_157,
                max_priority_fee_per_gas: u128::from(u64::MAX),
                max_fee_per_gas: u128::from(u64::MAX),
            },
        )
        .paymaster(
            RESERVOIR_PAYMASTER,
            40_637,
            0,
            vec![0xff; paymaster_data.len()].into(),
        )
        .build();
        let computation = sent.bundle_computation_gas_limit(&chain_spec, Some(1));
        assert!(
            computation <= settings.max_bundle_execution_gas,
            "computation gas {computation}"
        );
        // and the call gas limit is still close to the most that fits
        assert!(computation + 1_000 > settings.max_bundle_execution_gas);
    }

    /// S is measured low (e.g. refunds for cleared slots): the state above it spills into the
    /// call gas, and the searches still find limits the op runs with.
    #[tokio::test]
    async fn test_reservoir_mode_state_gas_measured_low() {
        let model = OpModel {
            net_state_gas: u128::from(DEPLOY_24KB_STATE_GAS) - 2_000_000,
            ..deploy_24kb()
        };
        let (entry, provider, _) = reservoir_mocks(model);

        let settings = reservoir_settings();
        let estimate = run_reservoir(entry, provider, settings).await.unwrap();

        let reservoir_gas = admitted_reservoir_gas(&estimate, &settings).unwrap();
        assert!(estimate.call_gas_limit >= model.call_gas_need(reservoir_gas));
    }

    /// The op fails even with the most reservoir and call gas: the metered error.
    #[tokio::test]
    async fn test_reservoir_mode_fails_with_most_reservoir() {
        let (entry, provider, simulations) = reservoir_mocks(OpModel {
            execution_gas: 20_000_000,
            ..churn()
        });

        let error = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap_err();
        assert!(matches!(error, GasEstimationError::CallGasLimitTooLow(1)));
        // only the measurement of S
        assert_eq!(simulations.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    /// The op fails with postOp: the metered error.
    #[tokio::test]
    async fn test_reservoir_mode_fails_with_post_op() {
        let model = OpModel {
            post_op_succeeds: false,
            ..deploy_24kb()
        };
        let (entry, provider, _) = reservoir_mocks(model);
        let mut op = demo_user_op_optional_gas(None);
        op.sender = RESERVOIR_SENDER;
        op.paymaster = Some(RESERVOIR_PAYMASTER);
        op.paymaster_verification_gas_limit = Some(50_000);
        op.paymaster_post_op_gas_limit = Some(50_000);

        let error = run_reservoir_op(entry, provider, reservoir_settings(), op, None)
            .await
            .unwrap_err();
        assert!(matches!(error, GasEstimationError::CallGasLimitTooLow(1)));
    }

    /// A new EIP-7702 authority's state is charged to the reservoir before the entry point
    /// runs, but the simulations apply the delegation by state override and do not show it.
    #[tokio::test]
    async fn test_reservoir_mode_new_authority_state() {
        let mut op = demo_user_op_optional_gas(None);
        op.sender = RESERVOIR_SENDER;
        let (entry, provider, _) = reservoir_mocks(deploy_24kb());
        let without = run_reservoir_op(entry, provider, reservoir_settings(), op.clone(), None)
            .await
            .unwrap();

        op.eip7702_auth_address = Some(Address::with_last_byte(0xde));
        let (entry, provider, _) = reservoir_mocks(deploy_24kb());
        let with = run_reservoir_op(entry, provider, reservoir_settings(), op, None)
            .await
            .unwrap();

        let chain_spec = reservoir_chain_spec();
        let authority_state = chain_spec.eip7702_authorization_new_account_gas()
            + chain_spec.eip7702_authorization_delegation_gas();
        assert_eq!(authority_state, 218_790);
        assert!(
            with.pre_verification_gas >= without.pre_verification_gas + authority_state,
            "with {}, without {}",
            with.pre_verification_gas,
            without.pre_verification_gas
        );
    }

    #[tokio::test]
    async fn test_reservoir_mode_state_gas_too_large() {
        let (entry, provider, _) = reservoir_mocks(OpModel::new(30_000, 70_000_000));

        let error = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GasEstimationError::StateGasTooLarge(70_000_000, 60_000_000)
        ));
    }

    /// State below the threshold after a failed metered estimate (the metered call gas limit
    /// needs more than the state itself): the reservoir is padded to the threshold, so the op is
    /// still classified as reservoir mode at admission.
    #[tokio::test]
    async fn test_reservoir_mode_pads_reservoir_to_threshold() {
        let state_gas = 500_000;
        let (entry, provider, _) = reservoir_mocks(OpModel::new(30_000, state_gas));
        let settings = reservoir_settings();

        let estimate = run_reservoir(entry, provider, settings).await.unwrap();

        // PVG pays for a reservoir of the threshold, not just S: together with the op's
        // computation gas (VGL 100,000 + CGL + static PVG) it exceeds the cap
        let computation = 100_000 + estimate.call_gas_limit;
        assert!(estimate.pre_verification_gas + computation > settings.max_bundle_execution_gas);
        assert!(estimate.pre_verification_gas > 10 * state_gas);
        assert_eq!(estimate.call_gas_limit, buffered(30_000));
        // admission classifies it as reservoir mode, with the margin to spare: a threshold up
        // to the margin higher (e.g. a lower verification gas limit) still classifies it so
        let reservoir_gas = admitted_reservoir_gas(&estimate, &settings).unwrap();
        let lower_vgl = GasEstimate {
            verification_gas_limit: estimate.verification_gas_limit
                - RESERVOIR_THRESHOLD_MARGIN / 2,
            ..estimate
        };
        assert!(admitted_reservoir_gas(&lower_vgl, &settings).is_some());
        assert!(reservoir_gas > state_gas);
    }

    /// An op without state gas (measured below one slot) has no use for a reservoir: the
    /// metered error is returned.
    #[tokio::test]
    async fn test_reservoir_mode_not_for_ops_without_state() {
        let (entry, provider, simulations) = reservoir_mocks(OpModel::new(30_000, 50_000));

        let error = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap_err();
        assert!(matches!(error, GasEstimationError::CallGasLimitTooLow(1)));
        // S, and the call gas search at R = S, which passes
        assert_eq!(simulations.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    /// An op that clears all the state it allocates has no net state, but its peak does not fit
    /// the call gas: the search finds the reservoir for it.
    #[tokio::test]
    async fn test_reservoir_mode_zero_net_state_peak() {
        // 400 slots allocated, then all 400 cleared
        let model = OpModel {
            net_state_gas: 0,
            ..churn()
        };
        let settings = reservoir_settings();
        assert!(model.call_gas_need(0) > settings.max_bundle_execution_gas);
        let (entry, provider, _) = reservoir_mocks(model);

        let estimate = run_reservoir(entry, provider, settings).await.unwrap();

        let reservoir_gas = admitted_reservoir_gas(&estimate, &settings).unwrap();
        assert!(estimate.call_gas_limit >= model.call_gas_need(reservoir_gas));
        assert!(reservoir_gas + estimate.call_gas_limit > CHURN_PEAK_STATE_GAS);
    }

    /// The node's `eth_simulateV1` gives calls no reservoir: the simulations would measure
    /// nothing the bundle will do, so the metered error, before any search.
    #[tokio::test]
    async fn test_reservoir_mode_fails_without_reservoir_in_simulation() {
        let (entry, provider, simulations) = reservoir_mocks(OpModel {
            reservoir_in_simulation: false,
            ..deploy_24kb()
        });

        let error = run_reservoir(entry, provider, reservoir_settings())
            .await
            .unwrap_err();
        assert!(matches!(error, GasEstimationError::CallGasLimitTooLow(1)));
        assert_eq!(simulations.load(std::sync::atomic::Ordering::Relaxed), 1);
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

    /// Admission's reservoir search for a bundler-sponsored op as sent: the estimate's call gas
    /// limit, with PVG and fees zeroed. Returns how many simulations ran.
    async fn run_sponsored(
        entry: MockEntryPointV0_7,
        provider: MockEvmProvider,
        settings: Settings,
        call_gas_limit: u128,
    ) -> Result<SponsoredReservoir, SponsoredReservoirError> {
        let mut entry = entry;
        entry
            .expect_balance_of()
            .returning(|_, _| Ok(U256::from(1)));
        let chain_spec = reservoir_chain_spec();
        let estimator = create_custom_estimator(chain_spec.clone(), provider, entry, settings);
        let (_, full_op) = reservoir_op(&chain_spec, &settings);
        let op = UserOperationBuilder::from_uo(full_op, &chain_spec)
            .call_gas_limit(call_gas_limit)
            .verification_gas_limit(100_000)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .pre_verification_gas(0)
            .build();
        estimator
            .reservoir
            .sponsored_reservoir_gas(&op, &chain_spec, B256::ZERO)
            .await
    }

    #[tokio::test]
    async fn test_sponsored_reservoir_found_at_signed_call_gas() {
        let (entry, provider, simulations) = reservoir_mocks(deploy_24kb());

        let reservoir = run_sponsored(
            entry,
            provider,
            reservoir_settings(),
            buffered(DEPLOY_24KB_EXECUTION_GAS),
        )
        .await
        .unwrap();

        // The call gas limit covers execution only, so the reservoir carries the state, within
        // the search's 1% tolerance.
        let SponsoredReservoir::Reservoir(reservoir_gas) = reservoir else {
            panic!("expected a reservoir, got {reservoir:?}");
        };
        let state_gas = u128::from(DEPLOY_24KB_STATE_GAS);
        assert!(reservoir_gas >= state_gas - CALL_GAS_BUFFER_VALUE);
        assert!(reservoir_gas <= state_gas + state_gas / 100);
        // The measured state gas passes, so it is the reservoir, without a search: the run
        // without a reservoir, the measurement, and the run at it.
        assert_eq!(reservoir_gas, state_gas);
        assert_eq!(simulations.load(std::sync::atomic::Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn test_sponsored_op_without_state_runs_metered() {
        let (entry, provider, simulations) = reservoir_mocks(OpModel::new(25_908, 0));

        let reservoir = run_sponsored(entry, provider, reservoir_settings(), buffered(25_908))
            .await
            .unwrap();

        assert_eq!(reservoir, SponsoredReservoir::Metered);
        // only the run without a reservoir
        assert_eq!(simulations.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_sponsored_op_failing_at_its_call_gas_limit() {
        let (entry, provider, _) = reservoir_mocks(deploy_24kb());

        // Too little call gas for its execution, whatever the reservoir
        let reservoir = run_sponsored(entry, provider, reservoir_settings(), 10_000)
            .await
            .unwrap();

        assert_eq!(reservoir, SponsoredReservoir::Fails);
    }

    #[tokio::test]
    async fn test_sponsored_op_state_gas_too_large() {
        let (entry, provider, _) = reservoir_mocks(OpModel::new(25_908, 70_000_000));

        let reservoir = run_sponsored(entry, provider, reservoir_settings(), buffered(25_908))
            .await
            .unwrap();

        // Reported over max_reservoir_gas, for admission to reject
        assert!(
            matches!(reservoir, SponsoredReservoir::Reservoir(gas) if gas > 60_000_000),
            "{reservoir:?}"
        );
    }

    #[tokio::test]
    async fn test_sponsored_reservoir_disabled() {
        let (entry, provider) = create_base_config();
        let settings = Settings {
            max_reservoir_gas: 0,
            ..reservoir_settings()
        };

        let reservoir = run_sponsored(entry, provider, settings, buffered(25_908))
            .await
            .unwrap();

        assert_eq!(reservoir, SponsoredReservoir::Metered);
    }

    /// The search is busy: an op that needs a reservoir is rejected (not admitted metered), one
    /// that runs without needs no permit.
    #[tokio::test]
    async fn test_sponsored_reservoir_busy() {
        let settings = Settings {
            max_concurrent_sponsored_reservoir_searches: 0,
            ..reservoir_settings()
        };

        let (entry, provider, _) = reservoir_mocks(deploy_24kb());
        let reservoir = run_sponsored(
            entry,
            provider,
            settings,
            buffered(DEPLOY_24KB_EXECUTION_GAS),
        )
        .await;
        assert!(
            matches!(reservoir, Err(SponsoredReservoirError::Busy)),
            "{reservoir:?}"
        );

        let (entry, provider, _) = reservoir_mocks(OpModel::new(25_908, 0));
        let reservoir = run_sponsored(entry, provider, settings, buffered(25_908))
            .await
            .unwrap();
        assert_eq!(reservoir, SponsoredReservoir::Metered);
    }

    /// On a node whose `eth_simulateV1` gives calls no reservoir, an op that runs without one is
    /// still admitted (no probe at a reservoir of 0), and one that needs one is rejected.
    #[tokio::test]
    async fn test_sponsored_reservoir_without_reservoir_in_simulation() {
        let (entry, provider, _) = reservoir_mocks(OpModel {
            reservoir_in_simulation: false,
            ..OpModel::new(25_908, 0)
        });
        let reservoir = run_sponsored(entry, provider, reservoir_settings(), buffered(25_908))
            .await
            .unwrap();
        assert_eq!(reservoir, SponsoredReservoir::Metered);

        let (entry, provider, _) = reservoir_mocks(OpModel {
            reservoir_in_simulation: false,
            ..deploy_24kb()
        });
        let reservoir = run_sponsored(
            entry,
            provider,
            reservoir_settings(),
            buffered(DEPLOY_24KB_EXECUTION_GAS),
        )
        .await;
        assert!(
            matches!(
                reservoir,
                Err(SponsoredReservoirError::NoSimulationReservoir(_))
            ),
            "{reservoir:?}"
        );
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
