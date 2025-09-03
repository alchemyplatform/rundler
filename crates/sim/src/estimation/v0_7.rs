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

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolInterface};
use rundler_contracts::v0_7::{
    CallGasEstimationProxy::{
        estimateCallGasCall, testCallGasCall, CallGasEstimationProxyCalls, EstimateCallGasArgs,
    },
    VerificationGasEstimationHelper::{
        estimatePaymasterVerificationGasCall, estimateVerificationGasCall,
        EstimateGasArgs as ContractEstimateGasArgs,
    },
    CALL_GAS_ESTIMATION_PROXY_V0_7_DEPLOYED_BYTECODE,
    ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE,
    VERIFICATION_GAS_ESTIMATION_HELPER_V0_7_DEPLOYED_BYTECODE,
};
use rundler_provider::{
    AccountOverride, DAGasProvider, EntryPoint, EvmProvider, FeeEstimator, SimulationProvider,
    StateOverride,
};
use rundler_types::{
    chain::ChainSpec,
    v0_7::{UserOperation, UserOperationBuilder, UserOperationOptionalGas},
    GasEstimate, UserOperation as _,
};
use rundler_utils::{guard_timer::CustomTimerGuard, math};
use tokio::join;
use tracing::instrument;

use super::{
    estimate_verification_gas::{EstimateGasArgs, VerificationGasEstimatorSpecialization},
    GasEstimationError, Metrics, Settings,
};
use crate::{
    gas, CallGasEstimator, CallGasEstimatorImpl, CallGasEstimatorSpecialization,
    VerificationGasEstimator, VerificationGasEstimatorImpl, MIN_CALL_GAS_LIMIT,
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

        let (block_hash, _) = provider
            .get_latest_block_hash_and_number()
            .await
            .map_err(anyhow::Error::from)?;

        let mut full_op = op
            .clone()
            .into_user_operation_builder(
                &self.chain_spec,
                settings.max_bundle_execution_gas,
                settings.max_verification_gas,
                settings.max_paymaster_verification_gas,
            )
            .pre_verification_gas(0)
            .build();
        if let Some(agg) = agg {
            full_op = full_op.transform_for_aggregator(
                &self.chain_spec,
                agg.address(),
                agg.costs().clone(),
                agg.dummy_uo_signature().clone(),
            );
        }

        let random_op = op.random_fill(&self.chain_spec);
        let da_gas_future = gas::estimate_da_gas_with_fees(
            &self.chain_spec,
            &self.entry_point,
            &self.fee_estimator,
            &random_op,
            op.max_fee_per_gas,
            op.max_priority_fee_per_gas,
            block_hash.into(),
            self.metrics.pvg_estimate_ms.clone(),
        );

        let verification_gas_future =
            self.estimate_verification_gas(&op, &full_op, block_hash, state_override.clone());

        let paymaster_verification_gas_future = self.estimate_paymaster_verification_gas(
            &op,
            &full_op,
            block_hash,
            state_override.clone(),
        );
        let call_gas_future =
            self.estimate_call_gas(&op, full_op.clone(), block_hash, state_override);

        // Not try_join! because then the output is nondeterministic if multiple calls fail.
        let (
            da_gas_result,
            verification_gas_limit_result,
            paymaster_verification_gas_limit_result,
            call_gas_limit_result,
        ) = join!(
            da_gas_future,
            verification_gas_future,
            paymaster_verification_gas_future,
            call_gas_future
        );

        let da_gas = da_gas_result.map_err(GasEstimationError::from)?;
        let verification_gas_limit = verification_gas_limit_result?;
        let paymaster_verification_gas_limit = paymaster_verification_gas_limit_result?;
        let call_gas_limit = call_gas_limit_result?;

        // Calculate the final PVG now that we have all gas limits
        let pre_verification_gas = if op.pre_verification_gas.is_some_and(|pvg| pvg != 0) {
            op.pre_verification_gas.unwrap()
        } else {
            // TODO(bundle): assuming a bundle size of 1
            let bundle_size = 1;
            let base_op = op.max_fill(&self.chain_spec);
            if self.chain_spec.charge_gas_limit_via_pvg {
                let op_with_limits = UserOperationBuilder::from_uo(base_op, &self.chain_spec)
                    .verification_gas_limit(verification_gas_limit)
                    .paymaster_verification_gas_limit(paymaster_verification_gas_limit)
                    .call_gas_limit(call_gas_limit)
                    .build();
                op_with_limits.required_pre_verification_gas_with_limits(
                    &self.chain_spec,
                    bundle_size,
                    da_gas,
                    None,
                    Some(verification_gas_limit),
                    Some(paymaster_verification_gas_limit),
                    Some(call_gas_limit),
                )
            } else {
                // Use original op baseline to match validation behavior
                base_op.required_pre_verification_gas(&self.chain_spec, bundle_size, da_gas, None)
            }
        };

        // check the total gas limit
        let op_with_gas = UserOperationBuilder::from_uo(full_op, &self.chain_spec)
            .pre_verification_gas(pre_verification_gas)
            .call_gas_limit(call_gas_limit)
            .verification_gas_limit(verification_gas_limit)
            .paymaster_verification_gas_limit(paymaster_verification_gas_limit)
            .build();

        // require that this can fit in a bundle of size 1
        let gas_limit = op_with_gas.bundle_computation_gas_limit(&self.chain_spec, Some(1));
        if gas_limit > self.settings.max_bundle_execution_gas {
            return Err(GasEstimationError::GasTotalTooLarge(
                gas_limit,
                self.settings.max_bundle_execution_gas,
            ));
        } else if op_with_gas.calldata_floor_gas_limit() > self.settings.max_bundle_execution_gas {
            return Err(GasEstimationError::GasTotalTooLarge(
                op_with_gas.calldata_floor_gas_limit(),
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
                op.max_fill(&self.chain_spec).calldata_floor_gas_limit(),
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
            chain_spec.clone(),
            settings,
            provider.clone(),
            VerificationGasEstimatorSpecializationV07 {
                entry_point: entry_point.clone(),
            },
        );

        let paymaster_verification_gas_estimator = VerificationGasEstimatorImpl::new(
            chain_spec.clone(),
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
        if let Some(vl) = optional_op.verification_gas_limit {
            if vl > self.settings.max_verification_gas {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "verificationGasLimit",
                    self.settings.max_verification_gas,
                ));
            }
        }
        if let Some(vl) = optional_op.paymaster_verification_gas_limit {
            if vl > self.settings.max_verification_gas {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "paymasterVerificationGasLimit",
                    self.settings.max_verification_gas,
                ));
            }
        }
        if let Some(cl) = optional_op.call_gas_limit {
            if cl > self.settings.max_bundle_execution_gas {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "callGasLimit",
                    self.settings.max_bundle_execution_gas,
                ));
            }
        }
        if let Some(cl) = optional_op.paymaster_post_op_gas_limit {
            if cl > self.settings.max_bundle_execution_gas {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "paymasterPostOpGasLimit",
                    self.settings.max_bundle_execution_gas,
                ));
            }
        }

        Ok(())
    }

    #[instrument(skip_all)]
    async fn estimate_verification_gas(
        &self,
        optional_op: &UserOperationOptionalGas,
        full_op: &UserOperation,
        block_hash: B256,
        state_override: StateOverride,
    ) -> Result<u128, GasEstimationError> {
        // if set and non-zero, don't estimate
        if let Some(vl) = optional_op.verification_gas_limit {
            if vl != 0 {
                // No need to do an extra simulation here, if the user provides a value that is
                // insufficient it will cause a revert during call gas estimation (or simulation).
                return Ok(vl);
            }
        }

        let _timer = CustomTimerGuard::new(self.metrics.vgl_estimate_ms.clone());
        let now = Instant::now();

        let verification_gas_limit = self
            .verification_gas_estimator
            .estimate_verification_gas(full_op, block_hash, state_override)
            .await?;

        let verification_gas_limit = math::increase_by_percent(
            verification_gas_limit,
            super::VERIFICATION_GAS_BUFFER_PERCENT,
        )
        .min(self.settings.max_verification_gas);

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

        if let Some(pvl) = optional_op.paymaster_verification_gas_limit {
            if pvl != 0 {
                return Ok(pvl);
            }
        }

        let _timer = CustomTimerGuard::new(self.metrics.pvgl_estimate_ms.clone());
        let now = Instant::now();

        let paymaster_verification_gas_limit = self
            .paymaster_verification_gas_estimator
            .estimate_verification_gas(full_op, block_hash, state_override)
            .await?;

        let paymaster_verification_gas_limit = math::increase_by_percent(
            paymaster_verification_gas_limit,
            super::VERIFICATION_GAS_BUFFER_PERCENT,
        )
        .min(self.settings.max_verification_gas);

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
        if let Some(cl) = optional_op.call_gas_limit {
            if cl != 0 {
                // The user provided a non-zero value, simulate once
                self.call_gas_estimator
                    .simulate_handle_op_with_result(full_op, block_hash, state_override)
                    .await?;
                return Ok(cl);
            }
        }

        let call_gas_limit = self
            .call_gas_estimator
            .estimate_call_gas(full_op, block_hash, state_override)
            .await?;

        // Add a buffer to the call gas limit and clamp
        let call_gas_limit = call_gas_limit
            .add(super::CALL_GAS_BUFFER_VALUE)
            .clamp(MIN_CALL_GAS_LIMIT, self.settings.max_bundle_execution_gas);

        Ok(call_gas_limit)
    }
}

/// Implementation of functions that specialize the call gas estimator to the
/// v0.7 entry point.
#[derive(Debug, Clone)]
pub struct CallGasEstimatorSpecializationV07 {
    chain_spec: ChainSpec,
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
                code: Some(ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE.clone()),
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
            code: Some(ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE.clone()),
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
        add_proxy_to_overrides(*self.entry_point.address(), to_override, state_override);
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
        add_proxy_to_overrides(*self.entry_point.address(), to_override, state_override);
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
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::{hex, U256};
    use alloy_sol_types::{Revert, SolError};
    use rundler_contracts::common::EstimationTypes::TestCallGasResult;
    use rundler_provider::{
        ExecutionResult, MockEntryPointV0_7, MockEvmProvider, MockFeeEstimator,
    };
    use rundler_types::v0_7::UserOperationOptionalGas;

    use super::*;
    use crate::{
        estimation::estimate_call_gas::PROXY_IMPLEMENTATION_ADDRESS_MARKER, GasEstimator as _,
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

    #[tokio::test]
    async fn test_return_provided_limits() {
        let (mut entry, mut provider) = create_base_config();

        provider
            .expect_get_latest_block_hash_and_number()
            .returning(|| Ok((B256::ZERO, 0)));

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
    async fn test_provided_reverts() {
        let (mut entry, mut provider) = create_base_config();

        provider
            .expect_get_latest_block_hash_and_number()
            .returning(|| Ok((B256::ZERO, 0)));

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
            .expect_get_latest_block_hash_and_number()
            .returning(|| Ok((B256::ZERO, 0)));

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
}
