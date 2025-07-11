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

use std::{cmp, ops::Add, time::Instant};

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolInterface};
use rundler_contracts::v0_6::{
    CallGasEstimationProxy::{
        estimateCallGasCall, testCallGasCall, CallGasEstimationProxyCalls, EstimateCallGasArgs,
    },
    VerificationGasEstimationHelper::{
        estimateVerificationGasCall, EstimateGasArgs as ContractEstimateGasArgs,
    },
    CALL_GAS_ESTIMATION_PROXY_V0_6_DEPLOYED_BYTECODE, ENTRY_POINT_V0_6_DEPLOYED_BYTECODE,
    VERIFICATION_GAS_ESTIMATION_HELPER_V0_6_DEPLOYED_BYTECODE,
};
use rundler_provider::{
    AccountOverride, DAGasProvider, EntryPoint, EvmProvider, FeeEstimator, SimulationProvider,
    StateOverride,
};
use rundler_types::{
    self,
    chain::ChainSpec,
    v0_6::{UserOperation, UserOperationBuilder, UserOperationOptionalGas},
    GasEstimate, UserOperation as _,
};
use rundler_utils::{guard_timer::CustomTimerGuard, math};
use tokio::join;
use tracing::instrument;

use super::{
    estimate_verification_gas::VerificationGasEstimatorSpecialization, CallGasEstimator,
    CallGasEstimatorImpl, CallGasEstimatorSpecialization, GasEstimationError, Metrics, Settings,
    VerificationGasEstimator,
};
use crate::{
    estimation::estimate_verification_gas::EstimateGasArgs, gas, precheck::MIN_CALL_GAS_LIMIT,
    simulation, GasEstimator as GasEstimatorTrait, VerificationGasEstimatorImpl,
};

/// Gas estimator implementation
pub struct GasEstimator<P, E, VGE, CGE, F> {
    chain_spec: ChainSpec,
    provider: P,
    entry_point: E,
    settings: Settings,
    fee_estimator: F,
    verification_gas_estimator: VGE,
    call_gas_estimator: CGE,
    metrics: Metrics,
}

#[async_trait::async_trait]
impl<P, E, VGE, CGE, F> GasEstimatorTrait for GasEstimator<P, E, VGE, CGE, F>
where
    P: EvmProvider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + DAGasProvider<UO = UserOperation>,
    VGE: VerificationGasEstimator<UO = UserOperation>,
    CGE: CallGasEstimator<UO = UserOperation>,
    F: FeeEstimator,
{
    type UserOperationOptionalGas = UserOperationOptionalGas;

    #[instrument(skip_all)]
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
        state_override: StateOverride,
    ) -> Result<GasEstimate, GasEstimationError> {
        let _timer = CustomTimerGuard::new(self.metrics.total_gas_estimate_ms.clone());
        self.check_provided_limits(&op)?;

        let agg = op
            .aggregator
            .map(|agg| {
                self.chain_spec
                    .get_signature_aggregator(&agg)
                    .ok_or(GasEstimationError::UnsupportedAggregator(agg))
            })
            .transpose()?;

        let (block_hash, _) = self
            .provider
            .get_latest_block_hash_and_number()
            .await
            .map_err(anyhow::Error::from)?;

        let mut full_op = op
            .clone()
            .into_user_operation_builder(
                &self.chain_spec,
                self.settings.max_bundle_execution_gas,
                self.settings.max_verification_gas,
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

        let pre_verification_gas_future = self.estimate_pre_verification_gas(&op, block_hash);

        let verification_future =
            self.estimate_verification_gas(&op, &full_op, block_hash, state_override.clone());
        let call_future = self.estimate_call_gas(&op, full_op.clone(), block_hash, state_override);

        // Not try_join! because then the output is nondeterministic if both
        // verification and call estimation fail.
        let (pvg_result, verification_gas_limit_result, call_gas_limit_result) = join!(
            pre_verification_gas_future,
            verification_future,
            call_future
        );
        let (pre_verification_gas, da_gas) = pvg_result?;
        let verification_gas_limit = verification_gas_limit_result?;
        let call_gas_limit = call_gas_limit_result?;

        // Verify total gas limit
        let op_with_gas = UserOperationBuilder::from_uo(full_op, &self.chain_spec)
            .verification_gas_limit(verification_gas_limit)
            .call_gas_limit(call_gas_limit)
            .pre_verification_gas(pre_verification_gas)
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
            verification_gas_limit,
            call_gas_limit,
            paymaster_verification_gas_limit: None,
        })
    }
}

impl<P, E, F>
    GasEstimator<
        P,
        E,
        VerificationGasEstimatorImpl<VerificationGasEstimatorSpecializationV06<E>, P>,
        CallGasEstimatorImpl<E, CallGasEstimatorSpecializationV06>,
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
            VerificationGasEstimatorSpecializationV06 {
                entry_point: entry_point.clone(),
            },
        );
        let call_gas_estimator = CallGasEstimatorImpl::new(
            entry_point.clone(),
            settings,
            CallGasEstimatorSpecializationV06 {
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
            call_gas_estimator,
            metrics: Metrics::default(),
        }
    }
}

impl<P, E, VGE, CGE, F> GasEstimator<P, E, VGE, CGE, F>
where
    P: EvmProvider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + DAGasProvider<UO = UserOperation>,
    VGE: VerificationGasEstimator<UO = UserOperation>,
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
        if let Some(cl) = optional_op.call_gas_limit {
            if cl > self.settings.max_bundle_execution_gas {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "callGasLimit",
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

        let verification_gas_limit: u128 = self
            .verification_gas_estimator
            .estimate_verification_gas(full_op, block_hash, state_override)
            .await?;

        // Add a buffer to the verification gas limit. Add 10% or 2000 gas, whichever is larger
        // to ensure we get at least a 2000 gas buffer. Cap at the max verification gas.
        let verification_gas_limit = cmp::max(
            math::increase_by_percent(
                verification_gas_limit,
                super::VERIFICATION_GAS_BUFFER_PERCENT,
            ),
            verification_gas_limit + simulation::v0_6::REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER,
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
    async fn estimate_pre_verification_gas(
        &self,
        optional_op: &UserOperationOptionalGas,
        block_hash: B256,
    ) -> Result<(u128, u128), GasEstimationError> {
        if let Some(pvg) = optional_op.pre_verification_gas {
            if pvg != 0 {
                return Ok((pvg, 0));
            }
        }

        let _timer = CustomTimerGuard::new(self.metrics.pvg_estimate_ms.clone());

        // If not using calldata pre-verification gas, return 0
        let gas_price = if !self.chain_spec.da_pre_verification_gas {
            0
        } else {
            // If the user provides fees, use them, otherwise use the current bundle fees
            let (bundle_fees, base_fee) = self
                .fee_estimator
                .required_bundle_fees(block_hash, None)
                .await?;
            if let (Some(max_fee), Some(prio_fee)) = (
                optional_op.max_fee_per_gas.filter(|fee| *fee != 0),
                optional_op.max_priority_fee_per_gas.filter(|fee| *fee != 0),
            ) {
                cmp::min(max_fee, base_fee.saturating_add(prio_fee))
            } else {
                base_fee.saturating_add(bundle_fees.max_priority_fee_per_gas)
            }
        };

        if let Some(agg) = &optional_op.aggregator {
            if self.chain_spec.get_signature_aggregator(agg).is_none() {
                return Err(GasEstimationError::UnsupportedAggregator(*agg));
            };
        }

        Ok(gas::estimate_pre_verification_gas(
            &self.chain_spec,
            &self.entry_point,
            &optional_op.max_fill(&self.chain_spec),
            &optional_op.random_fill(&self.chain_spec),
            block_hash.into(),
            gas_price,
        )
        .await?)
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
/// v0.6 entry point.
#[derive(Debug, Clone)]
pub struct CallGasEstimatorSpecializationV06 {
    chain_spec: ChainSpec,
}

impl CallGasEstimatorSpecialization for CallGasEstimatorSpecializationV06 {
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
                code: Some(ENTRY_POINT_V0_6_DEPLOYED_BYTECODE.clone()),
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
        UserOperationBuilder::from_uo(op, &self.chain_spec)
            .clear_paymaster()
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
        let op = callless_op.into_unstructured();
        let call = CallGasEstimationProxyCalls::estimateCallGas(estimateCallGasCall {
            args: EstimateCallGasArgs {
                callData: op.call_data,
                sender: op.sender,
                minGas: U256::from(min_gas),
                maxGas: U256::from(max_gas),
                allowedErrorPct: U256::from(allowed_error_pct),
                isContinuation: is_continuation,
            },
        });

        call.abi_encode().into()
    }

    fn get_test_call_gas_calldata(&self, callless_op: Self::UO, call_gas_limit: u128) -> Bytes {
        let op = callless_op.into_unstructured();
        let call = CallGasEstimationProxyCalls::testCallGas(testCallGasCall {
            sender: op.sender,
            callData: op.call_data,
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
const PROXY_TARGET_OFFSET: usize = 180;

// Replaces the address of the proxy target where it appears in the proxy
// bytecode so we don't need the same fixed address every time.
fn estimation_proxy_bytecode_with_target(target: Address) -> Bytes {
    let mut vec = CALL_GAS_ESTIMATION_PROXY_V0_6_DEPLOYED_BYTECODE.to_vec();
    let bytes: [u8; 20] = target.into();
    vec[PROXY_TARGET_OFFSET..PROXY_TARGET_OFFSET + 20].copy_from_slice(&bytes);
    vec.into()
}

#[derive(Clone)]
pub struct VerificationGasEstimatorSpecializationV06<EP> {
    entry_point: EP,
}

impl<EP> VerificationGasEstimatorSpecialization for VerificationGasEstimatorSpecializationV06<EP>
where
    EP: EntryPoint + SimulationProvider,
{
    type UO = UserOperation;

    fn add_proxy_to_overrides(&self, to_override: Address, state_override: &mut StateOverride) {
        state_override.insert(
            to_override,
            AccountOverride {
                code: Some(VERIFICATION_GAS_ESTIMATION_HELPER_V0_6_DEPLOYED_BYTECODE.clone()),
                ..Default::default()
            },
        );
    }

    fn get_call(&self, op: Self::UO, args: &EstimateGasArgs) -> Bytes {
        estimateVerificationGasCall {
            args: ContractEstimateGasArgs {
                entryPoint: *self.entry_point.address(),
                userOp: op.into(),
                minGas: U256::from(args.min_gas),
                maxGas: U256::from(args.max_gas),
                allowedErrorPct: U256::from(args.allowed_error_pct),
                isContinuation: args.is_continuation,
                constantFee: U256::from(args.constant_fee),
            },
        }
        .abi_encode()
        .into()
    }

    fn decode_revert(&self, revert_data: &Bytes) -> GasEstimationError {
        match EP::decode_simulate_handle_ops_revert(revert_data) {
            Ok(Ok(res)) => GasEstimationError::Other(anyhow::anyhow!(
                "unexpected result from simulate_handle_ops: {:?}",
                res
            )),
            Ok(Err(e)) => GasEstimationError::RevertInValidation(e),
            Err(e) => GasEstimationError::ProviderError(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::{hex, uint};
    use alloy_sol_types::{Revert, SolError, SolValue};
    use rundler_contracts::{
        common::EstimationTypes::*,
        v0_6::{
            GetBalances::{GetBalancesErrors, GetBalancesResult},
            UserOperation as ContractUserOperation,
        },
    };
    use rundler_provider::{
        ExecutionResult, GasUsedResult, MockEntryPointV0_6, MockEvmProvider, MockFeeEstimator,
        ProviderError,
    };
    use rundler_types::{
        da::DAGasOracleType,
        v0_6::{UserOperation, UserOperationOptionalGas, UserOperationRequiredFields},
        GasFees,
    };
    use serde_json::value::RawValue;

    use super::*;
    use crate::{
        estimation::{
            estimate_call_gas::PROXY_IMPLEMENTATION_ADDRESS_MARKER, CALL_GAS_BUFFER_VALUE,
            VERIFICATION_GAS_BUFFER_PERCENT,
        },
        simulation::v0_6::REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER,
        VerificationGasEstimatorImpl,
    };

    // Gas overhead defaults
    const FIXED: u32 = 21000;
    const PER_USER_OP: u32 = 18300;
    const PER_USER_OP_WORD: u32 = 4;
    const BUNDLE_SIZE: u32 = 1;

    // Alises for complex types (which also satisfy Clippy)
    type VerificationGasEstimatorWithMocks = VerificationGasEstimatorImpl<
        VerificationGasEstimatorSpecializationV06<Arc<MockEntryPointV0_6>>,
        Arc<MockEvmProvider>,
    >;
    type CallGasEstimatorWithMocks =
        CallGasEstimatorImpl<Arc<MockEntryPointV0_6>, CallGasEstimatorSpecializationV06>;
    type GasEstimatorWithMocks = GasEstimator<
        Arc<MockEvmProvider>,
        Arc<MockEntryPointV0_6>,
        VerificationGasEstimatorWithMocks,
        CallGasEstimatorWithMocks,
        MockFeeEstimator,
    >;

    fn create_base_config() -> (MockEntryPointV0_6, MockEvmProvider) {
        let mut entry = MockEntryPointV0_6::new();
        let provider = MockEvmProvider::new();

        // Fill in concrete implementations of call data and
        // `simulation_should_revert`
        entry.expect_simulation_should_revert().return_const(true);

        entry.expect_address().return_const(Address::ZERO);

        (entry, provider)
    }

    fn add_verification_gas_result<S: SolInterface + Send + Sync + 'static>(
        provider: &mut MockEvmProvider,
        result: S,
    ) {
        provider.expect_call().returning(move |_a, _b, _c| {
            Err(ProviderError::RPC(
                alloy_transport::TransportError::ErrorResp(alloy_json_rpc::ErrorPayload {
                    code: 0,
                    message: "revert".to_string().into(),
                    data: Some(
                        RawValue::from_string(
                            serde_json::to_string(&serde_json::json!({ "data": format!(
                                "0x{}",
                                hex::encode(result.abi_encode())
                            )}))
                            .unwrap(),
                        )
                        .unwrap(),
                    ),
                }),
            ))
        });
    }

    fn create_custom_estimator(
        chain_spec: ChainSpec,
        provider: MockEvmProvider,
        fee_estimator: MockFeeEstimator,
        entry: MockEntryPointV0_6,
        settings: Settings,
    ) -> GasEstimatorWithMocks {
        let provider = Arc::new(provider);
        GasEstimator::new(
            chain_spec.clone(),
            Arc::clone(&provider),
            Arc::new(entry),
            settings,
            fee_estimator,
        )
    }

    const TEST_MAX_GAS_LIMITS: u128 = 10000000000;
    const TEST_FEE: u128 = 1000;

    fn create_estimator(
        entry: MockEntryPointV0_6,
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
        let estimator = create_custom_estimator(
            ChainSpec::default(),
            provider,
            MockFeeEstimator::new(),
            entry,
            settings,
        );
        (estimator, settings)
    }

    fn demo_user_op_optional_gas(pvg: Option<u128>) -> UserOperationOptionalGas {
        UserOperationOptionalGas {
            sender: Address::ZERO,
            nonce: U256::ZERO,
            init_code: Bytes::new(),
            call_data: Bytes::new(),
            call_gas_limit: None,
            verification_gas_limit: None,
            pre_verification_gas: pvg,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(),
            eip7702_auth_address: None,
            aggregator: None,
        }
    }

    fn demo_user_op() -> UserOperation {
        UserOperationBuilder::new(
            &ChainSpec::default(),
            UserOperationRequiredFields {
                sender: Address::ZERO,
                nonce: U256::ZERO,
                init_code: Bytes::new(),
                call_data: Bytes::new(),
                call_gas_limit: 100,
                verification_gas_limit: 1000,
                pre_verification_gas: 1000,
                max_fee_per_gas: 1000,
                max_priority_fee_per_gas: 1000,
                paymaster_and_data: Bytes::new(),
                signature: Bytes::new(),
            },
        )
        .build()
    }

    #[tokio::test]
    async fn test_calc_pre_verification_input() {
        let (entry, mut provider) = create_base_config();
        provider
            .expect_get_pending_base_fee()
            .returning(|| Ok(TEST_FEE));
        provider
            .expect_get_max_priority_fee()
            .returning(|| Ok(TEST_FEE));

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op_optional_gas(None);
        let (estimation, _) = estimator
            .estimate_pre_verification_gas(&user_op, B256::ZERO)
            .await
            .unwrap();

        let uo = user_op.max_fill(&ChainSpec::default());

        let cuo_bytes = ContractUserOperation::from(uo).abi_encode();
        let length_in_words = cuo_bytes.len().div_ceil(32);
        let mut call_data_cost = 0;
        for b in cuo_bytes.iter() {
            if *b != 0 {
                call_data_cost += 16;
            } else {
                call_data_cost += 4;
            }
        }

        let result = FIXED / BUNDLE_SIZE
            + call_data_cost
            + PER_USER_OP
            + PER_USER_OP_WORD * (length_in_words as u32);

        assert_eq!(result as u128, estimation);
    }

    #[tokio::test]
    async fn test_calc_pre_verification_input_arbitrum() {
        let (mut entry, provider) = create_base_config();
        entry
            .expect_calc_da_gas()
            .returning(|_a, _b, _c, _d| Ok((TEST_FEE, Default::default(), Default::default())));

        let settings = Settings {
            max_verification_gas: 10000000000,
            max_bundle_execution_gas: 10000000000,
            max_gas_estimation_gas: 10000000000,
            max_paymaster_verification_gas: 10000000000,
            max_paymaster_post_op_gas: 10000000000,
            verification_estimation_gas_fee: 1_000_000_000_000,
            verification_gas_limit_efficiency_reject_threshold: 0.5,
            verification_gas_allowed_error_pct: 15,
            call_gas_allowed_error_pct: 15,
            max_gas_estimation_rounds: 3,
        };

        // Chose arbitrum
        let cs = ChainSpec {
            id: 42161,
            da_pre_verification_gas: true,
            da_gas_oracle_type: DAGasOracleType::ArbitrumNitro,
            ..Default::default()
        };
        let provider = Arc::new(provider);

        let mut fee_estimator = MockFeeEstimator::new();
        fee_estimator
            .expect_required_bundle_fees()
            .returning(|_, _| {
                Ok((
                    GasFees {
                        max_fee_per_gas: TEST_FEE,
                        max_priority_fee_per_gas: TEST_FEE,
                    },
                    TEST_FEE,
                ))
            });

        let estimator = GasEstimator::new(
            cs.clone(),
            Arc::clone(&provider),
            Arc::new(entry),
            settings,
            fee_estimator,
        );

        let user_op = demo_user_op_optional_gas(None);
        let (estimation, _) = estimator
            .estimate_pre_verification_gas(&user_op, B256::ZERO)
            .await
            .unwrap();

        let uo = user_op.max_fill(&ChainSpec::default());

        let cuo_bytes = ContractUserOperation::from(uo).abi_encode();
        let length_in_words = cuo_bytes.len().div_ceil(32);
        let mut call_data_cost = 0;
        for b in cuo_bytes.iter() {
            if *b != 0 {
                call_data_cost += 16;
            } else {
                call_data_cost += 4;
            }
        }

        let result = FIXED / BUNDLE_SIZE
            + call_data_cost
            + PER_USER_OP
            + PER_USER_OP_WORD * (length_in_words as u32);

        //Arbitrum DA gas
        let da_gas: u128 = 1000;

        assert_eq!(result as u128 + da_gas, estimation);
    }

    #[tokio::test]
    async fn test_calc_pre_verification_input_op() {
        let (mut entry, provider) = create_base_config();

        entry
            .expect_calc_da_gas()
            .returning(|_a, _b, _c, _d| Ok((TEST_FEE, Default::default(), Default::default())));

        let settings = Settings {
            max_verification_gas: 10000000000,
            max_bundle_execution_gas: 10000000000,
            max_gas_estimation_gas: 10000000000,
            max_paymaster_verification_gas: 10000000000,
            max_paymaster_post_op_gas: 10000000000,
            verification_estimation_gas_fee: 1_000_000_000_000,
            verification_gas_limit_efficiency_reject_threshold: 0.5,
            verification_gas_allowed_error_pct: 15,
            call_gas_allowed_error_pct: 15,
            max_gas_estimation_rounds: 3,
        };

        // Chose OP
        let cs = ChainSpec {
            id: 10,
            da_pre_verification_gas: true,
            da_gas_oracle_type: DAGasOracleType::OptimismBedrock,
            ..Default::default()
        };
        let mut fee_estimator = MockFeeEstimator::new();
        fee_estimator
            .expect_required_bundle_fees()
            .returning(|_, _| {
                Ok((
                    GasFees {
                        max_fee_per_gas: TEST_FEE,
                        max_priority_fee_per_gas: TEST_FEE,
                    },
                    TEST_FEE,
                ))
            });

        let estimator = create_custom_estimator(cs, provider, fee_estimator, entry, settings);

        let user_op = demo_user_op_optional_gas(None);
        let (estimation, _) = estimator
            .estimate_pre_verification_gas(&user_op, B256::ZERO)
            .await
            .unwrap();

        let uo = user_op.max_fill(&ChainSpec::default());

        let cuo_bytes = ContractUserOperation::from(uo).abi_encode();
        let length_in_words = cuo_bytes.len().div_ceil(32);
        let mut call_data_cost = 0;
        for b in cuo_bytes.iter() {
            if *b != 0 {
                call_data_cost += 16;
            } else {
                call_data_cost += 4;
            }
        }

        let result = FIXED / BUNDLE_SIZE
            + call_data_cost
            + PER_USER_OP
            + PER_USER_OP_WORD * (length_in_words as u32);

        //OP DA gas
        let da_gas = 1000;

        assert_eq!(result + da_gas, estimation as u32);
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas() {
        let (entry, mut provider) = create_base_config();
        let gas_usage = 10_000;

        add_verification_gas_result(
            &mut provider,
            EstimationTypesErrors::EstimateGasResult(EstimateGasResult {
                gas: U256::from(gas_usage),
                numRounds: U256::from(10),
            }),
        );

        let (estimator, _) = create_estimator(entry, provider);
        let optional_op = demo_user_op_optional_gas(Some(10000));
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&optional_op, &user_op, B256::ZERO, StateOverride::default())
            .await
            .unwrap();

        // the estimation should be the same as the gas usage plus the buffer
        let expected = gas_usage + ChainSpec::default().deposit_transfer_overhead();
        let expected_with_buffer =
            math::increase_by_percent(expected, VERIFICATION_GAS_BUFFER_PERCENT);

        assert_eq!(expected_with_buffer, estimation);
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_should_not_overflow() {
        let (entry, mut provider) = create_base_config();

        // this gas used number is larger than a u128 max number so we need to
        // check for this overflow
        add_verification_gas_result(
            &mut provider,
            EstimationTypesErrors::EstimateGasResult(EstimateGasResult {
                gas: uint!(1000000000000000000000000000000000000000_U256),
                numRounds: U256::from(10),
            }),
        );

        let (estimator, _) = create_estimator(entry, provider);
        let optional_op = demo_user_op_optional_gas(Some(10000));
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&optional_op, &user_op, B256::ZERO, StateOverride::default())
            .await
            .err();

        assert!(matches!(
            estimation,
            Some(GasEstimationError::GasUsedTooLarge)
        ));
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_success_field() {
        let (entry, mut provider) = create_base_config();

        // this should always revert instead of return success
        provider
            .expect_call()
            .returning(move |_a, _b, _c| Ok(Bytes::new()));

        let (estimator, _) = create_estimator(entry, provider);
        let optional_op = demo_user_op_optional_gas(Some(10000));
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&optional_op, &user_op, B256::ZERO, StateOverride::default())
            .await;

        assert!(estimation.is_err());
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_invalid_message() {
        let (entry, mut provider) = create_base_config();

        // unexpected revert value
        add_verification_gas_result(
            &mut provider,
            GetBalancesErrors::GetBalancesResult(GetBalancesResult { balances: vec![] }),
        );

        let (estimator, _) = create_estimator(entry, provider);
        let optional_op = demo_user_op_optional_gas(Some(10000));
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&optional_op, &user_op, B256::ZERO, StateOverride::default())
            .await;

        assert!(estimation.is_err());
    }

    #[tokio::test]
    async fn test_estimate_call_gas() {
        let (mut entry, mut provider) = create_base_config();

        let gas_estimate = 100_000;
        entry
            .expect_simulate_handle_op_estimate_gas()
            .returning(move |_a, _b, _c, _d, _e| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateGasResult {
                        gas: U256::from(gas_estimate),
                        numRounds: U256::from(10),
                    }
                    .abi_encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });

        provider
            .expect_get_code()
            .returning(|_a, _b| Ok(Bytes::new()));

        let (estimator, _) = create_estimator(entry, provider);
        let optional_op = demo_user_op_optional_gas(None);
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_call_gas(&optional_op, user_op, B256::ZERO, StateOverride::default())
            .await
            .unwrap();

        // result is derived from the spoofed gas_estimate field
        let expected = gas_estimate + CALL_GAS_BUFFER_VALUE;
        assert_eq!(estimation, expected);
    }

    #[tokio::test]
    async fn test_estimate_call_gas_error() {
        let (mut entry, mut provider) = create_base_config();

        // return an invalid response for the ExecutionResult
        // for a successful gas estimation
        entry
            .expect_simulate_handle_op_estimate_gas()
            .returning(|_a, _b, _c, _d, _e| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateGasRevertAtMax {
                        revertData: Bytes::new(),
                    }
                    .abi_encode()
                    .into(),
                    target_success: false,
                    ..Default::default()
                }))
            });

        provider
            .expect_get_code()
            .returning(|_a, _b| Ok(Bytes::new()));

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .call_gas_estimator
            .estimate_call_gas(user_op, B256::ZERO, StateOverride::default())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            estimation,
            GasEstimationError::RevertInCallWithBytes(_)
        ));
    }

    #[tokio::test]
    async fn test_estimate_call_gas_continuation() {
        let (mut entry, mut provider) = create_base_config();

        entry
            .expect_simulate_handle_op_estimate_gas()
            .returning(|_a, _b, _c, _d, _e| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateGasContinuation {
                        minGas: U256::from(100),
                        maxGas: U256::from(100000),
                        numRounds: U256::from(10),
                    }
                    .abi_encode()
                    .into(),
                    target_success: false,
                    ..Default::default()
                }))
            })
            .times(1);
        entry
            .expect_simulate_handle_op_estimate_gas()
            .returning(|_a, _b, _c, _d, _e| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateGasResult {
                        gas: U256::from(200),
                        numRounds: U256::from(10),
                    }
                    .abi_encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            })
            .times(1);

        provider
            .expect_get_code()
            .returning(|_a, _b| Ok(Bytes::new()));

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .call_gas_estimator
            .estimate_call_gas(user_op, B256::ZERO, StateOverride::default())
            .await
            .unwrap();

        // on the second loop of the estimate gas continuation
        // I update the spoofed value to 200

        assert_eq!(estimation, 200);
    }

    #[tokio::test]
    async fn test_estimation_optional_gas_used() {
        let (mut entry, mut provider) = create_base_config();
        let gas_usage = 10_000;

        entry
            .expect_simulate_handle_op_estimate_gas()
            .returning(move |_op, _b, _c, _d, _e| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateGasResult {
                        gas: U256::from(10000),
                        numRounds: U256::from(10),
                    }
                    .abi_encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });

        add_verification_gas_result(
            &mut provider,
            EstimationTypesErrors::EstimateGasResult(EstimateGasResult {
                gas: U256::from(gas_usage),
                numRounds: U256::from(10),
            }),
        );

        provider
            .expect_get_code()
            .returning(|_a, _b| Ok(Bytes::new()));
        provider
            .expect_get_latest_block_hash_and_number()
            .returning(|| Ok((B256::ZERO, 0)));
        provider.expect_get_gas_used().returning(move |_a| {
            Ok(GasUsedResult {
                gasUsed: U256::from(gas_usage),
                success: false,
                result: Bytes::new(),
            })
        });

        provider
            .expect_get_pending_base_fee()
            .returning(|| Ok(TEST_FEE));
        provider
            .expect_get_max_priority_fee()
            .returning(|| Ok(TEST_FEE));

        let (estimator, _) = create_estimator(entry, provider);

        let optional_op = demo_user_op_optional_gas(Some(10000));

        let estimation = estimator
            .estimate_op_gas(optional_op, StateOverride::default())
            .await
            .unwrap();

        // this should be a pass through
        assert_eq!(estimation.pre_verification_gas, 10000);

        // gas used increased by 10%
        let expected = gas_usage + ChainSpec::default().deposit_transfer_overhead as u128;
        assert_eq!(
            estimation.verification_gas_limit,
            cmp::max(
                math::increase_by_percent(expected, 10),
                expected + REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER
            )
        );

        // input gas limit clamped with the set limit in settings and constant MIN
        assert_eq!(estimation.call_gas_limit, 10000 + CALL_GAS_BUFFER_VALUE);
    }

    #[test]
    #[should_panic]
    fn test_estimation_optional_gas_invalid_settings() {
        let (entry, provider) = create_base_config();

        //max_call_gas is less than MIN_CALL_GAS_LIMIT

        let settings = Settings {
            max_verification_gas: 10,
            max_bundle_execution_gas: 10,
            max_gas_estimation_gas: 10,
            max_paymaster_post_op_gas: 10,
            max_paymaster_verification_gas: 10,
            verification_estimation_gas_fee: 1_000_000_000_000,
            verification_gas_limit_efficiency_reject_threshold: 0.5,
            verification_gas_allowed_error_pct: 15,
            call_gas_allowed_error_pct: 15,
            max_gas_estimation_rounds: 3,
        };

        create_custom_estimator(
            ChainSpec::default(),
            provider,
            MockFeeEstimator::new(),
            entry,
            settings,
        );
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
        optional_op.call_gas_limit = Some(TEST_MAX_GAS_LIMITS);
        optional_op.verification_gas_limit = Some(TEST_MAX_GAS_LIMITS);

        let err = estimator
            .estimate_op_gas(optional_op.clone(), StateOverride::default())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            err,
            GasEstimationError::GasTotalTooLarge(_, TEST_MAX_GAS_LIMITS)
        ))
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
        for i in 0..CALL_GAS_ESTIMATION_PROXY_V0_6_DEPLOYED_BYTECODE.len() - 20 {
            if CALL_GAS_ESTIMATION_PROXY_V0_6_DEPLOYED_BYTECODE[i..i + 20] == proxy_target_bytes {
                offsets.push(i);
            }
        }
        assert_eq!(vec![PROXY_TARGET_OFFSET], offsets);
    }
}
