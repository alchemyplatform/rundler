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

use std::{cmp, ops::Add};

use alloy_primitives::{fixed_bytes, Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_types::SolInterface;
use rand::Rng;
use rundler_contracts::v0_7::{
    CallGasEstimationProxy::{
        estimateCallGasCall, testCallGasCall, CallGasEstimationProxyCalls, EstimateCallGasArgs,
    },
    CALL_GAS_ESTIMATION_PROXY_V0_7_DEPLOYED_BYTECODE,
    ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE,
};
use rundler_provider::{
    AccountOverride, DAGasProvider, EntryPoint, EvmProvider, SimulationProvider, StateOverride,
};
use rundler_types::{
    chain::ChainSpec,
    v0_7::{UserOperation, UserOperationBuilder, UserOperationOptionalGas},
    GasEstimate, UserOperation as _,
};
use rundler_utils::math;
use tokio::join;

use super::{estimate_verification_gas::GetOpWithLimitArgs, GasEstimationError, Settings};
use crate::{
    gas, CallGasEstimator, CallGasEstimatorImpl, CallGasEstimatorSpecialization, FeeEstimator,
    VerificationGasEstimator, VerificationGasEstimatorImpl, MIN_CALL_GAS_LIMIT,
};

/// Gas estimator for entry point v0.7
pub struct GasEstimator<P, E, VGE, CGE, F> {
    chain_spec: ChainSpec,
    provider: P,
    entry_point: E,
    settings: Settings,
    fee_estimator: F,
    verification_gas_estimator: VGE,
    call_gas_estimator: CGE,
}

fn apply_7702_overrides(
    state_override: &mut StateOverride,
    sender: Address,
    contract_address: Address,
) {
    let prefix: FixedBytes<3> = fixed_bytes!("ef0100");
    let code: FixedBytes<23> = prefix.concat_const(contract_address.into());
    state_override.insert(
        sender,
        AccountOverride {
            code: Some(code.into()),
            ..Default::default()
        },
    );
}

#[async_trait::async_trait]
impl<P, E, VGE, CGE, F> super::GasEstimator for GasEstimator<P, E, VGE, CGE, F>
where
    P: EvmProvider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + DAGasProvider<UO = UserOperation>,
    VGE: VerificationGasEstimator<UO = UserOperation>,
    CGE: CallGasEstimator<UO = UserOperation>,
    F: FeeEstimator,
{
    type UserOperationOptionalGas = UserOperationOptionalGas;

    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
        state_override: StateOverride,
    ) -> Result<GasEstimate, GasEstimationError> {
        self.check_provided_limits(&op)?;

        let mut local_override = state_override.clone();
        if let Some(au) = &op.contract_address {
            apply_7702_overrides(&mut local_override, op.sender, *au);
        }
        let Self {
            provider, settings, ..
        } = self;

        let (block_hash, _) = provider
            .get_latest_block_hash_and_number()
            .await
            .map_err(anyhow::Error::from)?;

        let pre_verification_gas = self.estimate_pre_verification_gas(&op, block_hash).await?;

        let full_op = op
            .clone()
            .into_user_operation_builder(
                &self.chain_spec,
                settings.max_call_gas,
                settings.max_verification_gas,
                settings.max_paymaster_verification_gas,
            )
            .pre_verification_gas(pre_verification_gas)
            .build();

        let verification_gas_future =
            self.estimate_verification_gas(&op, &full_op, block_hash, local_override.clone());

        let paymaster_verification_gas_future = self.estimate_paymaster_verification_gas(
            &op,
            &full_op,
            block_hash,
            local_override.clone(),
        );
        let call_gas_future =
            self.estimate_call_gas(&op, full_op.clone(), block_hash, local_override);

        // Not try_join! because then the output is nondeterministic if multiple calls fail.
        let timer = std::time::Instant::now();
        let (verification_gas_limit, paymaster_verification_gas_limit, call_gas_limit) = join!(
            verification_gas_future,
            paymaster_verification_gas_future,
            call_gas_future
        );
        tracing::debug!("gas estimation took {}ms", timer.elapsed().as_millis());

        let verification_gas_limit = verification_gas_limit?;
        let paymaster_verification_gas_limit = paymaster_verification_gas_limit?;
        let call_gas_limit = call_gas_limit?;

        // check the total gas limit
        let mut op_with_gas = full_op;
        op_with_gas.pre_verification_gas = pre_verification_gas;
        op_with_gas.call_gas_limit = call_gas_limit;
        op_with_gas.verification_gas_limit = verification_gas_limit;
        op_with_gas.paymaster_verification_gas_limit = paymaster_verification_gas_limit;
        // require that this can fit in a bundle of size 1
        let gas_limit = op_with_gas.execution_gas_limit(&self.chain_spec, Some(1));
        if gas_limit > self.settings.max_total_execution_gas {
            return Err(GasEstimationError::GasTotalTooLarge(
                gas_limit,
                self.settings.max_total_execution_gas,
            ));
        }

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
        VerificationGasEstimatorImpl<P, E>,
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
            provider.clone(),
            entry_point.clone(),
            settings,
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
            call_gas_estimator,
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
        if let Some(vl) = optional_op.paymaster_verification_gas_limit {
            if vl > self.settings.max_verification_gas {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "paymasterVerificationGasLimit",
                    self.settings.max_verification_gas,
                ));
            }
        }
        if let Some(cl) = optional_op.call_gas_limit {
            if cl > self.settings.max_call_gas {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "callGasLimit",
                    self.settings.max_call_gas,
                ));
            }
        }
        if let Some(cl) = optional_op.paymaster_post_op_gas_limit {
            if cl > self.settings.max_call_gas {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "paymasterPostOpGasLimit",
                    self.settings.max_call_gas,
                ));
            }
        }

        Ok(())
    }

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

        let get_op_with_limit = |op: UserOperation, args: GetOpWithLimitArgs| {
            let GetOpWithLimitArgs { gas, fee } = args;
            UserOperationBuilder::from_uo(op, &self.chain_spec)
                .verification_gas_limit(gas)
                .max_fee_per_gas(fee)
                .max_priority_fee_per_gas(fee)
                .paymaster_post_op_gas_limit(0)
                .call_gas_limit(0)
                .build()
        };

        let verification_gas_limit = self
            .verification_gas_estimator
            .estimate_verification_gas(
                full_op,
                block_hash,
                state_override,
                self.settings.max_verification_gas,
                get_op_with_limit,
            )
            .await?;

        let verification_gas_limit = math::increase_by_percent(
            verification_gas_limit,
            super::VERIFICATION_GAS_BUFFER_PERCENT,
        )
        .min(self.settings.max_verification_gas);

        Ok(verification_gas_limit)
    }

    async fn estimate_paymaster_verification_gas(
        &self,
        optional_op: &UserOperationOptionalGas,
        full_op: &UserOperation,
        block_hash: B256,
        state_override: StateOverride,
    ) -> Result<u128, GasEstimationError> {
        // If not using paymaster, return zero, else if set and non-zero, don't estimate and return value
        if let Some(pvl) = optional_op.verification_gas_limit {
            if pvl != 0 {
                return Ok(pvl);
            }
        }

        let get_op_with_limit = |op: UserOperation, args: GetOpWithLimitArgs| {
            let GetOpWithLimitArgs { gas, fee } = args;
            UserOperationBuilder::from_uo(op, &self.chain_spec)
                .max_fee_per_gas(fee)
                .max_priority_fee_per_gas(fee)
                .paymaster_verification_gas_limit(gas)
                .paymaster_post_op_gas_limit(0)
                .call_gas_limit(0)
                .build()
        };

        let paymaster_verification_gas_limit = self
            .verification_gas_estimator
            .estimate_verification_gas(
                full_op,
                block_hash,
                state_override,
                self.settings.max_paymaster_verification_gas,
                get_op_with_limit,
            )
            .await?;

        let paymaster_verification_gas_limit = math::increase_by_percent(
            paymaster_verification_gas_limit,
            super::VERIFICATION_GAS_BUFFER_PERCENT,
        )
        .min(self.settings.max_verification_gas);

        Ok(paymaster_verification_gas_limit)
    }

    async fn estimate_pre_verification_gas(
        &self,
        optional_op: &UserOperationOptionalGas,
        block_hash: B256,
    ) -> Result<u128, GasEstimationError> {
        if let Some(pvg) = optional_op.pre_verification_gas {
            if pvg != 0 {
                return Ok(pvg);
            }
        }

        // If not using calldata pre-verification gas, return 0
        let gas_price = if !self.chain_spec.da_pre_verification_gas {
            0
        } else {
            // If the user provides fees, use them, otherwise use the current bundle fees
            let (bundle_fees, base_fee) = self.fee_estimator.required_bundle_fees(None).await?;
            if let (Some(max_fee), Some(prio_fee)) = (
                optional_op.max_fee_per_gas.filter(|fee| *fee != 0),
                optional_op.max_priority_fee_per_gas.filter(|fee| *fee != 0),
            ) {
                cmp::min(max_fee, base_fee.saturating_add(prio_fee))
            } else {
                base_fee.saturating_add(bundle_fees.max_priority_fee_per_gas)
            }
        };

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

    async fn estimate_call_gas(
        &self,
        optional_op: &UserOperationOptionalGas,
        full_op: UserOperation,
        block_hash: B256,
        state_override: StateOverride,
    ) -> Result<u128, GasEstimationError> {
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
            .clamp(MIN_CALL_GAS_LIMIT, self.settings.max_call_gas);

        Ok(call_gas_limit)
    }
}

/// Implementation of functions that specialize the call gas estimator to the
/// v0.7 entry point.
#[derive(Debug)]
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
        let moved_entry_point_address: Address = rand::thread_rng().gen();

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
        rounding: u128,
        is_continuation: bool,
    ) -> Bytes {
        let call = CallGasEstimationProxyCalls::estimateCallGas(estimateCallGasCall {
            args: EstimateCallGasArgs {
                userOp: callless_op.pack(),
                minGas: U256::from(min_gas),
                maxGas: U256::from(max_gas),
                rounding: U256::from(rounding),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::{hex, U256};
    use alloy_sol_types::{Revert, SolCall, SolError};
    use gas::MockFeeEstimator;
    use rundler_contracts::v0_7::{
        CallGasEstimationProxy::TestCallGasResult, IEntryPointSimulations,
    };
    use rundler_provider::{EvmCall, ExecutionResult, MockEntryPointV0_7, MockEvmProvider};
    use rundler_types::v0_7::UserOperationOptionalGas;

    use super::*;
    use crate::{
        estimation::estimate_call_gas::PROXY_IMPLEMENTATION_ADDRESS_MARKER, GasEstimator as _,
    };

    // Alises for complex types (which also satisfy Clippy)
    type VerificationGasEstimatorWithMocks =
        VerificationGasEstimatorImpl<Arc<MockEvmProvider>, Arc<MockEntryPointV0_7>>;
    type CallGasEstimatorWithMocks =
        CallGasEstimatorImpl<Arc<MockEntryPointV0_7>, CallGasEstimatorSpecializationV07>;
    type GasEstimatorWithMocks = GasEstimator<
        Arc<MockEvmProvider>,
        Arc<MockEntryPointV0_7>,
        VerificationGasEstimatorWithMocks,
        CallGasEstimatorWithMocks,
        MockFeeEstimator,
    >;

    fn create_base_config() -> (MockEntryPointV0_7, MockEvmProvider) {
        let mut entry = MockEntryPointV0_7::new();
        let provider = MockEvmProvider::new();

        // Fill in concrete implementations of call data and
        // `simulation_should_revert`
        entry
            .expect_get_simulate_handle_op_call()
            .returning(|op, state_override| {
                let data = IEntryPointSimulations::simulateHandleOpCall {
                    op: op.pack(),
                    target: Address::ZERO,
                    targetCallData: Bytes::new(),
                }
                .abi_encode()
                .into();

                EvmCall {
                    to: Address::ZERO,
                    data,
                    value: U256::ZERO,
                    state_override,
                }
            });
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
            max_call_gas: TEST_MAX_GAS_LIMITS,
            max_paymaster_verification_gas: TEST_MAX_GAS_LIMITS,
            max_paymaster_post_op_gas: TEST_MAX_GAS_LIMITS,
            max_total_execution_gas: TEST_MAX_GAS_LIMITS,
            max_simulate_handle_ops_gas: TEST_MAX_GAS_LIMITS.try_into().unwrap(),
            verification_estimation_gas_fee: 1_000_000_000_000,
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
            contract_address: None,
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
            .expect_simulate_handle_op()
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
            .expect_simulate_handle_op()
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
            .expect_simulate_handle_op()
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
            contract_address: None,
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
