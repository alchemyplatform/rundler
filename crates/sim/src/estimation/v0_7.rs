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

use std::{cmp, ops::Add, sync::Arc};

use ethers::{
    contract::EthCall,
    types::{spoof, Address, Bytes, H256, U128, U256},
};
use rand::Rng;
use rundler_provider::{EntryPoint, L1GasProvider, Provider, SimulationProvider};
use rundler_types::{
    chain::ChainSpec,
    contracts::v0_7::{
        call_gas_estimation_proxy::{
            EstimateCallGasArgs, EstimateCallGasCall, TestCallGasCall,
            CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE,
        },
        entry_point_simulations::ENTRYPOINTSIMULATIONS_DEPLOYED_BYTECODE,
    },
    v0_7::{UserOperation, UserOperationBuilder, UserOperationOptionalGas},
    GasEstimate,
};
use rundler_utils::{eth, math};
use tokio::join;

use super::{estimate_verification_gas::GetOpWithLimitArgs, GasEstimationError, Settings};
use crate::{
    gas, CallGasEstimator, CallGasEstimatorImpl, CallGasEstimatorSpecialization, FeeEstimator,
    VerificationGasEstimator, VerificationGasEstimatorImpl, MIN_CALL_GAS_LIMIT,
};

/// Gas estimator for entry point v0.7
#[derive(Debug)]
pub struct GasEstimator<P, E, VGE, CGE> {
    chain_spec: ChainSpec,
    provider: Arc<P>,
    entry_point: E,
    settings: Settings,
    fee_estimator: FeeEstimator<P>,
    verification_gas_estimator: VGE,
    call_gas_estimator: CGE,
}

#[async_trait::async_trait]
impl<P, E, VGE, CGE> super::GasEstimator for GasEstimator<P, E, VGE, CGE>
where
    P: Provider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + L1GasProvider<UO = UserOperation>,
    VGE: VerificationGasEstimator<UO = UserOperation>,
    CGE: CallGasEstimator<UO = UserOperation>,
{
    type UserOperationOptionalGas = UserOperationOptionalGas;

    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
        state_override: spoof::State,
    ) -> Result<GasEstimate, GasEstimationError> {
        self.check_provided_limits(&op)?;

        let Self {
            provider, settings, ..
        } = self;

        let (block_hash, _) = provider
            .get_latest_block_hash_and_number()
            .await
            .map_err(anyhow::Error::from)?;

        let pre_verification_gas = self.estimate_pre_verification_gas(&op).await?;

        let full_op = op
            .clone()
            .into_user_operation_builder(
                &self.chain_spec,
                settings.max_call_gas.into(),
                settings.max_verification_gas.into(),
                settings.max_paymaster_verification_gas.into(),
            )
            .pre_verification_gas(pre_verification_gas)
            .build();

        let verification_gas_future =
            self.estimate_verification_gas(&op, &full_op, block_hash, &state_override);
        let paymaster_verification_gas_future =
            self.estimate_paymaster_verification_gas(&op, &full_op, block_hash, &state_override);
        let call_gas_future =
            self.estimate_call_gas(&op, full_op.clone(), block_hash, state_override.clone());

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
        let gas_limit =
            gas::user_operation_execution_gas_limit(&self.chain_spec, &op_with_gas, true);
        if gas_limit > self.settings.max_total_execution_gas.into() {
            return Err(GasEstimationError::GasTotalTooLarge(
                gas_limit.as_u64(),
                self.settings.max_total_execution_gas,
            ));
        }

        Ok(GasEstimate {
            pre_verification_gas,
            call_gas_limit: call_gas_limit.into(),
            verification_gas_limit: verification_gas_limit.into(),
            paymaster_verification_gas_limit: op
                .paymaster
                .map(|_| paymaster_verification_gas_limit.into()),
        })
    }
}

impl<P, E>
    GasEstimator<
        P,
        E,
        VerificationGasEstimatorImpl<P, E>,
        CallGasEstimatorImpl<E, CallGasEstimatorSpecializationV07>,
    >
where
    P: Provider,
    E: EntryPoint
        + SimulationProvider<UO = UserOperation>
        + L1GasProvider<UO = UserOperation>
        + Clone,
{
    /// Create a new gas estimator
    pub fn new(
        chain_spec: ChainSpec,
        provider: Arc<P>,
        entry_point: E,
        settings: Settings,
        fee_estimator: FeeEstimator<P>,
    ) -> Self {
        if let Some(err) = settings.validate() {
            panic!("Invalid gas estimator settings: {}", err);
        }

        let verification_gas_estimator = VerificationGasEstimatorImpl::new(
            chain_spec.clone(),
            Arc::clone(&provider),
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

impl<P, E, VGE, CGE> GasEstimator<P, E, VGE, CGE>
where
    P: Provider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + L1GasProvider<UO = UserOperation>,
    VGE: VerificationGasEstimator<UO = UserOperation>,
    CGE: CallGasEstimator<UO = UserOperation>,
{
    fn check_provided_limits(
        &self,
        optional_op: &UserOperationOptionalGas,
    ) -> Result<(), GasEstimationError> {
        if let Some(pvg) = optional_op.pre_verification_gas {
            if pvg > self.settings.max_verification_gas.into() {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "preVerificationGas",
                    self.settings.max_verification_gas,
                ));
            }
        }
        if let Some(vl) = optional_op.verification_gas_limit {
            if vl > self.settings.max_verification_gas.into() {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "verificationGasLimit",
                    self.settings.max_verification_gas,
                ));
            }
        }
        if let Some(vl) = optional_op.paymaster_verification_gas_limit {
            if vl > self.settings.max_verification_gas.into() {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "paymasterVerificationGasLimit",
                    self.settings.max_verification_gas,
                ));
            }
        }
        if let Some(cl) = optional_op.call_gas_limit {
            if cl > self.settings.max_call_gas.into() {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "callGasLimit",
                    self.settings.max_call_gas,
                ));
            }
        }
        if let Some(cl) = optional_op.paymaster_post_op_gas_limit {
            if cl > self.settings.max_call_gas.into() {
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
        block_hash: H256,
        state_override: &spoof::State,
    ) -> Result<U128, GasEstimationError> {
        // if set and non-zero, don't estimate
        if let Some(vl) = optional_op.verification_gas_limit {
            if vl != U128::zero() {
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
                .paymaster_post_op_gas_limit(U128::zero())
                .call_gas_limit(U128::zero())
                .build()
        };

        let verification_gas_limit = self
            .verification_gas_estimator
            .estimate_verification_gas(
                full_op,
                block_hash,
                state_override,
                self.settings.max_verification_gas.into(),
                get_op_with_limit,
            )
            .await?;

        let verification_gas_limit = math::increase_by_percent(
            verification_gas_limit,
            super::VERIFICATION_GAS_BUFFER_PERCENT,
        )
        .min(self.settings.max_verification_gas.into());

        Ok(verification_gas_limit)
    }

    async fn estimate_paymaster_verification_gas(
        &self,
        optional_op: &UserOperationOptionalGas,
        full_op: &UserOperation,
        block_hash: H256,
        state_override: &spoof::State,
    ) -> Result<U128, GasEstimationError> {
        // If not using paymaster, return zero, else if set and non-zero, don't estimate and return value
        if let Some(pvl) = optional_op.verification_gas_limit {
            if pvl != U128::zero() {
                return Ok(pvl);
            }
        }

        let get_op_with_limit = |op: UserOperation, args: GetOpWithLimitArgs| {
            let GetOpWithLimitArgs { gas, fee } = args;
            UserOperationBuilder::from_uo(op, &self.chain_spec)
                .max_fee_per_gas(fee)
                .max_priority_fee_per_gas(fee)
                .paymaster_verification_gas_limit(gas)
                .paymaster_post_op_gas_limit(U128::zero())
                .call_gas_limit(U128::zero())
                .build()
        };

        let paymaster_verification_gas_limit = self
            .verification_gas_estimator
            .estimate_verification_gas(
                full_op,
                block_hash,
                state_override,
                self.settings.max_paymaster_verification_gas.into(),
                get_op_with_limit,
            )
            .await?;

        let paymaster_verification_gas_limit = math::increase_by_percent(
            paymaster_verification_gas_limit,
            super::VERIFICATION_GAS_BUFFER_PERCENT,
        )
        .min(self.settings.max_verification_gas.into());

        Ok(paymaster_verification_gas_limit)
    }

    async fn estimate_pre_verification_gas(
        &self,
        optional_op: &UserOperationOptionalGas,
    ) -> Result<U256, GasEstimationError> {
        if let Some(pvg) = optional_op.pre_verification_gas {
            if pvg != U256::zero() {
                return Ok(pvg);
            }
        }

        // If not using calldata pre-verification gas, return 0
        let gas_price = if !self.chain_spec.calldata_pre_verification_gas {
            U256::zero()
        } else {
            // If the user provides fees, use them, otherwise use the current bundle fees
            let (bundle_fees, base_fee) = self.fee_estimator.required_bundle_fees(None).await?;
            if let (Some(max_fee), Some(prio_fee)) = (
                optional_op.max_fee_per_gas.filter(|fee| !fee.is_zero()),
                optional_op
                    .max_priority_fee_per_gas
                    .filter(|fee| !fee.is_zero()),
            ) {
                cmp::min(max_fee.into(), base_fee.saturating_add(prio_fee.into()))
            } else {
                base_fee.saturating_add(bundle_fees.max_priority_fee_per_gas)
            }
        };

        Ok(gas::estimate_pre_verification_gas(
            &self.chain_spec,
            &self.entry_point,
            &optional_op.max_fill(&self.chain_spec),
            &optional_op.random_fill(&self.chain_spec),
            gas_price,
        )
        .await?)
    }

    async fn estimate_call_gas(
        &self,
        optional_op: &UserOperationOptionalGas,
        full_op: UserOperation,
        block_hash: H256,
        state_override: spoof::State,
    ) -> Result<U128, GasEstimationError> {
        // if set and non-zero, don't estimate
        if let Some(cl) = optional_op.call_gas_limit {
            if cl != U128::zero() {
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
            .clamp(MIN_CALL_GAS_LIMIT, self.settings.max_call_gas.into());

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

    fn add_proxy_to_overrides(&self, ep_to_override: Address, state_override: &mut spoof::State) {
        // For an explanation of what's going on here, see the comment at the
        // top of `CallGasEstimationProxy.sol`.
        // Use a random address for the moved entry point so that users can't
        // intentionally get bad estimates by interacting with the hardcoded
        // address.
        let moved_entry_point_address: Address = rand::thread_rng().gen();
        let estimation_proxy_bytecode =
            estimation_proxy_bytecode_with_target(moved_entry_point_address);
        state_override
            .account(moved_entry_point_address)
            .code(ENTRYPOINTSIMULATIONS_DEPLOYED_BYTECODE.clone());
        state_override
            .account(ep_to_override)
            .code(estimation_proxy_bytecode);
    }

    fn get_op_with_no_call_gas(&self, op: Self::UO) -> Self::UO {
        UserOperationBuilder::from_uo(op, &self.chain_spec)
            .call_gas_limit(U128::zero())
            .max_fee_per_gas(U128::zero())
            .build()
    }

    fn get_estimate_call_gas_calldata(
        &self,
        callless_op: Self::UO,
        min_gas: U256,
        max_gas: U256,
        rounding: U256,
        is_continuation: bool,
    ) -> Bytes {
        eth::call_data_of(
            EstimateCallGasCall::selector(),
            (EstimateCallGasArgs {
                user_op: callless_op.pack(),
                min_gas,
                max_gas,
                rounding,
                is_continuation,
            },),
        )
    }

    fn get_test_call_gas_calldata(&self, callless_op: Self::UO, call_gas_limit: U256) -> Bytes {
        eth::call_data_of(
            TestCallGasCall::selector(),
            (callless_op.pack(), call_gas_limit),
        )
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
    let mut vec = CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE.to_vec();
    vec[PROXY_TARGET_OFFSET..PROXY_TARGET_OFFSET + 20].copy_from_slice(target.as_bytes());
    vec.into()
}

#[cfg(test)]
mod tests {
    use ethers::{
        abi::AbiEncode,
        contract::EthCall,
        types::{Address, U64},
        utils::hex,
    };
    use rundler_provider::{ExecutionResult, MockEntryPointV0_7, MockProvider, SimulateOpCallData};
    use rundler_types::{
        contracts::v0_7::{
            call_gas_estimation_proxy::TestCallGasResult,
            entry_point_simulations::SimulateHandleOpCall,
        },
        v0_7::UserOperationOptionalGas,
    };
    use rundler_utils::eth::{self, ContractRevertError};

    use super::*;
    use crate::{
        estimation::estimate_call_gas::PROXY_IMPLEMENTATION_ADDRESS_MARKER, GasEstimator as _,
        PriorityFeeMode,
    };

    // Alises for complex types (which also satisfy Clippy)
    type VerificationGasEstimatorWithMocks =
        VerificationGasEstimatorImpl<MockProvider, Arc<MockEntryPointV0_7>>;
    type CallGasEstimatorWithMocks =
        CallGasEstimatorImpl<Arc<MockEntryPointV0_7>, CallGasEstimatorSpecializationV07>;
    type GasEstimatorWithMocks = GasEstimator<
        MockProvider,
        Arc<MockEntryPointV0_7>,
        VerificationGasEstimatorWithMocks,
        CallGasEstimatorWithMocks,
    >;

    fn create_base_config() -> (MockEntryPointV0_7, MockProvider) {
        let mut entry = MockEntryPointV0_7::new();
        let provider = MockProvider::new();

        // Fill in concrete implementations of call data and
        // `simulation_should_revert`
        entry
            .expect_get_simulate_op_call_data()
            .returning(|op, spoofed_state| {
                let call_data = eth::call_data_of(
                    SimulateHandleOpCall::selector(),
                    (op.packed().clone(), Address::zero(), Bytes::new()),
                );
                SimulateOpCallData {
                    call_data,
                    spoofed_state: spoofed_state.clone(),
                }
            });
        entry.expect_simulation_should_revert().return_const(true);

        entry.expect_address().return_const(Address::zero());

        (entry, provider)
    }

    fn create_fee_estimator(provider: Arc<MockProvider>) -> FeeEstimator<MockProvider> {
        FeeEstimator::new(
            &ChainSpec::default(),
            provider,
            PriorityFeeMode::BaseFeePercent(0),
            0,
        )
    }

    fn create_custom_estimator(
        chain_spec: ChainSpec,
        provider: MockProvider,
        entry: MockEntryPointV0_7,
        settings: Settings,
    ) -> GasEstimatorWithMocks {
        let provider = Arc::new(provider);
        GasEstimator::new(
            chain_spec.clone(),
            Arc::clone(&provider),
            Arc::new(entry),
            settings,
            create_fee_estimator(provider),
        )
    }

    const TEST_MAX_GAS_LIMITS: u64 = 10000000000;

    fn create_estimator(
        entry: MockEntryPointV0_7,
        provider: MockProvider,
    ) -> (GasEstimatorWithMocks, Settings) {
        let settings = Settings {
            max_verification_gas: TEST_MAX_GAS_LIMITS,
            max_call_gas: TEST_MAX_GAS_LIMITS,
            max_paymaster_verification_gas: TEST_MAX_GAS_LIMITS,
            max_paymaster_post_op_gas: TEST_MAX_GAS_LIMITS,
            max_total_execution_gas: TEST_MAX_GAS_LIMITS,
            max_simulate_handle_ops_gas: TEST_MAX_GAS_LIMITS,
            verification_estimation_gas_fee: 1_000_000_000_000,
        };
        let estimator = create_custom_estimator(ChainSpec::default(), provider, entry, settings);
        (estimator, settings)
    }

    fn demo_user_op_optional_gas(pvg: Option<U256>) -> UserOperationOptionalGas {
        UserOperationOptionalGas {
            sender: Address::zero(),
            nonce: U256::zero(),
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
        }
    }

    #[tokio::test]
    async fn test_pvg_over_max() {
        let (entry, provider) = create_base_config();
        let (estimator, _) = create_estimator(entry, provider);

        let optional_op = demo_user_op_optional_gas(Some(U256::from(TEST_MAX_GAS_LIMITS + 1)));

        let estimation = estimator
            .estimate_op_gas(optional_op, spoof::state())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            estimation,
            GasEstimationError::GasFieldTooLarge("preVerificationGas", TEST_MAX_GAS_LIMITS)
        ));
    }

    #[tokio::test]
    async fn test_vgl_over_max() {
        let (entry, provider) = create_base_config();
        let (estimator, _) = create_estimator(entry, provider);

        let mut optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        optional_op.verification_gas_limit = Some(U128::from(TEST_MAX_GAS_LIMITS + 1));

        let estimation = estimator
            .estimate_op_gas(optional_op, spoof::state())
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

        let mut optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        optional_op.paymaster_verification_gas_limit = Some(U128::from(TEST_MAX_GAS_LIMITS + 1));

        let estimation = estimator
            .estimate_op_gas(optional_op, spoof::state())
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

        let mut optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        optional_op.call_gas_limit = Some(U128::from(TEST_MAX_GAS_LIMITS + 1));

        let estimation = estimator
            .estimate_op_gas(optional_op, spoof::state())
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

        let mut optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        optional_op.paymaster_post_op_gas_limit = Some(U128::from(TEST_MAX_GAS_LIMITS + 1));

        let estimation = estimator
            .estimate_op_gas(optional_op, spoof::state())
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
            .returning(|| Ok((H256::zero(), U64::zero())));

        entry
            .expect_call_spoofed_simulate_op()
            .returning(move |_a, _b, _c, _d, _e, _f| {
                Ok(Ok(ExecutionResult {
                    target_result: TestCallGasResult {
                        success: true,
                        gas_used: 0.into(),
                        revert_data: Bytes::new(),
                    }
                    .encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });

        let (estimator, _) = create_estimator(entry, provider);

        let mut optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        optional_op.call_gas_limit = Some(U128::from(10000));
        optional_op.verification_gas_limit = Some(U128::from(10000));
        optional_op.paymaster = Some(Address::random());
        optional_op.paymaster_verification_gas_limit = Some(U128::from(10000));
        optional_op.paymaster_post_op_gas_limit = Some(U128::from(10000));

        let estimation = estimator
            .estimate_op_gas(optional_op.clone(), spoof::state())
            .await
            .unwrap();

        assert_eq!(
            estimation.pre_verification_gas,
            optional_op.pre_verification_gas.unwrap()
        );
        assert_eq!(
            estimation.verification_gas_limit,
            optional_op.verification_gas_limit.unwrap().into()
        );
        assert_eq!(
            estimation.paymaster_verification_gas_limit,
            optional_op
                .paymaster_verification_gas_limit
                .map(|v| v.into())
        );
        assert_eq!(
            estimation.call_gas_limit,
            optional_op.call_gas_limit.unwrap().into()
        );
    }

    #[tokio::test]
    async fn test_provided_reverts() {
        let (mut entry, mut provider) = create_base_config();

        provider
            .expect_get_latest_block_hash_and_number()
            .returning(|| Ok((H256::zero(), U64::zero())));

        let revert_msg = "test revert".to_string();
        let err = ContractRevertError {
            reason: revert_msg.clone(),
        };

        entry
            .expect_call_spoofed_simulate_op()
            .returning(move |_a, _b, _c, _d, _e, _f| {
                Ok(Ok(ExecutionResult {
                    target_result: TestCallGasResult {
                        success: false,
                        gas_used: 0.into(),
                        revert_data: err.clone().encode().into(),
                    }
                    .encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });

        let (estimator, _) = create_estimator(entry, provider);

        let mut optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        optional_op.call_gas_limit = Some(U128::from(10000));
        optional_op.verification_gas_limit = Some(U128::from(10000));

        let estimation_error = estimator
            .estimate_op_gas(optional_op.clone(), spoof::state())
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
            .expect_call_spoofed_simulate_op()
            .returning(move |_a, _b, _c, _d, _e, _f| {
                Ok(Ok(ExecutionResult {
                    target_result: TestCallGasResult {
                        success: true,
                        gas_used: TEST_MAX_GAS_LIMITS.into(),
                        revert_data: Bytes::new(),
                    }
                    .encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });
        provider
            .expect_get_latest_block_hash_and_number()
            .returning(|| Ok((H256::zero(), U64::zero())));

        let (estimator, _) = create_estimator(entry, provider);

        let optional_op = UserOperationOptionalGas {
            sender: Address::zero(),
            nonce: U256::zero(),
            call_data: Bytes::new(),
            call_gas_limit: Some(TEST_MAX_GAS_LIMITS.into()),
            verification_gas_limit: Some(TEST_MAX_GAS_LIMITS.into()),
            pre_verification_gas: Some(TEST_MAX_GAS_LIMITS.into()),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            signature: Bytes::new(),

            paymaster: None,
            paymaster_data: Bytes::new(),
            paymaster_verification_gas_limit: Some(TEST_MAX_GAS_LIMITS.into()),
            paymaster_post_op_gas_limit: Some(TEST_MAX_GAS_LIMITS.into()),

            factory: None,
            factory_data: Bytes::new(),
        };

        let estimation = estimator
            .estimate_op_gas(optional_op, spoof::state())
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
        for i in 0..CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE.len() - 20 {
            if CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE[i..i + 20] == proxy_target_bytes {
                offsets.push(i);
            }
        }
        assert_eq!(vec![PROXY_TARGET_OFFSET], offsets);
    }
}
