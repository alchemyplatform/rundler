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
    providers::spoof,
    types::{Address, Bytes, H256, U256},
};
use rand::Rng;
use rundler_provider::{EntryPoint, L1GasProvider, Provider, SimulationProvider};
use rundler_types::{
    chain::ChainSpec,
    contracts::{
        v0_6::call_gas_estimation_proxy::{
            EstimateCallGasArgs, EstimateCallGasCall, TestCallGasCall,
            CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE,
        },
        ENTRY_POINT_V0_6_DEPLOYED_BYTECODE,
    },
    v0_6::{UserOperation, UserOperationOptionalGas},
    GasEstimate,
};
use rundler_utils::{eth, math};
use tokio::join;

use super::{
    CallGasEstimator, CallGasEstimatorImpl, CallGasEstimatorSpecialization, GasEstimationError,
    Settings, VerificationGasEstimator,
};
use crate::{
    estimation::estimate_verification_gas::GetOpWithLimitArgs, gas, precheck::MIN_CALL_GAS_LIMIT,
    simulation, FeeEstimator, GasEstimator as GasEstimatorTrait, VerificationGasEstimatorImpl,
};

/// Gas estimator implementation
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
impl<P, E, VGE, CGE> GasEstimatorTrait for GasEstimator<P, E, VGE, CGE>
where
    P: Provider,
    E: EntryPoint + SimulationProvider<UO = UserOperation> + L1GasProvider<UO = UserOperation>,
    VGE: VerificationGasEstimator<UO = UserOperation>,
    CGE: CallGasEstimator<UO = UserOperation>,
{
    type UserOperationOptionalGas = UserOperationOptionalGas;

    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
        state_override: spoof::State,
    ) -> Result<GasEstimate, GasEstimationError> {
        self.check_provided_limits(&op)?;

        let (block_hash, _) = self
            .provider
            .get_latest_block_hash_and_number()
            .await
            .map_err(anyhow::Error::from)?;

        let pre_verification_gas = self.estimate_pre_verification_gas(&op).await?;

        let full_op = UserOperation {
            pre_verification_gas,
            ..op.clone().into_user_operation(
                self.settings.max_call_gas.into(),
                self.settings.max_verification_gas.into(),
            )
        };

        let verification_future =
            self.estimate_verification_gas(&op, &full_op, block_hash, &state_override);
        let call_future =
            self.estimate_call_gas(&op, full_op.clone(), block_hash, state_override.clone());

        // Not try_join! because then the output is nondeterministic if both
        // verification and call estimation fail.
        let timer = std::time::Instant::now();
        let (verification_gas_limit, call_gas_limit) = join!(verification_future, call_future);
        tracing::debug!("gas estimation took {}ms", timer.elapsed().as_millis());

        let verification_gas_limit = verification_gas_limit?;
        let call_gas_limit = call_gas_limit?;

        // Verify total gas limit
        let mut op_with_gas = full_op;
        op_with_gas.verification_gas_limit = verification_gas_limit;
        op_with_gas.call_gas_limit = call_gas_limit;
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
            verification_gas_limit,
            call_gas_limit,
            paymaster_verification_gas_limit: None,
        })
    }
}

impl<P, E>
    GasEstimator<
        P,
        E,
        VerificationGasEstimatorImpl<P, E>,
        CallGasEstimatorImpl<E, CallGasEstimatorSpecializationV06>,
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
            CallGasEstimatorSpecializationV06,
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
        if let Some(cl) = optional_op.call_gas_limit {
            if cl > self.settings.max_call_gas.into() {
                return Err(GasEstimationError::GasFieldTooLarge(
                    "callGasLimit",
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
    ) -> Result<U256, GasEstimationError> {
        // if set and non-zero, don't estimate
        if let Some(vl) = optional_op.verification_gas_limit {
            if vl != U256::zero() {
                // No need to do an extra simulation here, if the user provides a value that is
                // insufficient it will cause a revert during call gas estimation (or simulation).
                return Ok(vl);
            }
        }

        fn get_op_with_limit(op: UserOperation, args: GetOpWithLimitArgs) -> UserOperation {
            let GetOpWithLimitArgs { gas, fee } = args;
            UserOperation {
                verification_gas_limit: gas.into(),
                max_fee_per_gas: fee.into(),
                max_priority_fee_per_gas: fee.into(),
                call_gas_limit: U256::zero(),
                ..op
            }
        }

        let verification_gas_limit: U256 = self
            .verification_gas_estimator
            .estimate_verification_gas(
                full_op,
                block_hash,
                state_override,
                self.settings.max_verification_gas.into(),
                get_op_with_limit,
            )
            .await
            .map(|gas_u128| gas_u128.into())?;

        // Add a buffer to the verification gas limit. Add 10% or 2000 gas, whichever is larger
        // to ensure we get at least a 2000 gas buffer. Cap at the max verification gas.
        let verification_gas_limit = cmp::max(
            math::increase_by_percent(
                verification_gas_limit,
                super::VERIFICATION_GAS_BUFFER_PERCENT,
            ),
            verification_gas_limit + simulation::v0_6::REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER,
        )
        .min(self.settings.max_verification_gas.into());

        Ok(verification_gas_limit)
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
                cmp::min(max_fee, base_fee.saturating_add(prio_fee))
            } else {
                base_fee.saturating_add(bundle_fees.max_priority_fee_per_gas)
            }
        };

        Ok(gas::estimate_pre_verification_gas(
            &self.chain_spec,
            &self.entry_point,
            &optional_op.max_fill(
                self.settings.max_call_gas.into(),
                self.settings.max_verification_gas.into(),
            ),
            &optional_op.random_fill(
                self.settings.max_call_gas.into(),
                self.settings.max_verification_gas.into(),
            ),
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
    ) -> Result<U256, GasEstimationError> {
        // if set and non-zero, don't estimate
        if let Some(cl) = optional_op.call_gas_limit {
            if cl != U256::zero() {
                // The user provided a non-zero value, simulate once
                self.call_gas_estimator
                    .simulate_handle_op_with_result(full_op, block_hash, state_override)
                    .await?;
                return Ok(cl);
            }
        }

        let call_gas_limit: U256 = self
            .call_gas_estimator
            .estimate_call_gas(full_op, block_hash, state_override)
            .await?
            .into();

        // Add a buffer to the call gas limit and clamp
        let call_gas_limit = call_gas_limit
            .add(super::CALL_GAS_BUFFER_VALUE)
            .clamp(MIN_CALL_GAS_LIMIT.into(), self.settings.max_call_gas.into());

        Ok(call_gas_limit)
    }
}

/// Implementation of functions that specialize the call gas estimator to the
/// v0.6 entry point.
#[derive(Debug)]
pub struct CallGasEstimatorSpecializationV06;

impl CallGasEstimatorSpecialization for CallGasEstimatorSpecializationV06 {
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
            .code(ENTRY_POINT_V0_6_DEPLOYED_BYTECODE.clone());
        state_override
            .account(ep_to_override)
            .code(estimation_proxy_bytecode);
    }

    fn get_op_with_no_call_gas(&self, op: Self::UO) -> Self::UO {
        UserOperation {
            call_gas_limit: 0.into(),
            max_fee_per_gas: 0.into(),
            ..op
        }
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
                call_data: callless_op.call_data,
                sender: callless_op.sender,
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
            (callless_op.sender, callless_op.call_data, call_gas_limit),
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
    use anyhow::anyhow;
    use ethers::{
        abi::{AbiEncode, Address},
        contract::EthCall,
        types::{U128, U64},
        utils::hex,
    };
    use rundler_provider::{ExecutionResult, MockEntryPointV0_6, MockProvider, SimulateOpCallData};
    use rundler_types::{
        chain::L1GasOracleContractType,
        contracts::{
            utils::get_gas_used::GasUsedResult,
            v0_6::{
                call_gas_estimation_proxy::{
                    EstimateCallGasContinuation, EstimateCallGasResult, EstimateCallGasRevertAtMax,
                    TestCallGasResult,
                },
                i_entry_point,
            },
        },
        v0_6::{UserOperation, UserOperationOptionalGas},
        UserOperation as UserOperationTrait, ValidationRevert,
    };
    use rundler_utils::eth::{self, ContractRevertError};

    use super::*;
    use crate::{
        estimation::{
            estimate_call_gas::PROXY_IMPLEMENTATION_ADDRESS_MARKER, CALL_GAS_BUFFER_VALUE,
            VERIFICATION_GAS_BUFFER_PERCENT,
        },
        simulation::v0_6::REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER,
        PriorityFeeMode, VerificationGasEstimatorImpl,
    };

    // Gas overhead defaults
    const FIXED: u32 = 21000;
    const PER_USER_OP: u32 = 18300;
    const PER_USER_OP_WORD: u32 = 4;
    const BUNDLE_SIZE: u32 = 1;

    // Alises for complex types (which also satisfy Clippy)
    type VerificationGasEstimatorWithMocks =
        VerificationGasEstimatorImpl<MockProvider, Arc<MockEntryPointV0_6>>;
    type CallGasEstimatorWithMocks =
        CallGasEstimatorImpl<Arc<MockEntryPointV0_6>, CallGasEstimatorSpecializationV06>;
    type GasEstimatorWithMocks = GasEstimator<
        MockProvider,
        Arc<MockEntryPointV0_6>,
        VerificationGasEstimatorWithMocks,
        CallGasEstimatorWithMocks,
    >;

    fn create_base_config() -> (MockEntryPointV0_6, MockProvider) {
        let mut entry = MockEntryPointV0_6::new();
        let provider = MockProvider::new();

        // Fill in concrete implementations of call data and
        // `simulation_should_revert`
        entry
            .expect_get_simulate_op_call_data()
            .returning(|op, spoofed_state| {
                let call_data = eth::call_data_of(
                    i_entry_point::SimulateHandleOpCall::selector(),
                    (op.clone(), Address::zero(), Bytes::new()),
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
        entry: MockEntryPointV0_6,
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
    const TEST_FEE: U256 = U256([1000, 0, 0, 0]);

    fn create_estimator(
        entry: MockEntryPointV0_6,
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
            init_code: Bytes::new(),
            call_data: Bytes::new(),
            call_gas_limit: None,
            verification_gas_limit: None,
            pre_verification_gas: pvg,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(),
        }
    }

    fn demo_user_op() -> UserOperation {
        UserOperation {
            sender: Address::zero(),
            nonce: U256::zero(),
            init_code: Bytes::new(),
            call_data: Bytes::new(),
            call_gas_limit: U256::from(1000),
            verification_gas_limit: U256::from(1000),
            pre_verification_gas: U256::from(1000),
            max_fee_per_gas: U256::from(1000),
            max_priority_fee_per_gas: U256::from(1000),
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(),
        }
    }

    #[tokio::test]
    async fn test_calc_pre_verification_input() {
        let (entry, mut provider) = create_base_config();
        provider.expect_get_base_fee().returning(|| Ok(TEST_FEE));
        provider
            .expect_get_max_priority_fee()
            .returning(|| Ok(TEST_FEE));

        let (estimator, settings) = create_estimator(entry, provider);
        let user_op = demo_user_op_optional_gas(None);
        let estimation = estimator
            .estimate_pre_verification_gas(&user_op)
            .await
            .unwrap();

        let u_o = user_op.max_fill(
            settings.max_call_gas.into(),
            settings.max_verification_gas.into(),
        );

        let u_o_encoded = u_o.encode();
        let length_in_words = (u_o_encoded.len() + 31) / 32;

        //computed by mapping through the calldata bytes
        //and adding to the value either 4 or 16 depending
        //if the byte is non-zero
        let call_data_cost = 3936;

        let result = U256::from(FIXED) / U256::from(BUNDLE_SIZE)
            + call_data_cost
            + U256::from(PER_USER_OP)
            + U256::from(PER_USER_OP_WORD) * length_in_words;

        let dynamic_gas = 0;

        assert_eq!(result + dynamic_gas, estimation);
    }

    #[tokio::test]
    async fn test_calc_pre_verification_input_arbitrum() {
        let (mut entry, mut provider) = create_base_config();
        entry
            .expect_calc_l1_gas()
            .returning(|_a, _b, _c| Ok(TEST_FEE));
        provider.expect_get_base_fee().returning(|| Ok(TEST_FEE));
        provider
            .expect_get_max_priority_fee()
            .returning(|| Ok(TEST_FEE));

        let settings = Settings {
            max_verification_gas: 10000000000,
            max_call_gas: 10000000000,
            max_paymaster_verification_gas: 10000000000,
            max_paymaster_post_op_gas: 10000000000,
            max_total_execution_gas: 10000000000,
            max_simulate_handle_ops_gas: 100000000,
            verification_estimation_gas_fee: 1_000_000_000_000,
        };

        // Chose arbitrum
        let cs = ChainSpec {
            id: 42161,
            calldata_pre_verification_gas: true,
            l1_gas_oracle_contract_type: L1GasOracleContractType::ArbitrumNitro,
            ..Default::default()
        };
        let provider = Arc::new(provider);
        let estimator = GasEstimator::new(
            cs.clone(),
            Arc::clone(&provider),
            Arc::new(entry),
            settings,
            create_fee_estimator(provider),
        );

        let user_op = demo_user_op_optional_gas(None);
        let estimation = estimator
            .estimate_pre_verification_gas(&user_op)
            .await
            .unwrap();

        let u_o = user_op.max_fill(
            settings.max_call_gas.into(),
            settings.max_verification_gas.into(),
        );

        let u_o_encoded = u_o.encode();
        let length_in_words = (u_o_encoded.len() + 31) / 32;

        //computed by mapping through the calldata bytes
        //and adding to the value either 4 or 16 depending
        //if the byte is non-zero
        let call_data_cost = 3936;

        let result = U256::from(FIXED) / U256::from(BUNDLE_SIZE)
            + call_data_cost
            + U256::from(PER_USER_OP)
            + U256::from(PER_USER_OP_WORD) * length_in_words;

        //Arbitrum dynamic gas
        let dynamic_gas = 1000;

        assert_eq!(result + dynamic_gas, estimation);
    }

    #[tokio::test]
    async fn test_calc_pre_verification_input_op() {
        let (mut entry, mut provider) = create_base_config();

        entry
            .expect_calc_l1_gas()
            .returning(|_a, _b, _c| Ok(TEST_FEE));
        provider.expect_get_base_fee().returning(|| Ok(TEST_FEE));
        provider
            .expect_get_max_priority_fee()
            .returning(|| Ok(TEST_FEE));

        let settings = Settings {
            max_verification_gas: 10000000000,
            max_call_gas: 10000000000,
            max_paymaster_verification_gas: 10000000000,
            max_paymaster_post_op_gas: 10000000000,
            max_total_execution_gas: 10000000000,
            max_simulate_handle_ops_gas: 100000000,
            verification_estimation_gas_fee: 1_000_000_000_000,
        };

        // Chose OP
        let cs = ChainSpec {
            id: 10,
            calldata_pre_verification_gas: true,
            l1_gas_oracle_contract_type: L1GasOracleContractType::OptimismBedrock,
            ..Default::default()
        };
        let estimator = create_custom_estimator(cs, provider, entry, settings);

        let user_op = demo_user_op_optional_gas(None);
        let estimation = estimator
            .estimate_pre_verification_gas(&user_op)
            .await
            .unwrap();

        let u_o = user_op.max_fill(
            settings.max_call_gas.into(),
            settings.max_verification_gas.into(),
        );

        let u_o_encoded: Bytes = u_o.encode().into();
        let length_in_words = (u_o_encoded.len() + 31) / 32;

        //computed by mapping through the calldata bytes
        //and adding to the value either 4 or 16 depending
        //if the byte is non-zero
        let call_data_cost = 3936;

        let result = U256::from(FIXED) / U256::from(BUNDLE_SIZE)
            + call_data_cost
            + U256::from(PER_USER_OP)
            + U256::from(PER_USER_OP_WORD) * length_in_words;

        //OP dynamic gas
        let dynamic_gas = 1000;

        assert_eq!(result + dynamic_gas, estimation);
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas() {
        let (mut entry, mut provider) = create_base_config();

        let gas_usage = 10_000.into();

        entry
            .expect_decode_simulate_handle_ops_revert()
            .returning(|_a| {
                Ok(ExecutionResult {
                    pre_op_gas: U256::from(10000),
                    paid: U256::from(100000),
                    valid_after: 100000000000.into(),
                    valid_until: 100000000001.into(),
                    target_success: true,
                    target_result: Bytes::new(),
                })
            });
        entry
            .expect_call_spoofed_simulate_op()
            .returning(move |op, _b, _c, _d, _e, _f| {
                if op.total_verification_gas_limit() < gas_usage {
                    return Ok(Err(ValidationRevert::EntryPoint("AA23".to_string())));
                }

                Ok(Ok(ExecutionResult {
                    target_result: EstimateCallGasResult {
                        gas_estimate: gas_usage,
                        num_rounds: 10.into(),
                    }
                    .encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });

        provider
            .expect_get_gas_used()
            .returning(move |_a, _b, _c, _d| {
                Ok(GasUsedResult {
                    gas_used: gas_usage * 2,
                    success: false,
                    result: Bytes::new(),
                })
            });

        let (estimator, _) = create_estimator(entry, provider);
        let optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&optional_op, &user_op, H256::zero(), &spoof::state())
            .await
            .unwrap();

        // the estimation should be the same as the gas usage plus the buffer
        let expected = gas_usage + ChainSpec::default().deposit_transfer_overhead;
        let expected_with_buffer =
            math::increase_by_percent(expected, VERIFICATION_GAS_BUFFER_PERCENT);

        assert_eq!(expected_with_buffer, estimation);
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_should_not_overflow() {
        let (mut entry, mut provider) = create_base_config();

        entry
            .expect_decode_simulate_handle_ops_revert()
            .returning(|_a| {
                Ok(ExecutionResult {
                    pre_op_gas: U256::from(10000),
                    paid: U256::from(100000),
                    valid_after: 100000000000.into(),
                    valid_until: 100000000001.into(),
                    target_success: true,
                    target_result: Bytes::new(),
                })
            });
        entry
            .expect_call_spoofed_simulate_op()
            .returning(|_a, _b, _c, _d, _e, _f| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateCallGasResult {
                        gas_estimate: U256::from(10000),
                        num_rounds: U256::from(10),
                    }
                    .encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });

        // this gas used number is larger than a u64 max number so we need to
        // check for this overflow
        provider
            .expect_get_gas_used()
            .returning(move |_a, _b, _c, _d| {
                Ok(GasUsedResult {
                    gas_used: U256::from(18446744073709551616_u128),
                    success: false,
                    result: Bytes::new(),
                })
            });

        let (estimator, _) = create_estimator(entry, provider);
        let optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&optional_op, &user_op, H256::zero(), &spoof::state())
            .await
            .err();

        assert!(matches!(
            estimation,
            Some(GasEstimationError::GasUsedTooLarge)
        ));
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_success_field() {
        let (mut entry, mut provider) = create_base_config();

        entry
            .expect_decode_simulate_handle_ops_revert()
            .returning(|_a| {
                Ok(ExecutionResult {
                    pre_op_gas: U256::from(10000),
                    paid: U256::from(100000),
                    valid_after: 100000000000.into(),
                    valid_until: 100000000001.into(),
                    target_success: true,
                    target_result: Bytes::new(),
                })
            });
        entry
            .expect_call_spoofed_simulate_op()
            .returning(|_a, _b, _c, _d, _e, _f| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateCallGasResult {
                        gas_estimate: U256::from(10000),
                        num_rounds: U256::from(10),
                    }
                    .encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });

        // the success field should not be true as the
        // call should always revert
        provider
            .expect_get_gas_used()
            .returning(move |_a, _b, _c, _d| {
                Ok(GasUsedResult {
                    gas_used: U256::from(20000),
                    success: true,
                    result: Bytes::new(),
                })
            });

        let (estimator, _) = create_estimator(entry, provider);
        let optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&optional_op, &user_op, H256::zero(), &spoof::state())
            .await;

        assert!(estimation.is_err());
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_invalid_message() {
        let (mut entry, mut provider) = create_base_config();

        // checking for this simulated revert
        entry
            .expect_decode_simulate_handle_ops_revert()
            .returning(|_a| {
                Err(ValidationRevert::EntryPoint(
                    "Error with reverted message".to_string(),
                ))
            });
        entry
            .expect_call_spoofed_simulate_op()
            .returning(|_a, _b, _c, _d, _e, _f| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateCallGasResult {
                        gas_estimate: U256::from(100),
                        num_rounds: U256::from(10),
                    }
                    .encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });

        provider
            .expect_get_gas_used()
            .returning(move |_a, _b, _c, _d| {
                Ok(GasUsedResult {
                    gas_used: U256::from(20000),
                    success: false,
                    result: Bytes::new(),
                })
            });

        let (estimator, _) = create_estimator(entry, provider);
        let optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&optional_op, &user_op, H256::zero(), &spoof::state())
            .await;

        assert!(estimation.is_err());
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_invalid_spoof() {
        let (mut entry, mut provider) = create_base_config();

        entry
            .expect_decode_simulate_handle_ops_revert()
            .returning(|_a| {
                Ok(ExecutionResult {
                    pre_op_gas: U256::from(10000),
                    paid: U256::from(100000),
                    valid_after: 100000000000.into(),
                    valid_until: 100000000001.into(),
                    target_success: true,
                    target_result: Bytes::new(),
                })
            });

        //this mocked response causes error
        entry
            .expect_call_spoofed_simulate_op()
            .returning(|_a, _b, _c, _d, _e, _f| Err(anyhow!("Invalid spoof error")));

        provider
            .expect_get_gas_used()
            .returning(move |_a, _b, _c, _d| {
                Ok(GasUsedResult {
                    gas_used: U256::from(20000),
                    success: false,
                    result: Bytes::new(),
                })
            });

        let (estimator, _) = create_estimator(entry, provider);
        let optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&optional_op, &user_op, H256::zero(), &spoof::state())
            .await;

        assert!(estimation.is_err());
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_success_response() {
        let (mut entry, mut provider) = create_base_config();

        entry
            .expect_decode_simulate_handle_ops_revert()
            .returning(|_a| {
                Ok(ExecutionResult {
                    pre_op_gas: U256::from(10000),
                    paid: U256::from(100000),
                    valid_after: 100000000000.into(),
                    valid_until: 100000000001.into(),
                    target_success: true,
                    target_result: Bytes::new(),
                })
            });

        // this should always revert instead of return success
        entry
            .expect_call_spoofed_simulate_op()
            .returning(|_a, _b, _c, _d, _e, _f| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateCallGasResult {
                        gas_estimate: U256::from(10000),
                        num_rounds: U256::from(10),
                    }
                    .encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });

        provider
            .expect_get_gas_used()
            .returning(move |_a, _b, _c, _d| {
                Err(anyhow::anyhow!("This should always revert").into())
            });

        let (estimator, _) = create_estimator(entry, provider);
        let optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&optional_op, &user_op, H256::zero(), &spoof::state())
            .await;

        assert!(estimation.is_err());
    }

    #[tokio::test]
    async fn test_estimate_call_gas() {
        let (mut entry, mut provider) = create_base_config();

        let gas_estimate = U256::from(100_000);
        entry
            .expect_call_spoofed_simulate_op()
            .returning(move |_a, _b, _c, _d, _e, _f| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateCallGasResult {
                        gas_estimate,
                        num_rounds: U256::from(10),
                    }
                    .encode()
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
            .estimate_call_gas(&optional_op, user_op, H256::zero(), spoof::state())
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
            .expect_call_spoofed_simulate_op()
            .returning(|_a, _b, _c, _d, _e, _f| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateCallGasRevertAtMax {
                        revert_data: Bytes::new(),
                    }
                    .encode()
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
            .estimate_call_gas(user_op, H256::zero(), spoof::state())
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
            .expect_call_spoofed_simulate_op()
            .returning(|_a, _b, _c, _d, _e, _f| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateCallGasContinuation {
                        min_gas: U256::from(100),
                        max_gas: U256::from(100000),
                        num_rounds: U256::from(10),
                    }
                    .encode()
                    .into(),
                    target_success: false,
                    ..Default::default()
                }))
            })
            .times(1);
        entry
            .expect_call_spoofed_simulate_op()
            .returning(|_a, _b, _c, _d, _e, _f| {
                Ok(Ok(ExecutionResult {
                    target_result: EstimateCallGasResult {
                        gas_estimate: U256::from(200),
                        num_rounds: U256::from(10),
                    }
                    .encode()
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
            .estimate_call_gas(user_op, H256::zero(), spoof::state())
            .await
            .unwrap();

        // on the second loop of the estimate gas continuation
        // I update the spoofed value to 200

        assert_eq!(estimation, U128::from(200));
    }

    #[tokio::test]
    async fn test_estimation_optional_gas_used() {
        let (mut entry, mut provider) = create_base_config();
        let gas_usage = 10_000.into();

        entry
            .expect_call_spoofed_simulate_op()
            .returning(move |op, _b, _c, _d, _e, _f| {
                if op.total_verification_gas_limit() < gas_usage {
                    return Ok(Err(ValidationRevert::EntryPoint("AA23".to_string())));
                }

                Ok(Ok(ExecutionResult {
                    target_result: EstimateCallGasResult {
                        gas_estimate: U256::from(10000),
                        num_rounds: U256::from(10),
                    }
                    .encode()
                    .into(),
                    target_success: true,
                    ..Default::default()
                }))
            });
        entry
            .expect_decode_simulate_handle_ops_revert()
            .returning(|_a| {
                Ok(ExecutionResult {
                    pre_op_gas: U256::from(10000),
                    paid: U256::from(100000),
                    valid_after: 100000000000.into(),
                    valid_until: 100000000001.into(),
                    target_success: true,
                    target_result: Bytes::new(),
                })
            });

        provider
            .expect_get_code()
            .returning(|_a, _b| Ok(Bytes::new()));
        provider
            .expect_get_latest_block_hash_and_number()
            .returning(|| Ok((H256::zero(), U64::zero())));
        provider
            .expect_get_gas_used()
            .returning(move |_a, _b, _c, _d| {
                Ok(GasUsedResult {
                    gas_used: gas_usage,
                    success: false,
                    result: Bytes::new(),
                })
            });

        provider.expect_get_base_fee().returning(|| Ok(TEST_FEE));
        provider
            .expect_get_max_priority_fee()
            .returning(|| Ok(TEST_FEE));

        let (estimator, _) = create_estimator(entry, provider);

        let optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));

        let estimation = estimator
            .estimate_op_gas(optional_op, spoof::state())
            .await
            .unwrap();

        // this should be a pass through
        assert_eq!(estimation.pre_verification_gas, U256::from(10000));

        // gas used increased by 10%
        let expected = gas_usage + ChainSpec::default().deposit_transfer_overhead;
        assert_eq!(
            estimation.verification_gas_limit,
            cmp::max(
                math::increase_by_percent(expected, 10),
                expected + REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER
            )
        );

        // input gas limit clamped with the set limit in settings and constant MIN
        assert_eq!(
            estimation.call_gas_limit,
            U256::from(10000) + CALL_GAS_BUFFER_VALUE
        );
    }

    #[test]
    #[should_panic]
    fn test_estimation_optional_gas_invalid_settings() {
        let (entry, provider) = create_base_config();

        //max_call_gas is less than MIN_CALL_GAS_LIMIT

        let settings = Settings {
            max_verification_gas: 10,
            max_call_gas: 10,
            max_paymaster_post_op_gas: 10,
            max_paymaster_verification_gas: 10,
            max_total_execution_gas: 10,
            max_simulate_handle_ops_gas: 10,
            verification_estimation_gas_fee: 1_000_000_000_000,
        };

        create_custom_estimator(ChainSpec::default(), provider, entry, settings);
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
        optional_op.verification_gas_limit = Some(U256::from(TEST_MAX_GAS_LIMITS + 1));

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
    async fn test_cgl_over_max() {
        let (entry, provider) = create_base_config();
        let (estimator, _) = create_estimator(entry, provider);

        let mut optional_op = demo_user_op_optional_gas(Some(U256::from(10000)));
        optional_op.call_gas_limit = Some(U256::from(TEST_MAX_GAS_LIMITS + 1));

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
        optional_op.call_gas_limit = Some(U256::from(10000));
        optional_op.verification_gas_limit = Some(U256::from(10000));

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
        optional_op.call_gas_limit = Some(U256::from(10000));
        optional_op.verification_gas_limit = Some(U256::from(10000));

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
        optional_op.call_gas_limit = Some(TEST_MAX_GAS_LIMITS.into());
        optional_op.verification_gas_limit = Some(TEST_MAX_GAS_LIMITS.into());

        let err = estimator
            .estimate_op_gas(optional_op.clone(), spoof::state())
            .await
            .err()
            .unwrap();

        assert!(matches!(
            err,
            GasEstimationError::GasTotalTooLarge(_, TEST_MAX_GAS_LIMITS)
        ))
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
