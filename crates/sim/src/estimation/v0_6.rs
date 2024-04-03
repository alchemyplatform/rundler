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
    providers::spoof,
    types::{Bytes, H256, U256},
};
use rundler_provider::{EntryPoint, L1GasProvider, Provider, SimulationProvider};
use rundler_types::{
    chain::ChainSpec,
    v0_6::{UserOperation, UserOperationOptionalGas},
    GasEstimate,
};
use rundler_utils::math;
use tokio::join;

use super::{
    CallGasEstimator, CallGasEstimatorImpl, CallGasEstimatorSpecialization, GasEstimationError,
    Settings, VerificationGasEstimator, ENTRYPOINT_V0_6_DEPLOYED_BYTECODE,
};
use crate::{
    estimation::estimate_verification_gas::GetOpWithLimitArgs, gas, precheck::MIN_CALL_GAS_LIMIT,
    simulation, FeeEstimator, GasEstimator as GasEstimatorTrait, VerificationGasEstimatorImpl,
};

/// Percentage by which to increase the verification gas limit after binary search
const VERIFICATION_GAS_BUFFER_PERCENT: u64 = 10;
/// Absolute value by which to increase the call gas limit after binary search
const CALL_GAS_BUFFER_VALUE: U256 = U256([3000, 0, 0, 0]);

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
        let Self {
            provider, settings, ..
        } = self;

        let (block_hash, _) = provider
            .get_latest_block_hash_and_number()
            .await
            .map_err(anyhow::Error::from)?;

        // Estimate pre verification gas at the current fees
        // If the user provides fees, use them, otherwise use the current bundle fees
        let (bundle_fees, base_fee) = self.fee_estimator.required_bundle_fees(None).await?;
        let gas_price = if let (Some(max_fee), Some(prio_fee)) =
            (op.max_fee_per_gas, op.max_priority_fee_per_gas)
        {
            cmp::min(max_fee, base_fee + prio_fee)
        } else {
            base_fee + bundle_fees.max_priority_fee_per_gas
        };
        let pre_verification_gas = self.estimate_pre_verification_gas(&op, gas_price).await?;

        let op = UserOperation {
            pre_verification_gas,
            ..op.into_user_operation(
                settings.max_call_gas.into(),
                settings.max_verification_gas.into(),
            )
        };

        let verification_future = self.estimate_verification_gas(&op, block_hash, &state_override);
        let call_future = self.call_gas_estimator.estimate_call_gas(
            op.clone(),
            block_hash,
            state_override.clone(),
        );

        // Not try_join! because then the output is nondeterministic if both
        // verification and call estimation fail.
        let timer = std::time::Instant::now();
        let (verification_gas_limit, call_gas_limit) = join!(verification_future, call_future);
        tracing::debug!("gas estimation took {}ms", timer.elapsed().as_millis());

        let verification_gas_limit = verification_gas_limit?;
        let call_gas_limit = U256::from(call_gas_limit?);

        if let Some(err) = settings.validate() {
            return Err(GasEstimationError::RevertInValidation(err));
        }

        // Add a buffer to the verification gas limit. Add 10% or 2000 gas, whichever is larger
        // to ensure we get at least a 2000 gas buffer. Cap at the max verification gas.
        let verification_gas_limit = cmp::max(
            math::increase_by_percent(verification_gas_limit, VERIFICATION_GAS_BUFFER_PERCENT),
            verification_gas_limit + simulation::v0_6::REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER,
        )
        .min(settings.max_verification_gas.into());

        // Add a buffer to the call gas limit and clamp
        let call_gas_limit = call_gas_limit
            .add(CALL_GAS_BUFFER_VALUE)
            .clamp(MIN_CALL_GAS_LIMIT, settings.max_call_gas.into());

        Ok(GasEstimate {
            pre_verification_gas,
            verification_gas_limit,
            call_gas_limit,
            paymaster_verification_gas_limit: None,
            paymaster_post_op_gas_limit: None,
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
{
    async fn estimate_verification_gas(
        &self,
        op: &UserOperation,
        block_hash: H256,
        state_override: &spoof::State,
    ) -> Result<U256, GasEstimationError> {
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

        self.verification_gas_estimator
            .estimate_verification_gas(
                op,
                block_hash,
                state_override,
                self.settings.max_verification_gas.into(),
                get_op_with_limit,
            )
            .await
            .map(|gas_u128| gas_u128.into())
    }

    async fn estimate_pre_verification_gas(
        &self,
        op: &UserOperationOptionalGas,
        gas_price: U256,
    ) -> Result<U256, GasEstimationError> {
        Ok(gas::estimate_pre_verification_gas(
            &self.chain_spec,
            &self.entry_point,
            &op.max_fill(
                self.settings.max_call_gas.into(),
                self.settings.max_verification_gas.into(),
            ),
            &op.random_fill(
                self.settings.max_call_gas.into(),
                self.settings.max_verification_gas.into(),
            ),
            gas_price,
        )
        .await?)
    }
}

/// Implementation of functions that specialize the call gas estimator to the
/// v0.6 entry point.
#[derive(Debug)]
pub struct CallGasEstimatorSpecializationV06;

impl CallGasEstimatorSpecialization for CallGasEstimatorSpecializationV06 {
    type UO = UserOperation;

    fn get_op_with_verification_gas_but_no_call_gas(
        &self,
        op: Self::UO,
        settings: Settings,
    ) -> Self::UO {
        UserOperation {
            call_gas_limit: 0.into(),
            max_fee_per_gas: 0.into(),
            verification_gas_limit: settings.max_verification_gas.into(),
            ..op
        }
    }

    fn entry_point_simulations_code(&self) -> Bytes {
        // In v0.6, the entry point code contains the simulations code, so we
        // just return the entry point code.
        ENTRYPOINT_V0_6_DEPLOYED_BYTECODE.into()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use ethers::{
        abi::{AbiEncode, Address},
        contract::EthCall,
        types::{U128, U64},
    };
    use rundler_provider::{ExecutionResult, MockEntryPointV0_6, MockProvider, SimulateOpCallData};
    use rundler_types::{
        chain::L1GasOracleContractType,
        contracts::{
            utils::{
                call_gas_estimation_proxy::{
                    EstimateCallGasContinuation, EstimateCallGasResult, EstimateCallGasRevertAtMax,
                },
                get_gas_used::GasUsedResult,
            },
            v0_6::i_entry_point,
        },
        v0_6::{UserOperation, UserOperationOptionalGas},
        UserOperation as UserOperationTrait,
    };
    use rundler_utils::eth;

    use super::*;
    use crate::{
        simulation::v0_6::REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER, PriorityFeeMode,
        VerificationGasEstimatorImpl,
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

    fn create_estimator(
        entry: MockEntryPointV0_6,
        provider: MockProvider,
    ) -> (GasEstimatorWithMocks, Settings) {
        let settings = Settings {
            max_verification_gas: 10000000000,
            max_call_gas: 10000000000,
            max_paymaster_verification_gas: 10000000000,
            max_paymaster_post_op_gas: 10000000000,
            max_simulate_handle_ops_gas: 100000000,
            verification_estimation_gas_fee: 1_000_000_000_000,
        };
        let estimator = create_custom_estimator(ChainSpec::default(), provider, entry, settings);
        (estimator, settings)
    }

    fn demo_user_op_optional_gas() -> UserOperationOptionalGas {
        UserOperationOptionalGas {
            sender: Address::zero(),
            nonce: U256::zero(),
            init_code: Bytes::new(),
            call_data: Bytes::new(),
            call_gas_limit: Some(U256::from(1000)),
            verification_gas_limit: Some(U256::from(1000)),
            pre_verification_gas: Some(U256::from(1000)),
            max_fee_per_gas: Some(U256::from(1000)),
            max_priority_fee_per_gas: Some(U256::from(1000)),
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
        let (mut entry, provider) = create_base_config();
        entry.expect_address().return_const(Address::zero());

        let (estimator, settings) = create_estimator(entry, provider);
        let user_op = demo_user_op_optional_gas();
        let estimation = estimator
            .estimate_pre_verification_gas(&user_op, U256::zero())
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
        let (mut entry, provider) = create_base_config();
        entry.expect_address().return_const(Address::zero());
        entry
            .expect_calc_l1_gas()
            .returning(|_a, _b, _c| Ok(U256::from(1000)));

        let settings = Settings {
            max_verification_gas: 10000000000,
            max_call_gas: 10000000000,
            max_paymaster_verification_gas: 10000000000,
            max_paymaster_post_op_gas: 10000000000,
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

        let user_op = demo_user_op_optional_gas();
        let estimation = estimator
            .estimate_pre_verification_gas(&user_op, U256::zero())
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
        let (mut entry, provider) = create_base_config();

        entry.expect_address().return_const(Address::zero());
        entry
            .expect_calc_l1_gas()
            .returning(|_a, _b, _c| Ok(U256::from(1000)));

        let settings = Settings {
            max_verification_gas: 10000000000,
            max_call_gas: 10000000000,
            max_paymaster_verification_gas: 10000000000,
            max_paymaster_post_op_gas: 10000000000,
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

        let user_op = demo_user_op_optional_gas();
        let estimation = estimator
            .estimate_pre_verification_gas(&user_op, U256::zero())
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

        entry.expect_address().return_const(Address::zero());
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
                    return Ok(Err("AA23".to_string()));
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

        provider.expect_call_constructor().returning(
            move |_a, _b: (Address, U256, Bytes), _c, _d| {
                Ok(GasUsedResult {
                    gas_used: gas_usage * 2,
                    success: false,
                    result: Bytes::new(),
                })
            },
        );

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&user_op, H256::zero(), &spoof::state())
            .await
            .unwrap();

        // the estimation should be the same as the gas usage plus the buffer
        let expected = gas_usage + ChainSpec::default().deposit_transfer_overhead;
        assert_eq!(expected, estimation);
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_should_not_overflow() {
        let (mut entry, mut provider) = create_base_config();

        entry.expect_address().return_const(Address::zero());
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
        provider.expect_call_constructor().returning(
            move |_a, _b: (Address, U256, Bytes), _c, _d| {
                Ok(GasUsedResult {
                    gas_used: U256::from(18446744073709551616_u128),
                    success: false,
                    result: Bytes::new(),
                })
            },
        );

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&user_op, H256::zero(), &spoof::state())
            .await
            .err();

        assert!(matches!(
            estimation,
            Some(GasEstimationError::RevertInValidation(..))
        ));
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_success_field() {
        let (mut entry, mut provider) = create_base_config();

        entry.expect_address().return_const(Address::zero());
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
        provider.expect_call_constructor().returning(
            move |_a, _b: (Address, U256, Bytes), _c, _d| {
                Ok(GasUsedResult {
                    gas_used: U256::from(20000),
                    success: true,
                    result: Bytes::new(),
                })
            },
        );

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&user_op, H256::zero(), &spoof::state())
            .await;

        assert!(estimation.is_err());
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_invalid_message() {
        let (mut entry, mut provider) = create_base_config();

        entry.expect_address().return_const(Address::zero());
        // checking for this simulated revert
        entry
            .expect_decode_simulate_handle_ops_revert()
            .returning(|_a| Err(String::from("Error with reverted message")));
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

        provider.expect_call_constructor().returning(
            move |_a, _b: (Address, U256, Bytes), _c, _d| {
                Ok(GasUsedResult {
                    gas_used: U256::from(20000),
                    success: false,
                    result: Bytes::new(),
                })
            },
        );

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&user_op, H256::zero(), &spoof::state())
            .await;

        assert!(estimation.is_err());
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_invalid_spoof() {
        let (mut entry, mut provider) = create_base_config();

        entry.expect_address().return_const(Address::zero());
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

        provider.expect_call_constructor().returning(
            move |_a, _b: (Address, U256, Bytes), _c, _d| {
                Ok(GasUsedResult {
                    gas_used: U256::from(20000),
                    success: false,
                    result: Bytes::new(),
                })
            },
        );

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&user_op, H256::zero(), &spoof::state())
            .await;

        assert!(estimation.is_err());
    }

    #[tokio::test]
    async fn test_binary_search_verification_gas_success_response() {
        let (mut entry, mut provider) = create_base_config();

        entry.expect_address().return_const(Address::zero());
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

        provider.expect_call_constructor().returning(
            move |_a, _b: (Address, U256, Bytes), _c, _d| {
                let ret: Result<GasUsedResult, anyhow::Error> =
                    Err(anyhow::anyhow!("This should always revert"));
                ret
            },
        );

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .estimate_verification_gas(&user_op, H256::zero(), &spoof::state())
            .await;

        assert!(estimation.is_err());
    }

    #[tokio::test]
    async fn test_estimate_call_gas() {
        let (mut entry, mut provider) = create_base_config();

        entry.expect_address().return_const(Address::zero());
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
            .expect_get_code()
            .returning(|_a, _b| Ok(Bytes::new()));

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .call_gas_estimator
            .estimate_call_gas(user_op, H256::zero(), spoof::state())
            .await
            .unwrap();

        // result is derived from the spoofed gas_estimate field

        assert_eq!(estimation, U128::from(100));
    }

    #[tokio::test]
    async fn test_estimate_call_gas_error() {
        let (mut entry, mut provider) = create_base_config();

        entry.expect_address().return_const(Address::zero());

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

        entry.expect_address().return_const(Address::zero());
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

        entry.expect_address().return_const(Address::zero());
        entry
            .expect_call_spoofed_simulate_op()
            .returning(move |op, _b, _c, _d, _e, _f| {
                if op.total_verification_gas_limit() < gas_usage {
                    return Ok(Err("AA23".to_string()));
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
        provider.expect_call_constructor().returning(
            move |_a, _b: (Address, U256, Bytes), _c, _d| {
                Ok(GasUsedResult {
                    gas_used: gas_usage,
                    success: false,
                    result: Bytes::new(),
                })
            },
        );

        provider
            .expect_get_base_fee()
            .returning(|| Ok(U256::from(1000)));
        provider
            .expect_get_max_priority_fee()
            .returning(|| Ok(U256::from(1000)));

        let (estimator, _) = create_estimator(entry, provider);

        let user_op = demo_user_op_optional_gas();

        let estimation = estimator
            .estimate_op_gas(user_op, spoof::state())
            .await
            .unwrap();

        // this number uses the same logic as the pre_verification tests
        assert_eq!(estimation.pre_verification_gas, U256::from(43296));

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

    #[tokio::test]
    async fn test_estimation_optional_gas_invalid_settings() {
        let (mut entry, mut provider) = create_base_config();

        entry.expect_address().return_const(Address::zero());
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
        provider.expect_call_constructor().returning(
            move |_a, _b: (Address, U256, Bytes), _c, _d| {
                Ok(GasUsedResult {
                    gas_used: U256::from(100000),
                    success: false,
                    result: Bytes::new(),
                })
            },
        );

        provider
            .expect_get_base_fee()
            .returning(|| Ok(U256::from(1000)));
        provider
            .expect_get_max_priority_fee()
            .returning(|| Ok(U256::from(1000)));

        //max_call_gas is less than MIN_CALL_GAS_LIMIT

        let settings = Settings {
            max_verification_gas: 10,
            max_call_gas: 10,
            max_paymaster_post_op_gas: 10,
            max_paymaster_verification_gas: 10,
            max_simulate_handle_ops_gas: 10,
            verification_estimation_gas_fee: 1_000_000_000_000,
        };

        let estimator = create_custom_estimator(ChainSpec::default(), provider, entry, settings);
        let user_op = demo_user_op_optional_gas();
        let estimation = estimator
            .estimate_op_gas(user_op, spoof::state())
            .await
            .err();

        assert!(matches!(
            estimation,
            Some(GasEstimationError::RevertInValidation(..))
        ));
    }
}
