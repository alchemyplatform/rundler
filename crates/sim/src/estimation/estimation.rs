use std::{ops::Deref, sync::Arc};

use anyhow::{anyhow, Context};
use ethers::{
    abi::AbiDecode,
    contract::EthCall,
    providers::spoof,
    types::{Address, Bytes, H256, U256},
};
#[cfg(feature = "test-utils")]
use mockall::automock;
use rand::Rng;
use rundler_provider::{EntryPoint, Provider};
use rundler_types::{
    contracts::{
        call_gas_estimation_proxy::{
            EstimateCallGasArgs, EstimateCallGasCall, EstimateCallGasContinuation,
            EstimateCallGasResult, EstimateCallGasRevertAtMax,
            CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE,
        },
        i_entry_point,
    },
    UserOperation,
};
use rundler_utils::{eth, math};
use tokio::join;

use super::types::{GasEstimate, Settings, UserOperationOptionalGas};
use crate::{gas, precheck::MIN_CALL_GAS_LIMIT, utils};

/// Gas estimates will be rounded up to the next multiple of this. Increasing
/// this value reduces the number of rounds of `eth_call` needed in binary
/// search, e.g. a value of 1024 means ten fewer `eth_call`s needed for each of
/// verification gas and call gas.
const GAS_ROUNDING: u64 = 4096;

/// Gas estimation will stop when the binary search bounds are within
/// `GAS_ESTIMATION_ERROR_MARGIN` of each other.
const GAS_ESTIMATION_ERROR_MARGIN: f64 = 0.1;

const VERIFICATION_GAS_BUFFER_PERCENT: u64 = 10;

/// This accounts for the gas used during a transfer to the entrypoint contract
/// As well as the cost to initialize a previously 0 storage slot for an account
/// that has yet to deposit.
const GAS_FEE_TRANSFER_COST: u64 = 30000;

/// Offset at which the proxy target address appears in the proxy bytecode. Must
/// be updated whenever `CallGasEstimationProxy.sol` changes.
///
/// The easiest way to get the updated value is to run this module's tests. The
/// failure will tell you the new value.
const PROXY_TARGET_OFFSET: usize = 137;

/// Error type for gas estimation
#[derive(Debug, thiserror::Error)]
pub enum GasEstimationError {
    /// Validation reverted
    #[error("{0}")]
    RevertInValidation(String),
    /// Call reverted with a string message
    #[error("user operation's call reverted: {0}")]
    RevertInCallWithMessage(String),
    /// Call reverted with bytes
    #[error("user operation's call reverted: {0:#x}")]
    RevertInCallWithBytes(Bytes),
    /// Other error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Gas estimator trait
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait GasEstimator: Send + Sync + 'static {
    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
    ) -> Result<GasEstimate, GasEstimationError>;
}

/// Gas estimator implementation
#[derive(Debug)]
pub struct GasEstimatorImpl<P, E> {
    chain_id: u64,
    provider: Arc<P>,
    entry_point: E,
    settings: Settings,
}

#[async_trait::async_trait]
impl<P: Provider, E: EntryPoint> GasEstimator for GasEstimatorImpl<P, E> {
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
    ) -> Result<GasEstimate, GasEstimationError> {
        let Self {
            provider, settings, ..
        } = self;

        let block_hash = provider
            .get_latest_block_hash()
            .await
            .map_err(anyhow::Error::from)?;

        // Estimate pre verification gas
        let pre_verification_gas = self.calc_pre_verification_gas(&op).await?;

        // We deviate from the spec here always ignoring `max_fee_per_gas` and setting to zero.
        // If not using a paymaster, the bundler will automatically add 21K to the verification
        // gas limit to account for the gas fee transfer.
        // If using a paymaster, the transfer gas will need to be added by the client to the returned limit.
        let op = UserOperation {
            pre_verification_gas,
            verification_gas_limit: settings.max_verification_gas.into(),
            call_gas_limit: settings.max_call_gas.into(),
            max_fee_per_gas: 0.into(),
            max_priority_fee_per_gas: 0.into(),
            ..op.into_user_operation(settings)
        };

        let verification_future = self.binary_search_verification_gas(&op, block_hash);
        let call_future = self.estimate_call_gas(&op, block_hash);

        // Not try_join! because then the output is nondeterministic if both
        // verification and call estimation fail.
        let timer = std::time::Instant::now();
        let (verification_gas_limit, call_gas_limit) = join!(verification_future, call_future);
        tracing::debug!("gas estimation took {}ms", timer.elapsed().as_millis());

        let verification_gas_limit = verification_gas_limit?;
        let call_gas_limit = call_gas_limit?;

        if let Some(err) = settings.validate() {
            return Err(GasEstimationError::RevertInValidation(err));
        }

        Ok(GasEstimate {
            pre_verification_gas,
            verification_gas_limit: math::increase_by_percent(
                verification_gas_limit,
                VERIFICATION_GAS_BUFFER_PERCENT,
            )
            .min(settings.max_verification_gas.into()),
            call_gas_limit: call_gas_limit.clamp(MIN_CALL_GAS_LIMIT, settings.max_call_gas.into()),
        })
    }
}

impl<P: Provider, E: EntryPoint> GasEstimatorImpl<P, E> {
    /// Create a new gas estimator
    pub fn new(chain_id: u64, provider: Arc<P>, entry_point: E, settings: Settings) -> Self {
        Self {
            chain_id,
            provider,
            entry_point,
            settings,
        }
    }

    async fn binary_search_verification_gas(
        &self,
        op: &UserOperation,
        block_hash: H256,
    ) -> Result<U256, GasEstimationError> {
        let timer = std::time::Instant::now();
        let simulation_gas = U256::from(self.settings.max_simulate_handle_ops_gas);

        // Make one attempt at max gas, but zero fees, to see if success is possible.
        // Capture the gas usage of this attempt and use as the initial guess in the binary search
        let initial_op = UserOperation {
            verification_gas_limit: simulation_gas,
            call_gas_limit: 0.into(),
            ..op.clone()
        };
        let gas_used = utils::get_gas_used(
            self.provider.deref(),
            self.entry_point.address(),
            U256::zero(),
            utils::call_data_of(
                i_entry_point::SimulateHandleOpCall::selector(),
                (initial_op, Address::zero(), Bytes::new()),
            ),
        )
        .await
        .context("failed to run initial guess")?;
        if gas_used.success {
            Err(anyhow!(
                "simulateHandleOp succeeded, but should always revert"
            ))?;
        }
        if let Some(message) = self
            .entry_point
            .decode_simulate_handle_ops_revert(gas_used.result)
            .err()
        {
            return Err(GasEstimationError::RevertInValidation(message));
        }

        let run_attempt_returning_error = |gas: u64| async move {
            let op = UserOperation {
                verification_gas_limit: gas.into(),
                call_gas_limit: 0.into(),
                ..op.clone()
            };
            let error_message = self
                .entry_point
                .call_spoofed_simulate_op(
                    op,
                    Address::zero(),
                    Bytes::new(),
                    block_hash,
                    simulation_gas,
                    &spoof::state(),
                )
                .await?
                .err();
            Result::<_, anyhow::Error>::Ok(error_message)
        };

        let mut max_failure_gas = 0;
        let mut min_success_gas = self.settings.max_verification_gas;

        if gas_used.gas_used.cmp(&U256::from(u64::MAX)).is_gt() {
            return Err(GasEstimationError::RevertInValidation(
                "gas_used cannot be larger than a u64 integer".to_string(),
            ));
        }
        let mut guess = gas_used.gas_used.as_u64() * 2;
        let mut num_rounds = 0;
        while (min_success_gas as f64) / (max_failure_gas as f64)
            > (1.0 + GAS_ESTIMATION_ERROR_MARGIN)
        {
            num_rounds += 1;
            let is_failure = run_attempt_returning_error(guess).await?.is_some();
            if is_failure {
                max_failure_gas = guess;
            } else {
                min_success_gas = guess;
            }
            guess = (max_failure_gas + min_success_gas) / 2;
        }

        let mut min_success_gas = min_success_gas;
        if op.paymaster().is_none() {
            // If not using a paymaster, add the gas for the gas fee transfer.
            min_success_gas += GAS_FEE_TRANSFER_COST;
        }
        tracing::debug!(
            "binary search for verification gas took {num_rounds} rounds, {}ms",
            timer.elapsed().as_millis()
        );
        Ok(min_success_gas.into())
    }

    async fn estimate_call_gas(
        &self,
        op: &UserOperation,
        block_hash: H256,
    ) -> Result<U256, GasEstimationError> {
        let timer = std::time::Instant::now();
        // For an explanation of what's going on here, see the comment at the
        // top of `CallGasEstimationProxy.sol`.
        let entry_point_code = self
            .provider
            .get_code(self.entry_point.address(), Some(block_hash))
            .await
            .map_err(anyhow::Error::from)?;
        // Use a random address for the moved entry point so that users can't
        // intentionally get bad estimates by interacting with the hardcoded
        // address.
        let moved_entry_point_address: Address = rand::thread_rng().gen();
        let estimation_proxy_bytecode =
            estimation_proxy_bytecode_with_target(moved_entry_point_address);
        let mut spoofed_state = spoof::state();
        spoofed_state
            .account(moved_entry_point_address)
            .code(entry_point_code);
        spoofed_state
            .account(self.entry_point.address())
            .code(estimation_proxy_bytecode);
        let callless_op = UserOperation {
            call_gas_limit: 0.into(),
            ..op.clone()
        };
        let mut min_gas = U256::zero();
        let mut max_gas = U256::from(self.settings.max_call_gas);
        let mut is_continuation = false;
        let mut num_rounds = U256::zero();
        loop {
            let target_call_data = utils::call_data_of(
                EstimateCallGasCall::selector(),
                (EstimateCallGasArgs {
                    sender: op.sender,
                    call_data: Bytes::clone(&op.call_data),
                    min_gas,
                    max_gas,
                    rounding: GAS_ROUNDING.into(),
                    is_continuation,
                },),
            );
            let target_revert_data = self
                .entry_point
                .call_spoofed_simulate_op(
                    callless_op.clone(),
                    self.entry_point.address(),
                    target_call_data,
                    block_hash,
                    self.settings.max_simulate_handle_ops_gas.into(),
                    &spoofed_state,
                )
                .await?
                .map_err(GasEstimationError::RevertInCallWithMessage)?
                .target_result;
            if let Ok(result) = EstimateCallGasResult::decode(&target_revert_data) {
                num_rounds += result.num_rounds;
                tracing::debug!(
                    "binary search for call gas took {num_rounds} rounds, {}ms",
                    timer.elapsed().as_millis()
                );
                return Ok(result.gas_estimate);
            } else if let Ok(revert) = EstimateCallGasRevertAtMax::decode(&target_revert_data) {
                let error = if let Some(message) = eth::parse_revert_message(&revert.revert_data) {
                    GasEstimationError::RevertInCallWithMessage(message)
                } else {
                    GasEstimationError::RevertInCallWithBytes(revert.revert_data)
                };
                return Err(error);
            } else if let Ok(continuation) =
                EstimateCallGasContinuation::decode(&target_revert_data)
            {
                if is_continuation
                    && continuation.min_gas <= min_gas
                    && continuation.max_gas >= max_gas
                {
                    // This should never happen, but if it does, bail so we
                    // don't end up in an infinite loop!
                    Err(anyhow!(
                        "estimateCallGas should make progress each time it is called"
                    ))?;
                }
                is_continuation = true;
                min_gas = min_gas.max(continuation.min_gas);
                max_gas = max_gas.min(continuation.max_gas);
                num_rounds += continuation.num_rounds;
            } else {
                Err(anyhow!(
                    "estimateCallGas revert should be a Result or a Continuation"
                ))?;
            }
        }
    }

    async fn calc_pre_verification_gas(
        &self,
        op: &UserOperationOptionalGas,
    ) -> Result<U256, GasEstimationError> {
        Ok(gas::calc_pre_verification_gas(
            &op.max_fill(&self.settings),
            &op.random_fill(&self.settings),
            self.entry_point.address(),
            self.provider.clone(),
            self.chain_id,
        )
        .await?)
    }
}

/// Replaces the address of the proxy target where it appears in the proxy
/// bytecode so we don't need the same fixed address every time.
fn estimation_proxy_bytecode_with_target(target: Address) -> Bytes {
    let mut vec = CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE.to_vec();
    vec[PROXY_TARGET_OFFSET..PROXY_TARGET_OFFSET + 20].copy_from_slice(target.as_bytes());
    vec.into()
}

#[cfg(test)]
mod tests {
    use ethers::{
        abi::{AbiEncode, Address},
        providers::JsonRpcError,
        types::Chain,
        utils::hex,
    };
    use rundler_provider::{MockEntryPoint, MockProvider, ProviderError};
    use rundler_types::contracts::{get_gas_used::GasUsedResult, i_entry_point::ExecutionResult};

    use super::*;

    // Gas overhead defaults
    const FIXED: u32 = 21000;
    const PER_USER_OP: u32 = 18300;
    const PER_USER_OP_WORD: u32 = 4;
    const BUNDLE_SIZE: u32 = 1;

    /// Must match the constant in `CallGasEstimationProxy.sol`.
    const PROXY_TARGET_CONSTANT: &str = "A13dB4eCfbce0586E57D1AeE224FbE64706E8cd3";

    fn create_base_config() -> (MockEntryPoint, MockProvider) {
        let entry = MockEntryPoint::new();
        let provider = MockProvider::new();

        (entry, provider)
    }

    fn create_estimator(
        entry: MockEntryPoint,
        provider: MockProvider,
    ) -> (GasEstimatorImpl<MockProvider, MockEntryPoint>, Settings) {
        let settings = Settings {
            max_verification_gas: 10000000000,
            max_call_gas: 10000000000,
            max_simulate_handle_ops_gas: 100000000,
        };

        let estimator: GasEstimatorImpl<MockProvider, MockEntryPoint> =
            GasEstimatorImpl::new(0, Arc::new(provider), entry, settings);

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

    #[test]
    fn test_proxy_target_offset() {
        let proxy_target_bytes = hex::decode(PROXY_TARGET_CONSTANT).unwrap();
        let mut offsets = Vec::<usize>::new();
        for i in 0..CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE.len() - 20 {
            if CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE[i..i + 20] == proxy_target_bytes {
                offsets.push(i);
            }
        }
        assert_eq!(vec![PROXY_TARGET_OFFSET], offsets);
    }

    #[tokio::test]
    async fn test_calc_pre_verification_input() {
        let (mut entry, provider) = create_base_config();
        entry.expect_address().return_const(Address::zero());

        let (estimator, settings) = create_estimator(entry, provider);
        let user_op = demo_user_op_optional_gas();
        let estimation = estimator.calc_pre_verification_gas(&user_op).await.unwrap();

        let u_o = user_op.max_fill(&settings);

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
        entry.expect_address().return_const(Address::zero());
        provider
            .expect_calc_arbitrum_l1_gas()
            .returning(|_a, _b| Ok(U256::from(1000)));

        let settings = Settings {
            max_verification_gas: 10000000000,
            max_call_gas: 10000000000,
            max_simulate_handle_ops_gas: 100000000,
        };

        // Chose arbitrum
        let estimator: GasEstimatorImpl<MockProvider, MockEntryPoint> =
            GasEstimatorImpl::new(Chain::Arbitrum as u64, Arc::new(provider), entry, settings);

        let user_op = demo_user_op_optional_gas();
        let estimation = estimator.calc_pre_verification_gas(&user_op).await.unwrap();

        let u_o = user_op.max_fill(&settings);

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

        entry.expect_address().return_const(Address::zero());
        provider
            .expect_calc_optimism_l1_gas()
            .returning(|_a, _b| Ok(U256::from(1000)));

        let settings = Settings {
            max_verification_gas: 10000000000,
            max_call_gas: 10000000000,
            max_simulate_handle_ops_gas: 100000000,
        };

        // Chose OP
        let estimator: GasEstimatorImpl<MockProvider, MockEntryPoint> =
            GasEstimatorImpl::new(Chain::Optimism as u64, Arc::new(provider), entry, settings);

        let user_op = demo_user_op_optional_gas();
        let estimation = estimator.calc_pre_verification_gas(&user_op).await.unwrap();

        let u_o = user_op.max_fill(&settings);

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

        entry.expect_address().return_const(Address::zero());
        entry
            .expect_decode_simulate_handle_ops_revert()
            .returning(|_a| {
                Ok(ExecutionResult {
                    pre_op_gas: U256::from(10000),
                    paid: U256::from(100000),
                    valid_after: 100000000000,
                    valid_until: 100000000001,
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

        provider.expect_call().returning(|_a, _b| {
            let result_data: Bytes = GasUsedResult {
                gas_used: U256::from(20000),
                success: false,
                result: Bytes::new(),
            }
            .encode()
            .into();

            let json_rpc_error = JsonRpcError {
                code: -32000,
                message: "execution reverted".to_string(),
                data: Some(serde_json::Value::String(result_data.to_string())),
            };
            Err(ProviderError::JsonRpcError(json_rpc_error))
        });

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .binary_search_verification_gas(&user_op, H256::zero())
            .await
            .unwrap();

        let pre_op_gas: U256 = 10000.into();
        let gas_used: U256 = 20000.into();

        // result is based on the combination of pre op gas and gas used in loop

        assert_eq!(pre_op_gas + gas_used, estimation);
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
                    valid_after: 100000000000,
                    valid_until: 100000000001,
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
        // check for this overlflow
        provider.expect_call().returning(|_a, _b| {
            let result_data: Bytes = GasUsedResult {
                gas_used: U256::from(18446744073709551616_u128),
                success: false,
                result: Bytes::new(),
            }
            .encode()
            .into();

            let json_rpc_error = JsonRpcError {
                code: -32000,
                message: "execution reverted".to_string(),
                data: Some(serde_json::Value::String(result_data.to_string())),
            };
            Err(ProviderError::JsonRpcError(json_rpc_error))
        });

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .binary_search_verification_gas(&user_op, H256::zero())
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
                    valid_after: 100000000000,
                    valid_until: 100000000001,
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
        provider.expect_call().returning(|_a, _b| {
            let result_data: Bytes = GasUsedResult {
                gas_used: U256::from(20000),
                success: true,
                result: Bytes::new(),
            }
            .encode()
            .into();

            let json_rpc_error = JsonRpcError {
                code: -32000,
                message: "execution reverted".to_string(),
                data: Some(serde_json::Value::String(result_data.to_string())),
            };
            Err(ProviderError::JsonRpcError(json_rpc_error))
        });

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .binary_search_verification_gas(&user_op, H256::zero())
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

        provider.expect_call().returning(|_a, _b| {
            let result_data: Bytes = GasUsedResult {
                gas_used: U256::from(20000),
                success: false,
                result: Bytes::new(),
            }
            .encode()
            .into();

            let json_rpc_error = JsonRpcError {
                code: -32000,
                message: "execution reverted".to_string(),
                data: Some(serde_json::Value::String(result_data.to_string())),
            };
            Err(ProviderError::JsonRpcError(json_rpc_error))
        });

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .binary_search_verification_gas(&user_op, H256::zero())
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
                    valid_after: 100000000000,
                    valid_until: 100000000001,
                    target_success: true,
                    target_result: Bytes::new(),
                })
            });

        //this mocked response causes error
        entry
            .expect_call_spoofed_simulate_op()
            .returning(|_a, _b, _c, _d, _e, _f| Err(anyhow!("Invalid spoof error")));

        provider.expect_call().returning(|_a, _b| {
            let result_data: Bytes = GasUsedResult {
                gas_used: U256::from(20000),
                success: false,
                result: Bytes::new(),
            }
            .encode()
            .into();

            let json_rpc_error = JsonRpcError {
                code: -32000,
                message: "execution reverted".to_string(),
                data: Some(serde_json::Value::String(result_data.to_string())),
            };
            Err(ProviderError::JsonRpcError(json_rpc_error))
        });

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .binary_search_verification_gas(&user_op, H256::zero())
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
                    valid_after: 100000000000,
                    valid_until: 100000000001,
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

        provider.expect_call().returning(|_a, _b| Ok(Bytes::new()));

        let (estimator, _) = create_estimator(entry, provider);
        let user_op = demo_user_op();
        let estimation = estimator
            .binary_search_verification_gas(&user_op, H256::zero())
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
            .estimate_call_gas(&user_op, H256::zero())
            .await
            .unwrap();

        // result is derived from the spoofed gas_estimate field

        assert_eq!(estimation, U256::from(100));
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
            .estimate_call_gas(&user_op, H256::zero())
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
            .estimate_call_gas(&user_op, H256::zero())
            .await
            .unwrap();

        // on the second loop of the estimate gas continuation
        // I update the spoofed value to 200

        assert_eq!(estimation, U256::from(200));
    }

    #[tokio::test]
    async fn test_estimation_optional_gas_used() {
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
                    valid_after: 100000000000,
                    valid_until: 100000000001,
                    target_success: true,
                    target_result: Bytes::new(),
                })
            });

        provider
            .expect_get_code()
            .returning(|_a, _b| Ok(Bytes::new()));
        provider
            .expect_get_latest_block_hash()
            .returning(|| Ok(H256::zero()));
        provider.expect_call().returning(|_a, _b| {
            let result_data: Bytes = GasUsedResult {
                gas_used: U256::from(100000),
                success: false,
                result: Bytes::new(),
            }
            .encode()
            .into();

            let json_rpc_error = JsonRpcError {
                code: -32000,
                message: "execution reverted".to_string(),
                data: Some(serde_json::Value::String(result_data.to_string())),
            };
            Err(ProviderError::JsonRpcError(json_rpc_error))
        });

        let (estimator, _) = create_estimator(entry, provider);

        let user_op = demo_user_op_optional_gas();

        let estimation = estimator.estimate_op_gas(user_op).await.unwrap();

        // this number uses the same logic as the pre_verification tests
        assert_eq!(estimation.pre_verification_gas, U256::from(43296));

        // 30000 GAS_FEE_TRANSER_COST increased by default 10%
        assert_eq!(estimation.verification_gas_limit, U256::from(33000));

        // input gas limit clamped with the set limit in settings and constant MIN
        assert_eq!(estimation.call_gas_limit, U256::from(10000));
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
                    valid_after: 100000000000,
                    valid_until: 100000000001,
                    target_success: true,
                    target_result: Bytes::new(),
                })
            });

        provider
            .expect_get_code()
            .returning(|_a, _b| Ok(Bytes::new()));
        provider
            .expect_get_latest_block_hash()
            .returning(|| Ok(H256::zero()));
        provider.expect_call().returning(|_a, _b| {
            let result_data: Bytes = GasUsedResult {
                gas_used: U256::from(100000),
                success: false,
                result: Bytes::new(),
            }
            .encode()
            .into();

            let json_rpc_error = JsonRpcError {
                code: -32000,
                message: "execution reverted".to_string(),
                data: Some(serde_json::Value::String(result_data.to_string())),
            };
            Err(ProviderError::JsonRpcError(json_rpc_error))
        });

        //max_call_gas is less than MIN_CALL_GAS_LIMIT

        let settings = Settings {
            max_verification_gas: 10,
            max_call_gas: 10,
            max_simulate_handle_ops_gas: 10,
        };

        let estimator: GasEstimatorImpl<MockProvider, MockEntryPoint> =
            GasEstimatorImpl::new(0, Arc::new(provider), entry, settings);
        let user_op = demo_user_op_optional_gas();
        let estimation = estimator.estimate_op_gas(user_op).await.err();

        assert!(matches!(
            estimation,
            Some(GasEstimationError::RevertInValidation(..))
        ));
    }
}
