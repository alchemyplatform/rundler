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

use std::{cmp, marker::PhantomData};

use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::Context;
use arrayvec::ArrayVec;
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_provider::{DAGasProvider, EntryPoint, EvmProvider, FeeEstimator};
use rundler_types::{
    chain::ChainSpec,
    da::DAGasData,
    pool::{MempoolError, PrecheckViolation},
    PriorityFeeMode, UserOperation, UserOperationPermissions,
};
use rundler_utils::math;
use tracing::instrument;

use crate::{gas, types::ViolationError};

/// The min cost of a `CALL` with nonzero value, as required by the spec.
pub const MIN_CALL_GAS_LIMIT: u128 = 9100;

/// The result of a precheck call.
pub struct PrecheckReturn {
    /// DA gas data for the operation
    pub da_gas_data: DAGasData,
    /// The required pre-verification gas for the operation
    pub required_pre_verification_gas: u128,
    /// If the sender is 7702
    pub sender_is_7702: bool,
}

/// Trait for checking if a user operation is valid before simulation
/// according to the spec rules.
#[cfg_attr(feature = "test-utils", automock(type UO = rundler_types::v0_6::UserOperation;))]
#[async_trait::async_trait]
pub trait Prechecker: Send + Sync {
    /// The user operation type
    type UO: UserOperation;

    /// Run the precheck on the given operation and return an error if it fails.
    async fn check(
        &self,
        op: &Self::UO,
        perms: &UserOperationPermissions,
        block_hash: B256,
    ) -> Result<PrecheckReturn, PrecheckError>;
}

/// Precheck error
pub type PrecheckError = ViolationError<PrecheckViolation>;

impl From<PrecheckError> for MempoolError {
    fn from(mut error: PrecheckError) -> Self {
        let PrecheckError::Violations(violations) = &mut error else {
            return Self::Other(error.into());
        };

        let Some(violation) = violations.iter_mut().min() else {
            return Self::Other(error.into());
        };

        // extract violation and replace with dummy
        Self::PrecheckViolation(std::mem::replace(
            violation,
            PrecheckViolation::SenderIsNotContractAndNoInitCode(Address::ZERO),
        ))
    }
}

/// Prechecker implementation
pub struct PrecheckerImpl<UO, P, E, F> {
    chain_spec: ChainSpec,
    provider: P,
    entry_point: E,
    settings: Settings,
    fee_estimator: F,
    _uo_type: PhantomData<UO>,
}

/// Precheck settings
#[derive(Copy, Clone, Debug)]
pub struct Settings {
    /// Maximum verification gas allowed for a user operation
    pub max_verification_gas: u128,
    /// Maximum bundle execution gas allowed for a user operation
    pub max_bundle_execution_gas: u128,
    /// Maximum cost of a single user operation
    pub max_uo_cost: U256,
    /// If using a bundle priority fee, the percentage to add to the network/oracle
    /// provided value as a safety margin for fast inclusion.
    pub bundle_priority_fee_overhead_percent: u32,
    /// The priority fee mode to use for calculating required user operation priority fee.
    pub priority_fee_mode: PriorityFeeMode,
    /// Percentage of the current network base fee that a user operation must have to be accepted into the mempool.
    pub base_fee_accept_percent: u32,
    /// Percentage of the preVerificationGas that a user operation must have to be accepted into the mempool.
    /// Only applied if the chain has dynamic preVerificationGas, else enforced to 100%
    pub pre_verification_gas_accept_percent: u32,
    /// Reject user operations with gas limit efficiency below this threshold.
    /// Gas limit efficiency is defined as the ratio of the gas limit to the gas used.
    /// This applies to all the verification gas limits
    pub verification_gas_limit_efficiency_reject_threshold: f64,
    /// Whether to check if the EIP-7702 authority has too many pending transactions
    pub eip7702_authority_pending_check_enabled: bool,
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for Settings {
    fn default() -> Self {
        Self {
            max_verification_gas: 5_000_000,
            max_bundle_execution_gas: 10_000_000,
            max_uo_cost: U256::MAX,
            bundle_priority_fee_overhead_percent: 0,
            priority_fee_mode: PriorityFeeMode::BaseFeePercent(0),
            base_fee_accept_percent: 50,
            pre_verification_gas_accept_percent: 100,
            verification_gas_limit_efficiency_reject_threshold: 0.5,
            eip7702_authority_pending_check_enabled: false,
        }
    }
}

#[derive(Clone, Debug)]
struct AsyncData {
    factory_exists: bool,
    sender_bytecode: Bytes,
    paymaster_exists: bool,
    payer_funds: U256,
    base_fee: u128,
    min_pre_verification_gas: u128,
    da_gas_data: DAGasData,
    eip7702_authority_pending_transaction_count: Option<u64>,
}

#[async_trait::async_trait]
impl<UO, P, E, F> Prechecker for PrecheckerImpl<UO, P, E, F>
where
    P: EvmProvider + Clone,
    E: EntryPoint + DAGasProvider<UO = UO>,
    UO: UserOperation,
    F: FeeEstimator,
{
    type UO = UO;

    #[instrument(skip_all)]
    async fn check(
        &self,
        op: &Self::UO,
        perms: &UserOperationPermissions,
        block_hash: B256,
    ) -> Result<PrecheckReturn, PrecheckError> {
        let async_data = self.load_async_data(op, block_hash, perms).await?;
        let mut violations: Vec<PrecheckViolation> = vec![];
        violations.extend(self.check_init_code(op, &async_data, perms));
        violations.extend(self.check_gas(op, &async_data, perms));
        violations.extend(self.check_payer(op, &async_data));
        if !violations.is_empty() {
            Err(violations)?
        }
        Ok(PrecheckReturn {
            da_gas_data: async_data.da_gas_data,
            required_pre_verification_gas: async_data.min_pre_verification_gas,
            sender_is_7702: op.authorization_tuple().is_some()
                || is_7702_bytecode(&async_data.sender_bytecode),
        })
    }
}

impl<UO, P, E, F> PrecheckerImpl<UO, P, E, F>
where
    P: EvmProvider + Clone,
    E: EntryPoint + DAGasProvider<UO = UO>,
    UO: UserOperation,
    F: FeeEstimator,
{
    /// Create a new prechecker
    pub fn new(
        chain_spec: ChainSpec,
        provider: P,
        entry_point: E,
        fee_estimator: F,
        settings: Settings,
    ) -> Self {
        Self {
            chain_spec,
            provider,
            entry_point,
            settings,
            fee_estimator,
            _uo_type: PhantomData,
        }
    }

    fn check_init_code(
        &self,
        op: &UO,
        async_data: &AsyncData,
        perms: &UserOperationPermissions,
    ) -> ArrayVec<PrecheckViolation, 2> {
        let AsyncData {
            factory_exists,
            sender_bytecode,
            eip7702_authority_pending_transaction_count,
            ..
        } = async_data;
        let mut violations = ArrayVec::new();

        // 7702 delegation case
        if op.authorization_tuple().is_some() {
            if op.factory().is_some() {
                violations.push(PrecheckViolation::FactoryMustBeEmpty(op.factory().unwrap()));
            }
            if eip7702_authority_pending_transaction_count.is_some()
                && eip7702_authority_pending_transaction_count.unwrap() > 1
            {
                violations.push(
                    PrecheckViolation::Eip7702SenderPendingTransactionCountTooHigh(
                        eip7702_authority_pending_transaction_count.unwrap(),
                    ),
                );
            }
            if perms.eip7702_disabled {
                violations.push(PrecheckViolation::Eip7702Disabled);
            }
        // factory case
        } else if op.factory().is_some() {
            if !factory_exists {
                violations.push(PrecheckViolation::FactoryIsNotContract(
                    op.factory().unwrap(),
                ))
            }
            if !sender_bytecode.is_empty() {
                violations.push(PrecheckViolation::ExistingSenderWithInitCode(op.sender()));
            }
        // sender already deployed case
        } else if sender_bytecode.is_empty() {
            violations.push(PrecheckViolation::SenderIsNotContractAndNoInitCode(
                op.sender(),
            ));
        } else if perms.eip7702_disabled && is_7702_bytecode(sender_bytecode) {
            violations.push(PrecheckViolation::Eip7702Disabled);
        }
        violations
    }

    fn check_gas(
        &self,
        op: &UO,
        async_data: &AsyncData,
        perms: &UserOperationPermissions,
    ) -> ArrayVec<PrecheckViolation, 6> {
        let Settings {
            max_verification_gas,
            max_bundle_execution_gas,
            max_uo_cost,
            ..
        } = self.settings;
        let AsyncData {
            base_fee,
            mut min_pre_verification_gas,
            ..
        } = *async_data;

        let mut violations = ArrayVec::new();
        if op.total_verification_gas_limit() > max_verification_gas {
            violations.push(PrecheckViolation::VerificationGasLimitTooHigh(
                op.total_verification_gas_limit(),
                max_verification_gas,
            ));
        }

        // Compute the worst case total gas limit by assuming the UO is in its own bundle.
        // This is conservative and potentially may invalidate some very large UOs that would otherwise be valid.
        let gas_limit = op.bundle_computation_gas_limit(&self.chain_spec, Some(1));
        if gas_limit > max_bundle_execution_gas {
            violations.push(PrecheckViolation::TotalGasLimitTooHigh(
                gas_limit,
                max_bundle_execution_gas,
            ))
        } else if op.calldata_floor_gas_limit() > max_bundle_execution_gas {
            violations.push(PrecheckViolation::TotalGasLimitTooHigh(
                op.calldata_floor_gas_limit(),
                max_bundle_execution_gas,
            ))
        }
        if op.call_gas_limit() < MIN_CALL_GAS_LIMIT {
            violations.push(PrecheckViolation::CallGasLimitTooLow(
                op.call_gas_limit(),
                MIN_CALL_GAS_LIMIT,
            ));
        }

        // If the UO is bundler sponsored, skip the fee checks
        if perms.bundler_sponsorship.is_some() {
            return violations;
        }

        // NOTE: only fee checks below this short circuit

        // Check if the total gas fee of this op is too high
        if op.max_gas_cost() > max_uo_cost {
            violations.push(PrecheckViolation::OverMaxCost(
                op.max_gas_cost(),
                max_uo_cost,
            ));
        }

        // if preVerificationGas is dynamic, then allow for the percentage buffer
        // and check if the preVerificationGas is at least the minimum.
        if self.chain_spec.da_pre_verification_gas {
            let accept_pct = cmp::min(
                perms.underpriced_accept_pct.unwrap_or(100),
                self.settings.pre_verification_gas_accept_percent,
            );

            min_pre_verification_gas = math::percent_ceil(min_pre_verification_gas, accept_pct);
        }

        if op.pre_verification_gas() < min_pre_verification_gas {
            violations.push(PrecheckViolation::PreVerificationGasTooLow(
                op.pre_verification_gas(),
                min_pre_verification_gas,
            ));
        }

        // check that the max fee per gas and max priority fee per gas are at least the required fees
        let min_base_fee_accept_pct = cmp::min(
            perms.underpriced_accept_pct.unwrap_or(100),
            self.settings.base_fee_accept_percent,
        );
        let min_base_fee = math::percent_ceil(base_fee, min_base_fee_accept_pct);
        let min_priority_fee = self.settings.priority_fee_mode.minimum_priority_fee(
            base_fee,
            min_base_fee_accept_pct,
            self.chain_spec.min_max_priority_fee_per_gas(),
            self.settings.bundle_priority_fee_overhead_percent,
        );
        let min_max_fee = min_base_fee + min_priority_fee;

        // check priority fee first, since once ruled out we can check max fee
        if op.max_priority_fee_per_gas() < min_priority_fee {
            violations.push(PrecheckViolation::MaxPriorityFeePerGasTooLow(
                op.max_priority_fee_per_gas(),
                min_priority_fee,
            ));
        }
        if op.max_fee_per_gas() < min_max_fee {
            violations.push(PrecheckViolation::MaxFeePerGasTooLow(
                op.max_fee_per_gas(),
                min_max_fee,
            ));
        }

        violations
    }

    fn check_payer(&self, op: &UO, async_data: &AsyncData) -> Option<PrecheckViolation> {
        let AsyncData {
            paymaster_exists,
            payer_funds,
            ..
        } = *async_data;
        if let Some(paymaster) = op.paymaster() {
            if !paymaster_exists {
                return Some(PrecheckViolation::PaymasterIsNotContract(paymaster));
            }
        }
        let max_gas_cost = op.max_gas_cost();
        if payer_funds < max_gas_cost {
            if op.paymaster().is_none() {
                return Some(PrecheckViolation::SenderFundsTooLow(
                    payer_funds,
                    max_gas_cost,
                ));
            } else {
                return Some(PrecheckViolation::PaymasterDepositTooLow(
                    payer_funds,
                    max_gas_cost,
                ));
            }
        }
        None
    }

    #[instrument(skip_all)]
    async fn load_async_data(
        &self,
        op: &UO,
        block_hash: B256,
        perms: &UserOperationPermissions,
    ) -> anyhow::Result<AsyncData> {
        let base_fee = self.get_base_fee(block_hash).await?;

        let (
            factory_exists,
            sender_bytecode,
            paymaster_exists,
            payer_funds,
            (min_pre_verification_gas, da_gas_data),
            eip7702_authority_pending_transaction_count,
        ) = tokio::try_join!(
            self.is_contract(op.factory()),
            self.get_bytecode(op.sender()),
            self.is_contract(op.paymaster()),
            self.get_payer_funds(op),
            self.get_required_pre_verification_gas(op.clone(), block_hash, base_fee, perms),
            self.get_eip7702_authority_pending_transaction_count(op)
        )?;
        Ok(AsyncData {
            factory_exists,
            sender_bytecode,
            paymaster_exists,
            payer_funds,
            base_fee,
            min_pre_verification_gas,
            da_gas_data,
            eip7702_authority_pending_transaction_count,
        })
    }

    async fn get_bytecode(&self, address: Address) -> anyhow::Result<Bytes> {
        self.provider
            .get_code(address, None)
            .await
            .context("should load code to check if contract exists")
    }

    #[instrument(skip_all)]
    async fn is_contract(&self, address: Option<Address>) -> anyhow::Result<bool> {
        let Some(address) = address else {
            return Ok(false);
        };
        let bytecode = self.get_bytecode(address).await?;
        Ok(!bytecode.is_empty())
    }

    #[instrument(skip_all)]
    async fn get_payer_funds(&self, op: &UO) -> anyhow::Result<U256> {
        let (deposit, balance) =
            tokio::try_join!(self.get_payer_deposit(op), self.get_payer_balance(op),)?;
        Ok(deposit + balance)
    }

    #[instrument(skip_all)]
    async fn get_payer_deposit(&self, op: &UO) -> anyhow::Result<U256> {
        let payer = match op.paymaster() {
            Some(paymaster) => paymaster,
            None => op.sender(),
        };
        self.entry_point
            .balance_of(payer, None)
            .await
            .context("precheck should get payer balance")
    }

    #[instrument(skip_all)]
    async fn get_payer_balance(&self, op: &UO) -> anyhow::Result<U256> {
        if op.paymaster().is_some() {
            // Paymasters must deposit eth, and cannot pay with their own.
            return Ok(U256::ZERO);
        }
        self.provider
            .get_balance(op.sender(), None)
            .await
            .context("precheck should get sender balance")
    }

    #[instrument(skip_all)]
    async fn get_base_fee(&self, block_hash: B256) -> anyhow::Result<u128> {
        let (_, base_fee) = self
            .fee_estimator
            .required_bundle_fees(block_hash, None)
            .await?;
        Ok(base_fee)
    }

    #[instrument(skip_all)]
    async fn get_required_pre_verification_gas(
        &self,
        op: UO,
        block_hash: B256,
        base_fee: u128,
        perms: &UserOperationPermissions,
    ) -> anyhow::Result<(u128, DAGasData)> {
        if perms.bundler_sponsorship.is_some() {
            return Ok((0, DAGasData::Empty));
        }

        gas::calc_required_pre_verification_gas(
            &self.chain_spec,
            &self.entry_point,
            &op,
            block_hash,
            base_fee,
            self.settings
                .verification_gas_limit_efficiency_reject_threshold,
        )
        .await
    }

    async fn get_eip7702_authority_pending_transaction_count(
        &self,
        op: &UO,
    ) -> anyhow::Result<Option<u64>> {
        if op.authorization_tuple().is_none()
            || !self.settings.eip7702_authority_pending_check_enabled
        {
            return Ok(None);
        }
        let sender = op.sender();
        let (pending_count, transaction_count) = tokio::try_join!(
            self.provider.get_pending_transaction_count(sender),
            self.provider.get_transaction_count(sender),
        )?;
        tracing::info!(
            "pending_count: {}, transaction_count: {}",
            pending_count,
            transaction_count
        );
        Ok(Some(pending_count - transaction_count))
    }
}

fn is_7702_bytecode(bytecode: &Bytes) -> bool {
    if bytecode.len() < 23 {
        return false;
    }
    let prefix = &bytecode[..3];
    prefix == [0xef, 0x01, 0x00]
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::{address, bytes, Bytes};
    use rundler_provider::{MockEntryPointV0_6, MockEvmProvider, MockFeeEstimator};
    use rundler_types::{
        v0_6::{UserOperationBuilder, UserOperationRequiredFields},
        BundlerSponsorship, UserOperation as _,
    };

    use super::*;

    fn create_base_config() -> (
        ChainSpec,
        MockEvmProvider,
        MockEntryPointV0_6,
        MockFeeEstimator,
    ) {
        (
            ChainSpec::default(),
            MockEvmProvider::new(),
            MockEntryPointV0_6::new(),
            MockFeeEstimator::new(),
        )
    }

    fn get_test_async_data() -> AsyncData {
        AsyncData {
            factory_exists: true,
            sender_bytecode: bytes!("abcdef"),
            paymaster_exists: true,
            payer_funds: U256::from(5_000_000),
            base_fee: 4_000,
            min_pre_verification_gas: 1_000,
            da_gas_data: DAGasData::Empty,
            eip7702_authority_pending_transaction_count: None,
        }
    }

    #[tokio::test]
    async fn test_check_init_code() {
        let (cs, provider, entry_point, fee_estimator) = create_base_config();
        let provider = Arc::new(provider);
        let prechecker = PrecheckerImpl::new(
            cs.clone(),
            provider,
            entry_point,
            fee_estimator,
            Settings::default(),
        );
        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                sender: address!("3f8a2b6c4d5e1079286fa1b3c0d4e5f6902b7c8d"),
                nonce: U256::from(100),
                init_code: bytes!("3f8a2b6c4d5e1079286fa1b3c0d4e5f6902b7c8d"),
                call_data: Bytes::default(),
                call_gas_limit: 9_000, // large call gas limit high to trigger TotalGasLimitTooHigh
                verification_gas_limit: 10_000_000,
                pre_verification_gas: 0,
                max_fee_per_gas: 5_000,
                max_priority_fee_per_gas: 2_000,
                paymaster_and_data: Bytes::default(),
                signature: Bytes::default(),
            },
        )
        .build();

        let res = prechecker.check_init_code(
            &op,
            &get_test_async_data(),
            &UserOperationPermissions::default(),
        );
        let mut expected = ArrayVec::new();
        expected.push(PrecheckViolation::ExistingSenderWithInitCode(address!(
            "3f8a2b6c4d5e1079286fa1b3c0d4e5f6902b7c8d"
        )));
        assert_eq!(res, expected);
    }

    #[tokio::test]
    async fn test_check_init_code_7702_disabled() {
        let (cs, provider, entry_point, fee_estimator) = create_base_config();
        let provider = Arc::new(provider);
        let prechecker = PrecheckerImpl::new(
            cs.clone(),
            provider,
            entry_point,
            fee_estimator,
            Settings::default(),
        );
        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                sender: address!("3f8a2b6c4d5e1079286fa1b3c0d4e5f6902b7c8d"),
                nonce: U256::from(100),
                init_code: Bytes::default(),
                call_data: Bytes::default(),
                call_gas_limit: 9_000, // large call gas limit high to trigger TotalGasLimitTooHigh
                verification_gas_limit: 10_000_000,
                pre_verification_gas: 0,
                max_fee_per_gas: 5_000,
                max_priority_fee_per_gas: 2_000,
                paymaster_and_data: Bytes::default(),
                signature: Bytes::default(),
            },
        )
        .build();

        let perms = UserOperationPermissions {
            eip7702_disabled: true,
            ..Default::default()
        };

        let mut async_data = get_test_async_data();
        // 7702 indicator plus address
        async_data.sender_bytecode = bytes!("ef01000000000000000000000000000000000000000000");

        let res = prechecker.check_init_code(&op, &async_data, &perms);
        let mut expected = ArrayVec::new();
        expected.push(PrecheckViolation::Eip7702Disabled);
        assert_eq!(res, expected);
    }

    #[tokio::test]
    async fn test_check_gas() {
        let test_settings = Settings {
            max_verification_gas: 5_000_000,
            max_bundle_execution_gas: 10_000_000,
            max_uo_cost: U256::MAX,
            bundle_priority_fee_overhead_percent: 0,
            priority_fee_mode: PriorityFeeMode::BaseFeePercent(100),
            base_fee_accept_percent: 100,
            pre_verification_gas_accept_percent: 100,
            verification_gas_limit_efficiency_reject_threshold: 0.5,
            eip7702_authority_pending_check_enabled: false,
        };

        let (cs, provider, entry_point, fee_estimator) = create_base_config();
        let provider = Arc::new(provider);
        let prechecker = PrecheckerImpl::new(
            cs.clone(),
            provider,
            entry_point,
            fee_estimator,
            test_settings,
        );

        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                sender: address!("3f8a2b6c4d5e1079286fa1b3c0d4e5f6902b7c8d"),
                nonce: U256::from(100),
                init_code: bytes!("1000000000000000000000000000000000000000"),
                call_data: Bytes::default(),
                call_gas_limit: 9_000, // large call gas limit high to trigger TotalGasLimitTooHigh
                verification_gas_limit: 10_000_000,
                pre_verification_gas: 0,
                max_fee_per_gas: 5_000,
                max_priority_fee_per_gas: 2_000,
                paymaster_and_data: Bytes::default(),
                signature: Bytes::default(),
            },
        )
        .build();

        let res = prechecker.check_gas(
            &op,
            &get_test_async_data(),
            &UserOperationPermissions::default(),
        );

        let total_gas_limit = op.bundle_gas_limit(&cs, Some(1));

        assert_eq!(
            res,
            ArrayVec::<PrecheckViolation, 6>::from([
                PrecheckViolation::VerificationGasLimitTooHigh(10_000_000, 5_000_000,),
                PrecheckViolation::TotalGasLimitTooHigh(total_gas_limit, 10_000_000,),
                PrecheckViolation::CallGasLimitTooLow(9_000, 9_100,),
                PrecheckViolation::PreVerificationGasTooLow(0, 1_000,),
                PrecheckViolation::MaxPriorityFeePerGasTooLow(2_000, 4_000,),
                PrecheckViolation::MaxFeePerGasTooLow(5_000, 8_000,),
            ])
        );
    }

    #[tokio::test]
    async fn test_check_payer_paymaster_deposit_too_low() {
        let (cs, provider, entry_point, fee_estimator) = create_base_config();
        let provider = Arc::new(provider);
        let prechecker = PrecheckerImpl::new(
            cs.clone(),
            provider,
            entry_point,
            fee_estimator,
            Settings::default(),
        );

        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                sender: address!("3f8a2b6c4d5e1079286fa1b3c0d4e5f6902b7c8d"),
                nonce: U256::from(100),
                init_code: Bytes::default(),
                call_data: Bytes::default(),
                call_gas_limit: 500_000,
                verification_gas_limit: 500_000,
                pre_verification_gas: 0,
                max_fee_per_gas: 1_000,
                max_priority_fee_per_gas: 0,
                paymaster_and_data: bytes!(
                    "a4b2c8f0351d60729e4f0a12345678d9b1c3e5f27890abcdef123456780abcdef1"
                ),
                signature: Bytes::default(),
            },
        )
        .build();

        let res = prechecker.check_payer(&op, &get_test_async_data());
        assert_eq!(
            res,
            Some(PrecheckViolation::PaymasterDepositTooLow(
                U256::from(5_000_000),
                U256::from(2_000_000_000),
            ))
        );
    }

    #[tokio::test]
    async fn test_check_fees() {
        let settings = Settings {
            base_fee_accept_percent: 80,
            priority_fee_mode: PriorityFeeMode::PriorityFeeIncreasePercent(0),
            ..Default::default()
        };

        let (mut cs, provider, entry_point, fee_estimator) = create_base_config();
        cs.id = 10;
        let mintip = cs.min_max_priority_fee_per_gas();

        let provider = Arc::new(provider);
        let prechecker =
            PrecheckerImpl::new(cs.clone(), provider, entry_point, fee_estimator, settings);

        let mut async_data = get_test_async_data();
        async_data.base_fee = 5_000;
        async_data.min_pre_verification_gas = 1_000;

        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                max_fee_per_gas: math::percent(5000, settings.base_fee_accept_percent) + mintip,
                max_priority_fee_per_gas: mintip,
                pre_verification_gas: math::percent(
                    1_000,
                    settings.pre_verification_gas_accept_percent,
                ),
                call_gas_limit: MIN_CALL_GAS_LIMIT,
                ..Default::default()
            },
        )
        .build();

        let res = prechecker.check_gas(&op, &async_data, &UserOperationPermissions::default());
        assert!(res.is_empty());
    }

    #[tokio::test]
    async fn test_check_fees_too_low() {
        let settings = Settings {
            base_fee_accept_percent: 80,
            priority_fee_mode: PriorityFeeMode::PriorityFeeIncreasePercent(0),
            ..Default::default()
        };

        let (cs, provider, entry_point, fee_estimator) = create_base_config();
        let provider = Arc::new(provider);
        let prechecker =
            PrecheckerImpl::new(cs.clone(), provider, entry_point, fee_estimator, settings);

        let mut async_data = get_test_async_data();
        async_data.base_fee = 5_000;
        async_data.min_pre_verification_gas = 1_000;

        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                max_fee_per_gas: math::percent(5000, settings.base_fee_accept_percent - 10),
                max_priority_fee_per_gas: 0,
                pre_verification_gas: 1_000,
                call_gas_limit: MIN_CALL_GAS_LIMIT,
                ..Default::default()
            },
        )
        .build();

        let res = prechecker.check_gas(&op, &async_data, &UserOperationPermissions::default());
        let mut expected = ArrayVec::<PrecheckViolation, 6>::new();
        expected.push(PrecheckViolation::MaxFeePerGasTooLow(
            math::percent(5_000, settings.base_fee_accept_percent - 10),
            math::percent(5_000, settings.base_fee_accept_percent),
        ));

        assert_eq!(res, expected);
    }

    #[tokio::test]
    async fn test_check_fees_min() {
        let settings = Settings {
            base_fee_accept_percent: 100,
            priority_fee_mode: PriorityFeeMode::PriorityFeeIncreasePercent(0),
            ..Default::default()
        };

        let (mut cs, provider, entry_point, fee_estimator) = create_base_config();
        cs.id = 10;
        cs.min_max_priority_fee_per_gas = 100_000;
        let mintip = cs.min_max_priority_fee_per_gas();

        let provider = Arc::new(provider);
        let prechecker =
            PrecheckerImpl::new(cs.clone(), provider, entry_point, fee_estimator, settings);

        let mut async_data = get_test_async_data();
        async_data.base_fee = 5_000;
        async_data.min_pre_verification_gas = 1_000;

        let undertip = mintip - 1;

        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                max_fee_per_gas: 5_000 + mintip,
                max_priority_fee_per_gas: undertip,
                pre_verification_gas: 1_000,
                call_gas_limit: MIN_CALL_GAS_LIMIT,
                ..Default::default()
            },
        )
        .build();

        let res = prechecker.check_gas(&op, &async_data, &UserOperationPermissions::default());
        let mut expected = ArrayVec::<PrecheckViolation, 6>::new();
        expected.push(PrecheckViolation::MaxPriorityFeePerGasTooLow(
            mintip - 1,
            mintip,
        ));

        assert_eq!(res, expected);
    }

    #[tokio::test]
    async fn test_pvg_too_low() {
        let settings = Settings {
            base_fee_accept_percent: 80,
            priority_fee_mode: PriorityFeeMode::PriorityFeeIncreasePercent(0),
            ..Default::default()
        };

        let (cs, provider, entry_point, fee_estimator) = create_base_config();
        let provider = Arc::new(provider);
        let prechecker =
            PrecheckerImpl::new(cs.clone(), provider, entry_point, fee_estimator, settings);

        let mut async_data = get_test_async_data();
        async_data.base_fee = 5_000;
        async_data.min_pre_verification_gas = 1_000;

        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                max_fee_per_gas: 5000,
                max_priority_fee_per_gas: 0,
                pre_verification_gas: math::percent(
                    1_000,
                    settings.pre_verification_gas_accept_percent - 10,
                ),
                call_gas_limit: MIN_CALL_GAS_LIMIT,
                ..Default::default()
            },
        )
        .build();

        let res = prechecker.check_gas(&op, &async_data, &UserOperationPermissions::default());
        let mut expected = ArrayVec::<PrecheckViolation, 6>::new();
        expected.push(PrecheckViolation::PreVerificationGasTooLow(
            math::percent(1_000, settings.pre_verification_gas_accept_percent - 10),
            math::percent(1_000, settings.pre_verification_gas_accept_percent),
        ));

        assert_eq!(res, expected);
    }

    #[tokio::test]
    async fn test_check_fees_relaxed() {
        let settings = Settings {
            base_fee_accept_percent: 80,
            priority_fee_mode: PriorityFeeMode::PriorityFeeIncreasePercent(0),
            ..Default::default()
        };

        let (mut cs, provider, entry_point, fee_estimator) = create_base_config();
        cs.id = 10;
        cs.da_pre_verification_gas = true;
        let mintip = cs.min_max_priority_fee_per_gas();

        let provider = Arc::new(provider);
        let prechecker =
            PrecheckerImpl::new(cs.clone(), provider, entry_point, fee_estimator, settings);

        let mut async_data = get_test_async_data();
        async_data.base_fee = 5_000;
        async_data.min_pre_verification_gas = 1_000;

        let pct_underpriced = 50;

        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                max_fee_per_gas: math::percent(5000, pct_underpriced) + mintip,
                max_priority_fee_per_gas: mintip,
                pre_verification_gas: math::percent(1_000, pct_underpriced),
                call_gas_limit: MIN_CALL_GAS_LIMIT,
                ..Default::default()
            },
        )
        .build();

        let perms = UserOperationPermissions {
            underpriced_accept_pct: Some(pct_underpriced),
            ..Default::default()
        };

        let res = prechecker.check_gas(&op, &async_data, &perms);
        assert!(res.is_empty());
    }

    #[tokio::test]
    async fn test_check_fees_relaxed_underpriced() {
        let settings = Settings {
            base_fee_accept_percent: 80,
            priority_fee_mode: PriorityFeeMode::PriorityFeeIncreasePercent(0),
            ..Default::default()
        };

        let (mut cs, provider, entry_point, fee_estimator) = create_base_config();
        cs.id = 10;
        cs.da_pre_verification_gas = true;
        let mintip = cs.min_max_priority_fee_per_gas();

        let provider = Arc::new(provider);
        let prechecker =
            PrecheckerImpl::new(cs.clone(), provider, entry_point, fee_estimator, settings);

        let mut async_data = get_test_async_data();
        async_data.base_fee = 5_000;
        async_data.min_pre_verification_gas = 1_000;

        let pct_underpriced = 50;

        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                max_fee_per_gas: math::percent(5000, pct_underpriced - 10) + mintip,
                max_priority_fee_per_gas: mintip,
                pre_verification_gas: math::percent(1_000, pct_underpriced - 10),
                call_gas_limit: MIN_CALL_GAS_LIMIT,
                ..Default::default()
            },
        )
        .build();

        let perms = UserOperationPermissions {
            underpriced_accept_pct: Some(pct_underpriced),
            ..Default::default()
        };

        let res = prechecker.check_gas(&op, &async_data, &perms);

        let mut expected = ArrayVec::<PrecheckViolation, 6>::new();
        expected.push(PrecheckViolation::PreVerificationGasTooLow(
            math::percent(1_000, pct_underpriced - 10),
            math::percent(1_000, pct_underpriced),
        ));
        expected.push(PrecheckViolation::MaxFeePerGasTooLow(
            math::percent(5000, pct_underpriced - 10),
            math::percent(5000, pct_underpriced),
        ));

        assert_eq!(res, expected);
    }

    #[tokio::test]
    async fn test_bundler_sponsorship_skip_fee_check() {
        let settings = Settings {
            base_fee_accept_percent: 80,
            priority_fee_mode: PriorityFeeMode::PriorityFeeIncreasePercent(0),
            ..Default::default()
        };

        let (mut cs, provider, entry_point, fee_estimator) = create_base_config();
        cs.id = 10;
        cs.da_pre_verification_gas = true;

        let provider = Arc::new(provider);
        let prechecker =
            PrecheckerImpl::new(cs.clone(), provider, entry_point, fee_estimator, settings);

        let mut async_data = get_test_async_data();
        async_data.base_fee = 5_000;
        async_data.min_pre_verification_gas = 1_000;

        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                max_fee_per_gas: 0,
                max_priority_fee_per_gas: 0,
                pre_verification_gas: 0,
                call_gas_limit: MIN_CALL_GAS_LIMIT,
                ..Default::default()
            },
        )
        .build();

        let perms = UserOperationPermissions {
            bundler_sponsorship: Some(BundlerSponsorship {
                max_cost: U256::from(100),
                valid_until: u64::MAX,
            }),
            ..Default::default()
        };

        let res = prechecker.check_gas(&op, &async_data, &perms);
        assert!(res.is_empty());
    }

    #[tokio::test]
    async fn test_max_uo_cost_fail() {
        let settings = Settings {
            max_uo_cost: U256::from(1_000_000_000), // 1 gwei
            ..Default::default()
        };

        let (cs, provider, entry_point, fee_estimator) = create_base_config();
        let provider = Arc::new(provider);
        let prechecker =
            PrecheckerImpl::new(cs.clone(), provider, entry_point, fee_estimator, settings);

        let mut async_data = get_test_async_data();
        async_data.base_fee = 1_000;

        // Create a UO with a high gas cost that exceeds max_uo_cost
        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                max_fee_per_gas: 1_000,
                max_priority_fee_per_gas: 100,
                call_gas_limit: 1_000_000,
                verification_gas_limit: 1_000_000,
                pre_verification_gas: 1_000_000,
                ..Default::default()
            }, // max gas cost 3 gwei
        )
        .build();

        let res = prechecker.check_gas(&op, &async_data, &UserOperationPermissions::default());

        // Calculate expected max gas cost
        let max_gas_cost = op.max_gas_cost();
        let mut expected = ArrayVec::<PrecheckViolation, 6>::new();
        expected.push(PrecheckViolation::OverMaxCost(
            max_gas_cost,
            U256::from(1_000_000_000),
        ));

        assert_eq!(res, expected);
    }

    #[tokio::test]
    async fn test_max_uo_cost_pass() {
        let settings = Settings {
            max_uo_cost: U256::from(5_000_000_000_u128), // 5 gwei
            ..Default::default()
        };

        let (cs, provider, entry_point, fee_estimator) = create_base_config();
        let provider = Arc::new(provider);
        let prechecker =
            PrecheckerImpl::new(cs.clone(), provider, entry_point, fee_estimator, settings);

        let mut async_data = get_test_async_data();
        async_data.base_fee = 1_000;

        // Create a UO with a high gas cost that exceeds max_uo_cost
        let op = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                max_fee_per_gas: 1_000,
                max_priority_fee_per_gas: 100,
                call_gas_limit: 1_000_000,
                verification_gas_limit: 1_000_000,
                pre_verification_gas: 1_000_000,
                ..Default::default()
            }, // max gas cost 3 gwei
        )
        .build();

        let res = prechecker.check_gas(&op, &async_data, &UserOperationPermissions::default());
        assert!(res.is_empty());
    }
}
