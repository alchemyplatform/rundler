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

use std::sync::Arc;

use anyhow::Context;
use arrayvec::ArrayVec;
use ethers::types::{Address, U256};
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_provider::{EntryPoint, Provider};
use rundler_types::{GasFees, UserOperation};

use crate::{gas, types::ViolationError};

/// The min cost of a `CALL` with nonzero value, as required by the spec.
pub const MIN_CALL_GAS_LIMIT: U256 = U256([9100, 0, 0, 0]);

/// Trait for checking if a user operation is valid before simulation
/// according to the spec rules.
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait Prechecker: Send + Sync + 'static {
    /// Run the precheck on the given operation and return an error if it fails.
    async fn check(&self, op: &UserOperation) -> Result<(), PrecheckError>;
}

/// Precheck error
pub type PrecheckError = ViolationError<PrecheckViolation>;

/// Prechecker implementation
#[derive(Debug)]
pub struct PrecheckerImpl<P: Provider, E: EntryPoint> {
    provider: Arc<P>,
    entry_point: E,
    settings: Settings,
    fee_estimator: gas::FeeEstimator<P>,
}

/// Precheck settings
#[derive(Copy, Clone, Debug)]
pub struct Settings {
    /// Chain ID
    pub chain_id: u64,
    /// Maximum verification gas allowed for a user operation
    pub max_verification_gas: U256,
    /// Maximum total execution gas allowed for a user operation
    pub max_total_execution_gas: U256,
    /// Whether to use a bundle priority fee on the bundle transaction.
    /// If `None`, the default is to use a bundle priority fee if the
    /// chain id known to support EIP-1559.
    pub use_bundle_priority_fee: Option<bool>,
    /// If using a bundle priority fee, the percentage to add to the network/oracle
    /// provided value as a safety margin for fast inclusion.
    pub bundle_priority_fee_overhead_percent: u64,
    /// The priority fee mode to use for calculating required user operation priority fee.
    pub priority_fee_mode: gas::PriorityFeeMode,
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for Settings {
    fn default() -> Self {
        Self {
            max_verification_gas: 5_000_000.into(),
            use_bundle_priority_fee: None,
            bundle_priority_fee_overhead_percent: 0,
            priority_fee_mode: gas::PriorityFeeMode::BaseFeePercent(0),
            max_total_execution_gas: 10_000_000.into(),
            chain_id: 1,
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct AsyncData {
    factory_exists: bool,
    sender_exists: bool,
    paymaster_exists: bool,
    payer_funds: U256,
    bundle_fees: GasFees,
    min_pre_verification_gas: U256,
}

#[async_trait::async_trait]
impl<P: Provider, E: EntryPoint> Prechecker for PrecheckerImpl<P, E> {
    async fn check(&self, op: &UserOperation) -> Result<(), PrecheckError> {
        let async_data = self.load_async_data(op).await?;
        let mut violations: Vec<PrecheckViolation> = vec![];
        violations.extend(self.check_init_code(op, async_data));
        violations.extend(self.check_gas(op, async_data));
        violations.extend(self.check_payer(op, async_data));
        if !violations.is_empty() {
            Err(violations)?
        }
        Ok(())
    }
}

impl<P: Provider, E: EntryPoint> PrecheckerImpl<P, E> {
    /// Create a new prechecker
    pub fn new(provider: Arc<P>, entry_point: E, settings: Settings) -> Self {
        Self {
            provider: provider.clone(),
            entry_point,
            settings,
            fee_estimator: gas::FeeEstimator::new(
                provider,
                settings.chain_id,
                settings.priority_fee_mode,
                settings.use_bundle_priority_fee,
                settings.bundle_priority_fee_overhead_percent,
            ),
        }
    }

    fn check_init_code(
        &self,
        op: &UserOperation,
        async_data: AsyncData,
    ) -> ArrayVec<PrecheckViolation, 2> {
        let AsyncData {
            factory_exists,
            sender_exists,
            ..
        } = async_data;
        let mut violations = ArrayVec::new();
        let len = op.init_code.len();
        if len == 0 {
            if !sender_exists {
                violations.push(PrecheckViolation::SenderIsNotContractAndNoInitCode(
                    op.sender,
                ));
            }
        } else {
            if len < 20 {
                violations.push(PrecheckViolation::InitCodeTooShort(len));
            } else if !factory_exists {
                violations.push(PrecheckViolation::FactoryIsNotContract(
                    op.factory().unwrap(),
                ))
            }
            if sender_exists {
                violations.push(PrecheckViolation::ExistingSenderWithInitCode(op.sender));
            }
        }
        violations
    }

    fn check_gas(
        &self,
        op: &UserOperation,
        async_data: AsyncData,
    ) -> ArrayVec<PrecheckViolation, 6> {
        let Settings {
            chain_id,
            max_verification_gas,
            max_total_execution_gas,
            ..
        } = self.settings;
        let AsyncData {
            bundle_fees,
            min_pre_verification_gas,
            ..
        } = async_data;

        let mut violations = ArrayVec::new();
        if op.verification_gas_limit > max_verification_gas {
            violations.push(PrecheckViolation::VerificationGasLimitTooHigh(
                op.verification_gas_limit,
                max_verification_gas,
            ));
        }
        let total_gas_limit = gas::user_operation_gas_limit(op, chain_id);
        if total_gas_limit > max_total_execution_gas {
            violations.push(PrecheckViolation::TotalGasLimitTooHigh(
                total_gas_limit,
                max_total_execution_gas,
            ))
        }
        if op.pre_verification_gas < min_pre_verification_gas {
            violations.push(PrecheckViolation::PreVerificationGasTooLow(
                op.pre_verification_gas,
                min_pre_verification_gas,
            ));
        }

        let required_fees = self.fee_estimator.required_op_fees(bundle_fees);

        if op.max_fee_per_gas < required_fees.max_fee_per_gas {
            violations.push(PrecheckViolation::MaxFeePerGasTooLow(
                op.max_fee_per_gas,
                required_fees.max_fee_per_gas,
            ));
        }
        if op.max_priority_fee_per_gas < required_fees.max_priority_fee_per_gas {
            violations.push(PrecheckViolation::MaxPriorityFeePerGasTooLow(
                op.max_priority_fee_per_gas,
                required_fees.max_priority_fee_per_gas,
            ));
        }

        if op.call_gas_limit < MIN_CALL_GAS_LIMIT {
            violations.push(PrecheckViolation::CallGasLimitTooLow(
                op.call_gas_limit,
                MIN_CALL_GAS_LIMIT,
            ));
        }
        violations
    }

    fn check_payer(&self, op: &UserOperation, async_data: AsyncData) -> Option<PrecheckViolation> {
        let AsyncData {
            paymaster_exists,
            payer_funds,
            ..
        } = async_data;
        if !op.paymaster_and_data.is_empty() {
            let Some(paymaster) = op.paymaster() else {
                return Some(PrecheckViolation::PaymasterTooShort(
                    op.paymaster_and_data.len(),
                ));
            };
            if !paymaster_exists {
                return Some(PrecheckViolation::PaymasterIsNotContract(paymaster));
            }
        }
        let max_gas_cost = gas::user_operation_max_gas_cost(op);
        if payer_funds < max_gas_cost {
            if op.paymaster_and_data.is_empty() {
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

    async fn load_async_data(&self, op: &UserOperation) -> anyhow::Result<AsyncData> {
        let (
            factory_exists,
            sender_exists,
            paymaster_exists,
            payer_funds,
            bundle_fees,
            min_pre_verification_gas,
        ) = tokio::try_join!(
            self.is_contract(op.factory()),
            self.is_contract(Some(op.sender)),
            self.is_contract(op.paymaster()),
            self.get_payer_funds(op),
            self.get_bundle_fees(),
            self.get_pre_verification_gas(op.clone())
        )?;
        Ok(AsyncData {
            factory_exists,
            sender_exists,
            paymaster_exists,
            payer_funds,
            bundle_fees,
            min_pre_verification_gas,
        })
    }

    async fn is_contract(&self, address: Option<Address>) -> anyhow::Result<bool> {
        let Some(address) = address else {
            return Ok(false);
        };
        let bytecode = self
            .provider
            .get_code(address, None)
            .await
            .context("should load code to check if contract exists")?;
        Ok(!bytecode.is_empty())
    }

    async fn get_payer_funds(&self, op: &UserOperation) -> anyhow::Result<U256> {
        let (deposit, balance) =
            tokio::try_join!(self.get_payer_deposit(op), self.get_payer_balance(op),)?;
        Ok(deposit + balance)
    }

    async fn get_payer_deposit(&self, op: &UserOperation) -> anyhow::Result<U256> {
        let payer = match op.paymaster() {
            Some(paymaster) => paymaster,
            None => op.sender,
        };
        self.entry_point
            .balance_of(payer, None)
            .await
            .context("precheck should get payer balance")
    }

    async fn get_payer_balance(&self, op: &UserOperation) -> anyhow::Result<U256> {
        if !op.paymaster_and_data.is_empty() {
            // Paymasters must deposit eth, and cannot pay with their own.
            return Ok(0.into());
        }
        self.provider
            .get_balance(op.sender, None)
            .await
            .context("precheck should get sender balance")
    }

    async fn get_bundle_fees(&self) -> anyhow::Result<GasFees> {
        self.fee_estimator
            .required_bundle_fees(None)
            .await
            .context("should get bundle fees")
    }

    async fn get_pre_verification_gas(&self, op: UserOperation) -> anyhow::Result<U256> {
        gas::calc_pre_verification_gas(
            &op,
            &op,
            self.entry_point.address(),
            self.provider.clone(),
            self.settings.chain_id,
        )
        .await
        .context("should calculate pre-verification gas")
    }
}

/// Precheck violation enumeration
///
/// All possible errors that can be returned from a precheck.
#[derive(Clone, Debug, parse_display::Display, Eq, PartialEq, Ord, PartialOrd)]
pub enum PrecheckViolation {
    /// The init code is too short to contain a factory address.
    #[display("initCode must start with a 20-byte factory address, but was only {0} bytes")]
    InitCodeTooShort(usize),
    /// The sender is not deployed, and no init code is provided.
    #[display("sender {0:?} is not a contract and initCode is empty")]
    SenderIsNotContractAndNoInitCode(Address),
    /// The sender is already deployed, and an init code is provided.
    #[display("sender {0:?} is an existing contract, but initCode is nonempty")]
    ExistingSenderWithInitCode(Address),
    /// An init code contains a factory address that is not deployed.
    #[display("initCode indicates factory with no code: {0:?}")]
    FactoryIsNotContract(Address),
    /// The total gas limit of the user operation is too high.
    /// See `gas::user_operation_execution_gas_limit` for calculation.
    #[display("total gas limit is {0} but must be at most {1}")]
    TotalGasLimitTooHigh(U256, U256),
    /// The verification gas limit of the user operation is too high.
    #[display("verificationGasLimit is {0} but must be at most {1}")]
    VerificationGasLimitTooHigh(U256, U256),
    /// The pre-verification gas of the user operation is too low.
    #[display("preVerificationGas is {0} but must be at least {1}")]
    PreVerificationGasTooLow(U256, U256),
    /// The paymaster and data is too short to contain a paymaster address.
    #[display("paymasterAndData must start a 20-byte paymaster address, but was only {0} bytes")]
    PaymasterTooShort(usize),
    /// A paymaster is provided, but the address is not deployed.
    #[display("paymasterAndData indicates paymaster with no code: {0:?}")]
    PaymasterIsNotContract(Address),
    /// The paymaster deposit is too low to pay for the user operation's maximum cost.
    #[display("paymaster deposit is {0} but must be at least {1} to pay for this operation")]
    PaymasterDepositTooLow(U256, U256),
    /// The sender balance is too low to pay for the user operation's maximum cost.
    /// (when not using a paymaster)
    #[display("sender balance and deposit together is {0} but must be at least {1} to pay for this operation")]
    SenderFundsTooLow(U256, U256),
    /// The provided max fee per gas is too low based on the current network rate.
    #[display("maxFeePerGas is {0} but must be at least {1}, which is based on the current block base fee")]
    MaxFeePerGasTooLow(U256, U256),
    /// The provided max priority fee per gas is too low based on the current network rate.
    #[display("maxPriorityFeePerGas is {0} but must be at least {1}")]
    MaxPriorityFeePerGasTooLow(U256, U256),
    /// The call gas limit is too low to account for any possible call.
    #[display("callGasLimit is {0} but must be at least {1}")]
    CallGasLimitTooLow(U256, U256),
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethers::types::Bytes;
    use rundler_provider::{MockEntryPoint, MockProvider};

    use super::*;

    fn create_base_config() -> (MockProvider, MockEntryPoint) {
        (MockProvider::new(), MockEntryPoint::new())
    }

    fn get_test_async_data() -> AsyncData {
        AsyncData {
            factory_exists: true,
            sender_exists: true,
            paymaster_exists: true,
            payer_funds: 5_000_000.into(),
            bundle_fees: GasFees {
                max_fee_per_gas: 5_000.into(),
                max_priority_fee_per_gas: 1_000.into(),
            },
            min_pre_verification_gas: 1_000.into(),
        }
    }

    #[tokio::test]
    async fn test_check_init_code() {
        let (provider, entry_point) = create_base_config();
        let prechecker = PrecheckerImpl::new(Arc::new(provider), entry_point, Settings::default());
        let op = UserOperation {
            sender: Address::from_str("0x3f8a2b6c4d5e1079286fa1b3c0d4e5f6902b7c8d").unwrap(),
            nonce: 100.into(),
            init_code: Bytes::from_str("0x1000").unwrap(),
            call_data: Bytes::default(),
            call_gas_limit: 9_000.into(), // large call gas limit high to trigger TotalGasLimitTooHigh
            verification_gas_limit: 10_000_000.into(),
            pre_verification_gas: 0.into(),
            max_fee_per_gas: 5_000.into(),
            max_priority_fee_per_gas: 2_000.into(),
            paymaster_and_data: Bytes::default(),
            signature: Bytes::default(),
        };

        let res = prechecker.check_init_code(&op, get_test_async_data());
        assert_eq!(
            res,
            ArrayVec::<PrecheckViolation, 2>::from([
                PrecheckViolation::InitCodeTooShort(2),
                PrecheckViolation::ExistingSenderWithInitCode(
                    Address::from_str("0x3f8a2b6c4d5e1079286fa1b3c0d4e5f6902b7c8d").unwrap()
                )
            ])
        );
    }

    #[tokio::test]
    async fn test_check_gas() {
        let (provider, entry_point) = create_base_config();
        let test_settings = Settings {
            chain_id: 1,
            max_verification_gas: 5_000_000.into(),
            max_total_execution_gas: 10_000_000.into(),
            use_bundle_priority_fee: None,
            bundle_priority_fee_overhead_percent: 0,
            priority_fee_mode: gas::PriorityFeeMode::BaseFeePercent(100),
        };
        let prechecker = PrecheckerImpl::new(Arc::new(provider), entry_point, test_settings);
        let op = UserOperation {
            sender: Address::from_str("0x3f8a2b6c4d5e1079286fa1b3c0d4e5f6902b7c8d").unwrap(),
            nonce: 100.into(),
            init_code: Bytes::from_str("0x1000000000000000000000000000000000000000").unwrap(),
            call_data: Bytes::default(),
            call_gas_limit: 9_000.into(), // large call gas limit high to trigger TotalGasLimitTooHigh
            verification_gas_limit: 10_000_000.into(),
            pre_verification_gas: 0.into(),
            max_fee_per_gas: 5_000.into(),
            max_priority_fee_per_gas: 2_000.into(),
            paymaster_and_data: Bytes::default(),
            signature: Bytes::default(),
        };

        let res = prechecker.check_gas(&op, get_test_async_data());

        assert_eq!(
            res,
            ArrayVec::<PrecheckViolation, 6>::from([
                PrecheckViolation::VerificationGasLimitTooHigh(10_000_000.into(), 5_000_000.into(),),
                PrecheckViolation::TotalGasLimitTooHigh(20_009_000.into(), 10_000_000.into(),),
                PrecheckViolation::PreVerificationGasTooLow(0.into(), 1_000.into(),),
                PrecheckViolation::MaxFeePerGasTooLow(5_000.into(), 8_000.into(),),
                PrecheckViolation::MaxPriorityFeePerGasTooLow(2_000.into(), 4_000.into(),),
                PrecheckViolation::CallGasLimitTooLow(9_000.into(), 9_100.into(),),
            ])
        );
    }

    #[tokio::test]
    async fn test_check_payer_paymaster_deposit_too_low() {
        let (provider, entry_point) = create_base_config();
        let prechecker = PrecheckerImpl::new(Arc::new(provider), entry_point, Settings::default());
        let op = UserOperation {
            sender: Address::from_str("0x3f8a2b6c4d5e1079286fa1b3c0d4e5f6902b7c8d").unwrap(),
            nonce: 100.into(),
            init_code: Bytes::default(),
            call_data: Bytes::default(),
            call_gas_limit: 500_000.into(),
            verification_gas_limit: 500_000.into(),
            pre_verification_gas: 0.into(),
            max_fee_per_gas: 1_000.into(),
            max_priority_fee_per_gas: 0.into(),
            paymaster_and_data: Bytes::from_str(
                "0xa4b2c8f0351d60729e4f0a12345678d9b1c3e5f27890abcdef123456780abcdef1",
            )
            .unwrap(),
            signature: Bytes::default(),
        };

        let res = prechecker.check_payer(&op, get_test_async_data());
        assert_eq!(
            res,
            Some(PrecheckViolation::PaymasterDepositTooLow(
                5_000_000.into(),
                2_000_000_000.into(),
            ))
        );
    }
}
