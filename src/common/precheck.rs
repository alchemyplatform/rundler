use std::sync::Arc;

use anyhow::Context;
use arrayvec::ArrayVec;
use ethers::types::{Address, U256};
use tonic::async_trait;

use super::{
    gas::GasFees,
    types::{EntryPointLike, ProviderLike},
};
use crate::common::{
    gas,
    types::{UserOperation, ViolationError},
};

/// The min cost of a `CALL` with nonzero value, as required by the spec.
pub const MIN_CALL_GAS_LIMIT: U256 = U256([9100, 0, 0, 0]);

#[async_trait]
pub trait Prechecker {
    async fn check(&self, op: &UserOperation) -> Result<(), PrecheckError>;
}

pub type PrecheckError = ViolationError<PrecheckViolation>;

#[derive(Debug)]
pub struct PrecheckerImpl<P: ProviderLike, E: EntryPointLike> {
    provider: Arc<P>,
    chain_id: u64,
    entry_point: E,
    settings: Settings,
    fee_estimator: gas::FeeEstimator<P>,
}

#[derive(Copy, Clone, Debug)]
pub struct Settings {
    pub max_verification_gas: U256,
    pub use_bundle_priority_fee: Option<bool>,
    pub bundle_priority_fee_overhead_percent: u64,
    pub priority_fee_mode: gas::PriorityFeeMode,
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

#[async_trait]
impl<P: ProviderLike, E: EntryPointLike> Prechecker for PrecheckerImpl<P, E> {
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

impl<P: ProviderLike, E: EntryPointLike> PrecheckerImpl<P, E> {
    pub fn new(provider: Arc<P>, chain_id: u64, entry_point: E, settings: Settings) -> Self {
        Self {
            provider: provider.clone(),
            chain_id,
            entry_point,
            settings,
            fee_estimator: gas::FeeEstimator::new(
                provider,
                chain_id,
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
    ) -> ArrayVec<PrecheckViolation, 5> {
        let Settings {
            max_verification_gas,
            ..
        } = self.settings;
        let AsyncData {
            bundle_fees,
            min_pre_verification_gas,
            ..
        } = async_data;

        let mut violations = ArrayVec::new();
        if op.verification_gas_limit > max_verification_gas {
            violations.push(PrecheckViolation::VerificationGasTooHigh(
                op.verification_gas_limit,
                max_verification_gas,
            ));
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
        let max_gas_cost = op.max_gas_cost();
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
            .balance_of(payer)
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
            op.clone(),
            op,
            self.entry_point.address(),
            self.provider.clone(),
            self.chain_id,
        )
        .await
        .context("should calculate pre-verification gas")
    }
}

#[derive(Clone, Debug, parse_display::Display, Eq, PartialEq)]
pub enum PrecheckViolation {
    #[display("initCode must start with a 20-byte factory address, but was only {0} bytes")]
    InitCodeTooShort(usize),
    #[display("sender {0:?} is not a contract and initCode is empty")]
    SenderIsNotContractAndNoInitCode(Address),
    #[display("sender {0:?} is an existing contract, but initCode is nonempty")]
    ExistingSenderWithInitCode(Address),
    #[display("initCode indicates factory with no code: {0:?}")]
    FactoryIsNotContract(Address),
    #[display("verificationGasLimit is {0} but must be at most {1}")]
    VerificationGasTooHigh(U256, U256),
    #[display("preVerificationGas is {0} but must be at least {1}")]
    PreVerificationGasTooLow(U256, U256),
    #[display("paymasterAndData must start a 20-byte paymaster address, but was only {0} bytes")]
    PaymasterTooShort(usize),
    #[display("paymasterAndData indicates paymaster with no code: {0:?}")]
    PaymasterIsNotContract(Address),
    #[display("paymaster deposit is {0} but must be at least {1} to pay for this operation")]
    PaymasterDepositTooLow(U256, U256),
    #[display("sender balance and deposit together is {0} but must be at least {1} to pay for this operation")]
    SenderFundsTooLow(U256, U256),
    #[display("maxFeePerGas is {0} but must be at least {1}, which is based on the current block base fee")]
    MaxFeePerGasTooLow(U256, U256),
    #[display("maxPriorityFeePerGas is {0} but must be at least {1}")]
    MaxPriorityFeePerGasTooLow(U256, U256),
    #[display("callGasLimit is {0} but must be at least {1}")]
    CallGasLimitTooLow(U256, U256),
}
