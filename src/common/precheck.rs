use std::sync::Arc;

use anyhow::Context;
use arrayvec::ArrayVec;
use ethers::{
    providers::Middleware,
    types::{Address, BlockNumber, U256},
};
use tonic::async_trait;

use crate::common::{
    contracts::i_entry_point::IEntryPoint,
    gas,
    types::{UserOperation, ViolationError},
};

/// The min cost of a `CALL` with nonzero value, as required by the spec.
const MIN_CALL_GAS_LIMIT: U256 = U256([9000, 0, 0, 0]);

#[async_trait]
pub trait Prechecker {
    async fn check(&self, op: &UserOperation) -> Result<(), PrecheckError>;
}

pub type PrecheckError = ViolationError<PrecheckViolation>;

#[derive(Debug)]
pub struct PrecheckerImpl<M>
where
    M: Middleware + 'static,
    M::Error: 'static,
{
    provider: Arc<M>,
    entry_point: IEntryPoint<M>,
    settings: Settings,
}

#[derive(Copy, Clone, Debug)]
pub struct Settings {
    pub min_priority_fee_per_gas: U256,
    pub max_verification_gas: U256,
}

#[derive(Copy, Clone, Debug)]
struct AsyncData {
    factory_exists: bool,
    sender_exists: bool,
    paymaster_exists: bool,
    payer_funds: U256,
    base_fee: U256,
}

#[async_trait]
impl<M> Prechecker for PrecheckerImpl<M>
where
    M: Middleware + 'static,
    M::Error: 'static,
{
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

impl<M> PrecheckerImpl<M>
where
    M: Middleware + 'static,
    M::Error: 'static,
{
    pub fn new(provider: Arc<M>, entry_point_address: Address, settings: Settings) -> Self {
        let entry_point = IEntryPoint::new(entry_point_address, Arc::clone(&provider));
        Self {
            provider,
            entry_point,
            settings,
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
            min_priority_fee_per_gas,
            max_verification_gas,
        } = self.settings;
        let AsyncData { base_fee, .. } = async_data;
        let mut violations = ArrayVec::new();
        if op.verification_gas_limit > max_verification_gas {
            violations.push(PrecheckViolation::VerificationGasTooHigh(
                op.verification_gas_limit,
                max_verification_gas,
            ));
        }
        let min_pre_verification_gas = gas::calc_pre_verification_gas(op);
        if op.pre_verification_gas < min_pre_verification_gas {
            violations.push(PrecheckViolation::PreVerificationGasTooLow(
                op.pre_verification_gas,
                min_pre_verification_gas,
            ));
        }
        // The entry point calculates the user's fee per gas as
        // min(maxFeePerGas, maxPriorityFeePerGas + block.basefee), so we need
        // each term to be at least the current base fee plus the amount we want
        // as tip.
        let min_max_fee_per_gas = base_fee + min_priority_fee_per_gas;
        if op.max_fee_per_gas < min_max_fee_per_gas {
            violations.push(PrecheckViolation::MaxFeePerGasTooLow(
                op.max_fee_per_gas,
                min_max_fee_per_gas,
            ));
        }
        if op.max_priority_fee_per_gas < min_priority_fee_per_gas {
            violations.push(PrecheckViolation::MaxPriorityFeePerGasTooLow(
                op.max_priority_fee_per_gas,
                min_priority_fee_per_gas,
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
            base_fee,
            ..
        } = async_data;
        if !op.paymaster_and_data.is_empty() {
            let Some(paymaster) = op.paymaster() else {
                return Some(PrecheckViolation::PaymasterTooShort(op.paymaster_and_data.len()));
            };
            if !paymaster_exists {
                return Some(PrecheckViolation::PaymasterIsNotContract(paymaster));
            }
        }
        let max_gas_cost = max_gas_cost_for_op(op, base_fee);
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
        let (factory_exists, sender_exists, paymaster_exists, payer_funds, base_fee) = tokio::try_join!(
            self.is_contract(op.factory()),
            self.is_contract(Some(op.sender)),
            self.is_contract(op.paymaster()),
            self.get_payer_funds(op),
            self.get_base_fee(),
        )?;
        Ok(AsyncData {
            factory_exists,
            sender_exists,
            paymaster_exists,
            payer_funds,
            base_fee,
        })
    }

    async fn is_contract(&self, address: Option<Address>) -> anyhow::Result<bool> {
        let Some(address) = address else {
            return Ok(false)
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
            .call()
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

    async fn get_base_fee(&self) -> anyhow::Result<U256> {
        self.provider
            .get_block(BlockNumber::Latest)
            .await
            .context("should load latest block to get base fee")?
            .context("latest block should exist")?
            .base_fee_per_gas
            .context("latest block should have a nonempty base fee")
    }
}

fn max_gas_cost_for_op(op: &UserOperation, base_fee: U256) -> U256 {
    let max_gas = op.call_gas_limit + op.verification_gas_limit + op.pre_verification_gas;
    let fee_per_gas = op
        .max_fee_per_gas
        .min(op.max_priority_fee_per_gas + base_fee);
    max_gas * fee_per_gas
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
