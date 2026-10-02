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

//! Builds v0.7 user operations for the probe fixtures, submits them in a `handleOps`
//! bundle from the harness EOA (acting as the bundler), and measures the unmetered gas.
//!
//! # Measurement
//!
//! Every op is sent with `preVerificationGas = 0`, `callGasLimit = 0` and non-empty
//! `callData`. The EntryPoint still ABI-encodes and copies the callData for the inner call,
//! and the account call then fails immediately for lack of gas. With `callGasLimit = 0`
//! (and a `paymasterPostOpGasLimit` no larger than the execution gas used) the v0.7
//! unused-gas penalty is zero, so `UserOperationEvent.actualGasUsed` is exactly the gas the
//! EntryPoint metered for the op. The unmetered gas of the bundle, which PVG must cover, is
//!
//! ```text
//! unmetered = receipt.gasUsed - Σ actualGasUsed
//! ```

use std::collections::BTreeMap;

use alloy_eips::eip7702::SignedAuthorization;
use alloy_network::{TransactionBuilder, TransactionBuilder7702};
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{SolCall, SolEvent};
use anyhow::{Context, bail};
use rundler_contracts::v0_7::{IEntryPoint, PackedUserOperation};
use rundler_types::{
    AuthorityState, EntryPointVersion, PvgState, UserOperation as _,
    authorization::Eip7702Auth,
    chain::ChainSpec,
    v0_7::{UserOperation, UserOperationBuilder, UserOperationRequiredFields},
};
use serde::Serialize;

use crate::{
    contracts::{ProbeFactory, ProbePaymaster},
    fixtures::{self, Fixtures},
    harness::{Harness, TxOutcome},
};

/// Verification gas limit for an op on an already-deployed account. A consumption check
/// (AA26), so a generous value costs nothing but prefund.
const VERIFICATION_GAS_LIMIT: u128 = 300_000;
/// Verification gas limit for an op that deploys its account. Sized for EIP-8037 state-gas
/// (new account + code deposit at 1,530 gas per byte).
const VERIFICATION_GAS_LIMIT_DEPLOY: u128 = 2_000_000;
/// Paymaster verification gas limit (consumption check, AA36).
const PAYMASTER_VERIFICATION_GAS_LIMIT: u128 = 100_000;
/// Default `paymasterPostOpGasLimit` for [`Payer::PaymasterPostOp`]. Must be enough for
/// `ProbePaymaster.postOp` and no more than the execution gas used, or the penalty applies.
pub const DEFAULT_POST_OP_GAS_LIMIT: u128 = 10_000;
/// `verification_gas_limit_efficiency_reject_threshold` used for the floor-aware prediction
/// (rundler's CLI default).
const VERIFICATION_EFFICIENCY_THRESHOLD: f64 = 0.0;
/// Priority fee of every op, in wei. Op fees only scale prefund and payment, not gas.
const OP_PRIORITY_FEE: u128 = 1_000;

/// Who pays for an op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Payer {
    /// Account has no EntryPoint deposit and pays `missingAccountFunds` in validateUserOp,
    /// so its deposit goes 0 -> prefund -> 0 in validation and the refund writes it again
    /// after the EntryPoint stops metering (the standard LightAccount self-pay path).
    SelfZeroDeposit,
    /// Account deposit covers the prefund, so `missingAccountFunds` is 0.
    SelfPrefunded,
    /// Paymaster without context, so postOp is not called.
    Paymaster,
    /// Paymaster with context, so postOp is called.
    PaymasterPostOp,
}

/// Where the bundle's compensation goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BeneficiaryKind {
    /// The bundler EOA itself (rundler's usual configuration).
    Bundler,
    /// An account that already exists and is not otherwise touched by the bundle.
    Existing,
    /// An address that has never been used.
    Fresh,
}

/// The sender of an op.
#[derive(Debug, Clone)]
pub enum Sender {
    /// A new `ProbeAccount` with a random salt, deployed and funded as its payer requires.
    NewProbe,
    /// An account the experiment prepared itself (deployed and funded, or an EIP-7702
    /// delegated EOA). No setup is performed for it.
    Prepared(Address),
}

#[derive(Debug, Clone)]
pub struct OpSpec {
    pub payer: Payer,
    pub sender: Sender,
    pub nonce: U256,
    /// Deploy the account through `initCode` in this op (vs. already deployed). Only for
    /// [`Sender::NewProbe`].
    pub deploy_in_op: bool,
    pub call_data: Bytes,
    pub signature: Bytes,
    pub post_op_gas_limit: u128,
    /// Use this paymaster instead of the fixture one (paymaster payers only).
    pub paymaster: Option<Address>,
    /// Use this paymasterData instead of the payer's default (paymaster payers only).
    pub paymaster_data: Option<Bytes>,
    /// EIP-7702 authorization to include in the bundle transaction for this op's sender.
    pub authorization: Option<SignedAuthorization>,
    /// Pin `maxFeePerGas` (otherwise `2 * baseFee + priority`), e.g. to size a deposit to
    /// exactly the prefund.
    pub max_fee: Option<u128>,
}

impl OpSpec {
    /// An op shaped like typical traffic: `execute(address,uint256,bytes)` callData with empty
    /// inner data, and a 65-byte ECDSA-sized signature.
    pub fn typical(payer: Payer, deploy_in_op: bool) -> Self {
        Self {
            payer,
            sender: Sender::NewProbe,
            nonce: U256::ZERO,
            deploy_in_op,
            call_data: typical_call_data(),
            signature: pseudo_random_bytes(65),
            post_op_gas_limit: DEFAULT_POST_OP_GAS_LIMIT,
            paymaster: None,
            paymaster_data: None,
            authorization: None,
            max_fee: None,
        }
    }

    /// The same op sent by an account the experiment prepared.
    pub fn with_sender(mut self, sender: Address, nonce: u64) -> Self {
        self.sender = Sender::Prepared(sender);
        self.nonce = U256::from(nonce);
        self
    }

    /// The prefund the EntryPoint requires for this op at `max_fee`
    /// (`callGasLimit` and `preVerificationGas` are 0).
    pub fn prefund(&self, max_fee: u128) -> U256 {
        let mut gas = if self.deploy_in_op {
            VERIFICATION_GAS_LIMIT_DEPLOY
        } else {
            VERIFICATION_GAS_LIMIT
        };
        match self.payer {
            Payer::Paymaster => gas += PAYMASTER_VERIFICATION_GAS_LIMIT,
            Payer::PaymasterPostOp => {
                gas += PAYMASTER_VERIFICATION_GAS_LIMIT + self.post_op_gas_limit
            }
            Payer::SelfZeroDeposit | Payer::SelfPrefunded => {}
        }
        U256::from(gas * max_fee)
    }
}

/// A signature in `ProbeAccount`'s scratch-action layout: `action | key | scratch`.
/// Action 0 does nothing, 1 sets the Scratch slot, 2 clears it. All three have the same length.
pub fn scratch_signature(action: u8, key: B256, scratch: Address) -> Bytes {
    let mut sig = vec![action];
    sig.extend_from_slice(key.as_slice());
    sig.extend_from_slice(scratch.as_slice());
    sig.into()
}

/// `execute(0x1111…, 0, "")` as LightAccount/SimpleAccount encode it: 132 bytes.
pub fn typical_call_data() -> Bytes {
    let mut data = vec![0xb6, 0x1d, 0x27, 0xf6];
    let mut dest = [0u8; 32];
    dest[12..].fill(0x11);
    data.extend_from_slice(&dest);
    data.extend_from_slice(&[0u8; 32]); // value
    let mut offset = [0u8; 32];
    offset[31] = 0x60;
    data.extend_from_slice(&offset);
    data.extend_from_slice(&[0u8; 32]); // length 0
    data.into()
}

/// Deterministic bytes that are all non-zero, standing in for signatures and other
/// high-entropy data.
pub fn pseudo_random_bytes(len: usize) -> Bytes {
    (0..len)
        .map(|i| ((i * 37 + 11) % 255 + 1) as u8)
        .collect::<Vec<_>>()
        .into()
}

/// Calldata composition of the bundle transaction and whether the calldata floor bound it.
#[derive(Debug, Clone, Serialize)]
pub struct FloorInfo {
    pub calldata_len: usize,
    pub zero_bytes: usize,
    pub non_zero_bytes: usize,
    /// EIP-7623 tokens: `zero + 4 * non_zero`.
    pub tokens: u64,
    /// `bundle_intrinsic_gas + floor gas per byte * bytes`, using the prediction ChainSpec.
    pub floor_gas: u64,
    /// `receipt.gasUsed == floor_gas`: the transaction paid the floor, not its execution.
    pub floor_bound: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpResult {
    pub sender: Address,
    pub nonce: U256,
    pub has_authorization: bool,
    pub payer: Payer,
    pub deploy_in_op: bool,
    pub call_data_len: usize,
    pub signature_len: usize,
    pub packed_abi_size: usize,
    pub success: bool,
    /// Rundler's `authorization_gas_limit` for this op (included in the predictions).
    pub predicted_authorization_gas: u128,
    /// State the op was priced with, read just before the bundle was sent
    pub pvg_state: PvgState,
    /// Rundler's `state_pre_verification_gas` for this op (included in the predictions)
    pub predicted_state_gas: u128,
    /// Gas the EntryPoint metered for this op (PVG is 0, penalty is 0).
    pub actual_gas_used: u128,
    pub actual_gas_cost: U256,
    /// `actualGasCost` passed to postOp (pre-penalty, before the post-postOp tail).
    pub post_op_actual_gas_cost: Option<U256>,
    /// Rundler's `static_pre_verification_gas` for this op.
    pub predicted_static_pvg: u128,
    /// Rundler's required PVG at this bundle size without the calldata floor (static + shared +
    /// state gas). This is what gas estimation returns.
    pub predicted_execution_pvg: u128,
    /// Rundler's `required_pre_verification_gas` at this bundle size with the EIP-7623 floor
    /// top-up, as the mempool precheck and the bundle builder require it.
    pub predicted_required_pvg: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleRun {
    pub label: String,
    pub n: usize,
    pub beneficiary: BeneficiaryKind,
    pub beneficiary_address: Address,
    pub tx: TxOutcome,
    pub ops: Vec<OpResult>,
    pub sum_actual_gas_used: u128,
    /// `receipt.gasUsed - Σ actualGasUsed`: what PVG has to cover for this bundle.
    pub unmetered_gas: i128,
    /// Σ rundler-predicted PVG over the ops at this bundle size.
    pub predicted_pvg_total: u128,
    /// Positive: rundler would overcharge; negative: the bundler loses this much gas.
    pub predicted_minus_unmetered: i128,
    /// Σ floor-aware required PVG over the ops.
    pub predicted_required_pvg_total: u128,
    /// As `predicted_minus_unmetered`, against the floor-aware requirement.
    pub predicted_required_minus_unmetered: i128,
    pub floor: FloorInfo,
}

/// Builds, funds, submits and measures one bundle.
pub struct BundleRunner<'a> {
    pub harness: &'a Harness,
    pub fixtures: &'a Fixtures,
    /// ChainSpec whose PVG formula is being checked.
    pub spec: &'a ChainSpec,
}

struct PreparedOp {
    spec: OpSpec,
    uo: UserOperation,
    packed: PackedUserOperation,
}

impl BundleRunner<'_> {
    pub async fn run(
        &self,
        label: impl Into<String>,
        specs: &[OpSpec],
        beneficiary: BeneficiaryKind,
    ) -> anyhow::Result<BundleRun> {
        let label = label.into();
        let n = specs.len();
        let ops = self.prepare(specs).await?;
        let mut pvg_states = Vec::with_capacity(ops.len());
        for op in &ops {
            pvg_states.push(self.pvg_state(&op.uo).await?);
        }
        let beneficiary_address = self.beneficiary_address(beneficiary).await?;

        let input: Bytes = IEntryPoint::handleOpsCall {
            ops: ops.iter().map(|op| op.packed.clone()).collect(),
            beneficiary: beneficiary_address,
        }
        .abi_encode()
        .into();
        let floor_input = input.clone();
        let mut request = TransactionRequest::default()
            .with_to(self.fixtures.entry_point)
            .with_input(input);
        let authorizations: Vec<SignedAuthorization> = specs
            .iter()
            .filter_map(|s| s.authorization.clone())
            .collect();
        if !authorizations.is_empty() {
            request = request.with_authorization_list(authorizations);
        }
        let mut tx = self
            .harness
            .send(request)
            .await
            .with_context(|| format!("bundle {label} (n={n})"))?;
        if !tx.success {
            bail!("bundle {label} (n={n}) reverted: {}", tx.tx_hash);
        }

        let paymasters: Vec<Address> = ops.iter().filter_map(|op| op.uo.paymaster()).collect();
        let (events, post_ops) = self.decode_logs(&tx, &paymasters)?;
        let mut post_ops = post_ops.into_iter();
        let mut results = Vec::with_capacity(n);
        for (op, pvg_state) in ops.iter().zip(&pvg_states) {
            let sender = op.uo.sender();
            let nonce = op.uo.nonce();
            let event = events
                .get(&(sender, nonce))
                .with_context(|| format!("no UserOperationEvent for {sender} nonce {nonce}"))?;
            let post_op_actual_gas_cost = (op.spec.payer == Payer::PaymasterPostOp)
                .then(|| post_ops.next())
                .flatten();
            results.push(OpResult {
                sender,
                nonce,
                has_authorization: op.spec.authorization.is_some(),
                predicted_authorization_gas: op.uo.authorization_gas_limit(self.spec),
                pvg_state: *pvg_state,
                predicted_state_gas: op.uo.state_pre_verification_gas(self.spec, pvg_state),
                payer: op.spec.payer,
                deploy_in_op: op.spec.deploy_in_op,
                call_data_len: op.spec.call_data.len(),
                signature_len: op.spec.signature.len(),
                packed_abi_size: op.uo.abi_encoded_size(),
                success: event.success,
                actual_gas_used: event.actualGasUsed.to::<u128>(),
                actual_gas_cost: event.actualGasCost,
                post_op_actual_gas_cost,
                predicted_static_pvg: op.uo.static_pre_verification_gas(self.spec),
                predicted_execution_pvg: op
                    .uo
                    .required_pre_verification_gas(self.spec, n, 0, None, pvg_state),
                predicted_required_pvg: op.uo.required_pre_verification_gas(
                    self.spec,
                    n,
                    0,
                    Some(VERIFICATION_EFFICIENCY_THRESHOLD),
                    pvg_state,
                ),
            });
        }

        if beneficiary == BeneficiaryKind::Bundler {
            tx.account_for_inflow(results.iter().map(|r| r.actual_gas_cost).sum());
        }
        let sum_actual_gas_used: u128 = results.iter().map(|r| r.actual_gas_used).sum();
        let predicted_pvg_total: u128 = results.iter().map(|r| r.predicted_execution_pvg).sum();
        let predicted_required_pvg_total: u128 =
            results.iter().map(|r| r.predicted_required_pvg).sum();
        let unmetered_gas = tx.gas_used as i128 - sum_actual_gas_used as i128;
        let floor = self.floor_info(&floor_input, tx.gas_used);

        eprintln!(
            "{label:<40} n={n} gas_used={:>8} metered={sum_actual_gas_used:>8} unmetered={unmetered_gas:>7} predicted={predicted_pvg_total:>7} diff={:>6}{}",
            tx.gas_used,
            predicted_pvg_total as i128 - unmetered_gas,
            if floor.floor_bound {
                format!(
                    " FLOOR (floor-aware diff={})",
                    predicted_required_pvg_total as i128 - unmetered_gas
                )
            } else {
                String::new()
            },
        );

        Ok(BundleRun {
            label,
            n,
            beneficiary,
            beneficiary_address,
            tx,
            ops: results,
            sum_actual_gas_used,
            unmetered_gas,
            predicted_pvg_total,
            predicted_minus_unmetered: predicted_pvg_total as i128 - unmetered_gas,
            predicted_required_pvg_total,
            predicted_required_minus_unmetered: predicted_required_pvg_total as i128
                - unmetered_gas,
            floor,
        })
    }

    /// Builds the ops with fresh senders and funds/deploys them as their payer requires,
    /// batching the preparation into one `ProbeFactory.setup` transaction per group.
    async fn prepare(&self, specs: &[OpSpec]) -> anyhow::Result<Vec<PreparedOp>> {
        let default_max_fee = self.default_max_fee().await?;

        let mut groups: BTreeMap<(bool, U256, U256), Vec<U256>> = BTreeMap::new();
        let mut ops = Vec::with_capacity(specs.len());
        for spec in specs {
            let max_fee = spec.max_fee.unwrap_or(default_max_fee);
            let salt = U256::from_be_bytes(rand_bytes32());
            let (sender, new_probe) = match spec.sender {
                Sender::NewProbe => (self.fixtures.account_address(salt), true),
                Sender::Prepared(address) => {
                    if spec.deploy_in_op {
                        bail!("deploy_in_op requires Sender::NewProbe");
                    }
                    (address, false)
                }
            };
            let vgl = if spec.deploy_in_op {
                VERIFICATION_GAS_LIMIT_DEPLOY
            } else {
                VERIFICATION_GAS_LIMIT
            };

            let mut builder = UserOperationBuilder::new(
                self.spec,
                EntryPointVersion::V0_7,
                UserOperationRequiredFields {
                    sender,
                    nonce: spec.nonce,
                    call_data: spec.call_data.clone(),
                    call_gas_limit: 0,
                    verification_gas_limit: vgl,
                    pre_verification_gas: 0,
                    max_priority_fee_per_gas: OP_PRIORITY_FEE,
                    max_fee_per_gas: max_fee,
                    signature: spec.signature.clone(),
                },
            );
            if spec.deploy_in_op {
                builder = builder.factory(self.fixtures.factory, Fixtures::factory_data(salt));
            }
            let paymaster = spec.paymaster.unwrap_or(self.fixtures.paymaster);
            builder = match spec.payer {
                Payer::Paymaster => builder.paymaster(
                    paymaster,
                    PAYMASTER_VERIFICATION_GAS_LIMIT,
                    0,
                    spec.paymaster_data.clone().unwrap_or_default(),
                ),
                Payer::PaymasterPostOp => builder.paymaster(
                    paymaster,
                    PAYMASTER_VERIFICATION_GAS_LIMIT,
                    spec.post_op_gas_limit,
                    spec.paymaster_data
                        .clone()
                        .unwrap_or(Bytes::from_static(&[0x01])),
                ),
                Payer::SelfZeroDeposit | Payer::SelfPrefunded => builder,
            };
            if let Some(auth) = &spec.authorization {
                builder = builder.authorization_tuple(Eip7702Auth::from(auth.clone()));
            }
            let uo = builder.build();

            let prefund = U256::from(uo.total_gas_limit() * max_fee);
            debug_assert_eq!(prefund, spec.prefund(max_fee));
            let (account_value, deposit_value) = match spec.payer {
                // Exactly the prefund: the account pays it all as missingAccountFunds.
                Payer::SelfZeroDeposit => (prefund, U256::ZERO),
                Payer::SelfPrefunded => (U256::ZERO, prefund * U256::from(2)),
                Payer::Paymaster | Payer::PaymasterPostOp => (U256::ZERO, U256::ZERO),
            };
            let predeploy = !spec.deploy_in_op;
            if new_probe && (predeploy || account_value > U256::ZERO || deposit_value > U256::ZERO)
            {
                groups
                    .entry((predeploy, account_value, deposit_value))
                    .or_default()
                    .push(salt);
            }

            let packed = uo.clone().pack();
            ops.push(PreparedOp {
                spec: spec.clone(),
                uo,
                packed,
            });
        }

        for ((predeploy, account_value, deposit_value), salts) in groups {
            self.setup_probes(salts, predeploy, account_value, deposit_value)
                .await?;
        }

        // The fixture paymaster must cover every prefund in the bundle (AA31 otherwise). Top it
        // up to twice the bundle's total when short; experiments size custom paymasters
        // themselves.
        let fixture_prefunds: U256 = ops
            .iter()
            .filter(|op| op.uo.paymaster() == Some(self.fixtures.paymaster))
            .map(|op| U256::from(op.uo.total_gas_limit() * op.uo.max_fee_per_gas()))
            .sum();
        if fixture_prefunds > U256::ZERO {
            let ep = self.fixtures.entry_point;
            let paymaster = self.fixtures.paymaster;
            let deposit = fixtures::deposit_of(self.harness, ep, paymaster).await?;
            if deposit < fixture_prefunds {
                let target = fixture_prefunds * U256::from(2);
                fixtures::deposit_to(self.harness, ep, paymaster, target - deposit).await?;
            }
        }
        Ok(ops)
    }

    /// Reads the state rundler prices the op with, the same way `rundler_sim::gas::load_pvg_state`
    /// does: the sender's EntryPoint deposit without a paymaster, and the authority account for
    /// an op with an authorization.
    async fn pvg_state(&self, uo: &UserOperation) -> anyhow::Result<PvgState> {
        let sender = uo.sender();
        let sender_deposit_is_zero = if uo.paymaster().is_none() {
            let deposit =
                fixtures::deposit_of(self.harness, self.fixtures.entry_point, sender).await?;
            Some(deposit.is_zero())
        } else {
            None
        };
        let authority = if uo.authorization_tuple().is_some() {
            let provider = &self.harness.provider;
            let code = provider.get_code_at(sender).await?;
            let nonce = provider.get_transaction_count(sender).await?;
            let balance = provider.get_balance(sender).await?;
            Some(AuthorityState::from_account(&code, nonce, balance))
        } else {
            None
        };
        Ok(PvgState {
            sender_deposit_is_zero,
            authority,
        })
    }

    /// `maxFeePerGas` ops get when their spec does not pin one.
    pub async fn default_max_fee(&self) -> anyhow::Result<u128> {
        let base_fee = self
            .harness
            .provider
            .get_block(alloy_rpc_types_eth::BlockId::latest())
            .await?
            .and_then(|b| b.header.base_fee_per_gas)
            .unwrap_or(1) as u128;
        Ok(base_fee * 2 + OP_PRIORITY_FEE)
    }

    /// Deploys (if `predeploy`) and funds the `ProbeAccount`s with these salts in one
    /// transaction: `account_value` wei to each account and `deposit_value` wei to each
    /// account's EntryPoint deposit.
    pub async fn setup_probes(
        &self,
        salts: Vec<U256>,
        predeploy: bool,
        account_value: U256,
        deposit_value: U256,
    ) -> anyhow::Result<()> {
        let total = (account_value + deposit_value) * U256::from(salts.len());
        let outcome = self
            .harness
            .send(
                TransactionRequest::default()
                    .with_to(self.fixtures.factory)
                    .with_value(total)
                    .with_input(
                        ProbeFactory::setupCall {
                            salts,
                            predeploy,
                            accountValue: account_value,
                            depositValue: deposit_value,
                        }
                        .abi_encode(),
                    ),
            )
            .await
            .context("setup transaction")?;
        if !outcome.success {
            bail!("setup transaction reverted: {}", outcome.tx_hash);
        }
        Ok(())
    }

    async fn beneficiary_address(&self, kind: BeneficiaryKind) -> anyhow::Result<Address> {
        Ok(match kind {
            BeneficiaryKind::Bundler => self.harness.sender,
            BeneficiaryKind::Fresh => Address::random(),
            BeneficiaryKind::Existing => {
                let addr = Address::random();
                let outcome = self
                    .harness
                    .send(
                        TransactionRequest::default()
                            .with_to(addr)
                            .with_value(U256::from(1)),
                    )
                    .await?;
                if !outcome.success {
                    bail!("failed to create beneficiary account {addr}");
                }
                addr
            }
        })
    }

    /// UserOperationEvents by (sender, nonce), and ProbePostOp `actualGasCost`s emitted by
    /// any of `paymasters`, in execution order.
    #[allow(clippy::type_complexity)]
    fn decode_logs(
        &self,
        tx: &TxOutcome,
        paymasters: &[Address],
    ) -> anyhow::Result<(
        BTreeMap<(Address, U256), IEntryPoint::UserOperationEvent>,
        Vec<U256>,
    )> {
        let mut events = BTreeMap::new();
        let mut post_ops = Vec::new();
        for log in &tx.logs {
            let topic0 = log.topic0().copied();
            if log.address() == self.fixtures.entry_point
                && topic0 == Some(IEntryPoint::UserOperationEvent::SIGNATURE_HASH)
            {
                let ev = log
                    .log_decode::<IEntryPoint::UserOperationEvent>()?
                    .inner
                    .data;
                events.insert((ev.sender, ev.nonce), ev);
            } else if paymasters.contains(&log.address())
                && topic0 == Some(ProbePaymaster::ProbePostOp::SIGNATURE_HASH)
            {
                let ev = log.log_decode::<ProbePaymaster::ProbePostOp>()?.inner.data;
                post_ops.push(ev.actualGasCost);
            }
        }
        Ok((events, post_ops))
    }

    fn floor_info(&self, input: &Bytes, gas_used: u64) -> FloorInfo {
        let zero_bytes = input.iter().filter(|b| **b == 0).count();
        let non_zero_bytes = input.len() - zero_bytes;
        let tokens = (zero_bytes + 4 * non_zero_bytes) as u64;
        // ChainSpec floor prices are per byte: zero = 1 token, non-zero = 4 tokens.
        let floor_gas = (self.spec.bundle_intrinsic_gas()
            + self.spec.calldata_floor_zero_byte_gas() * zero_bytes as u128
            + self.spec.calldata_floor_non_zero_byte_gas() * non_zero_bytes as u128)
            as u64;
        FloorInfo {
            calldata_len: input.len(),
            zero_bytes,
            non_zero_bytes,
            tokens,
            floor_gas,
            floor_bound: gas_used == floor_gas,
        }
    }
}

fn rand_bytes32() -> [u8; 32] {
    alloy_primitives::B256::random().0
}
