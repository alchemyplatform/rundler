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

//! Connection to the chain under test and the primitives every experiment uses:
//! send a transaction and record exactly what it cost, and deploy fixtures idempotently.

use std::time::Duration;

use alloy_json_rpc::RpcError;
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, B256, Bytes, I256, U64, U256, address};
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_client::ClientBuilder;
use alloy_rpc_types_eth::{BlockId, Log, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::{
    TransportError, TransportErrorKind,
    layers::{OrRetryPolicyFn, RateLimitRetryPolicy, RetryBackoffLayer},
};
use anyhow::{Context, bail};
use serde::Serialize;
use serde_json::json;

/// Nick's deterministic CREATE2 deployer. Present on the Glamsterdam devnet and on anvil.
pub const CREATE2_DEPLOYER: Address = address!("4e59b44847b379578588920ca78fbf26c0b4956c");

/// Retries for transient RPC failures, with exponential backoff from the initial delay.
const RPC_MAX_RETRIES: u32 = 10;
const RPC_INITIAL_BACKOFF_MS: u64 = 1_000;

/// How long to wait for a sent transaction's receipt before giving up (e.g. when the node
/// dropped it from its pool).
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(180);

/// Gas limit headroom over `eth_estimateGas`, in percent. Only affects the limit set on
/// the transaction, never the measured `gasUsed`.
const GAS_LIMIT_HEADROOM_PERCENT: u64 = 20;

/// Upper bound for any transaction's gas limit: EIP-7825's `TX_MAX_GAS_LIMIT` (2^24).
///
/// Under EIP-8037, gas above this limit becomes the state-gas reservoir, which `gasleft()` does
/// not see. Staying at or below it keeps the reservoir empty, which is how rundler submits
/// bundles on ETH mainnet and Sepolia, and makes every state charge visible to the EntryPoint.
pub const TX_GAS_CAP: u64 = 1 << 24;

/// Priority fee of every probe op, in wei. Op fees only scale prefund and payment, not gas.
pub const OP_PRIORITY_FEE: u128 = 1_000;

/// Identity of the chain the experiment ran against.
#[derive(Debug, Clone, Serialize)]
pub struct ChainInfo {
    pub chain_id: u64,
    pub client_version: String,
    pub block_number: u64,
    pub block_gas_limit: u64,
    pub base_fee_per_gas: Option<u64>,
}

/// Everything recorded about one mined transaction.
#[derive(Debug, Clone, Serialize)]
pub struct TxOutcome {
    pub tx_hash: B256,
    pub block_number: u64,
    pub success: bool,
    /// `eth_estimateGas` for the same request, before sending.
    pub estimate: u64,
    pub gas_limit: u64,
    /// `receipt.gasUsed`.
    pub gas_used: u64,
    pub effective_gas_price: u128,
    /// Value sent with the transaction.
    pub value: U256,
    /// Sender balance change across the transaction's block (after minus before).
    /// `None` if historical balances are not available from the node.
    pub balance_change: Option<I256>,
    /// Gas the sender actually paid for, from `balance_change`, net of value sent and of
    /// value received (see [`TxOutcome::account_for_inflow`]). Should equal `gas_used`; a
    /// mismatch means receipt gas and charged gas diverge.
    pub charged_gas: Option<u64>,
    #[serde(skip)]
    pub logs: Vec<Log>,
}

impl TxOutcome {
    /// True when the balance-derived gas matches `receipt.gasUsed` (or could not be checked).
    pub fn charge_matches_receipt(&self) -> bool {
        self.charged_gas.is_none_or(|g| g == self.gas_used)
    }

    /// Recomputes `charged_gas` given value the sender received in the same transaction,
    /// e.g. the bundle compensation when the bundler is its own beneficiary.
    pub fn account_for_inflow(&mut self, inflow: U256) {
        self.charged_gas = charged_gas(
            self.balance_change,
            self.value,
            inflow,
            self.effective_gas_price,
        );
    }
}

fn charged_gas(
    balance_change: Option<I256>,
    value: U256,
    inflow: U256,
    effective_gas_price: u128,
) -> Option<u64> {
    let change = balance_change?;
    let price = U256::from(effective_gas_price);
    if price.is_zero() {
        return None;
    }
    // change = inflow - value - gas * price
    let spent = I256::try_from(inflow).ok()? - I256::try_from(value).ok()? - change;
    if spent.is_negative() {
        return None;
    }
    u64::try_from(spent.into_raw() / price).ok()
}

/// Output of reth's `stateGasTracer` for one call.
#[derive(Debug, Clone, Serialize)]
pub struct StateGasTrace {
    pub gas_used: u64,
    pub execution_gas_used: u64,
    /// Net EIP-8037 state gas of the whole transaction (charges minus refills).
    pub state_gas_used: u64,
    pub gas_refund: u64,
    /// The tracer's raw result, in case it carries more than the fields above.
    pub raw: serde_json::Value,
}

/// A funded EOA on the chain under test.
pub struct Harness {
    pub provider: DynProvider,
    pub sender: Address,
}

impl Harness {
    pub async fn connect(rpc_url: &str, private_key: &str) -> anyhow::Result<Self> {
        let signer: PrivateKeySigner = private_key
            .trim()
            .trim_start_matches("0x")
            .parse()
            .context("PVG_PRIVATE_KEY is not a valid private key")?;
        let sender = signer.address();
        // Devnet RPC proxies flap: retry 502/503/504 and rate limits instead of aborting a run.
        let policy = OrRetryPolicyFn::new(RateLimitRetryPolicy::default(), |e: &TransportError| {
            matches!(
                e,
                RpcError::Transport(TransportErrorKind::HttpError(h)) if matches!(h.status, 502 | 504)
            )
        });
        let client = ClientBuilder::default()
            .layer(RetryBackoffLayer::new_with_policy(
                RPC_MAX_RETRIES,
                RPC_INITIAL_BACKOFF_MS,
                u64::MAX,
                policy,
            ))
            .connect(rpc_url)
            .await
            .with_context(|| format!("failed to connect to {rpc_url}"))?;
        // Nonces are tracked locally: a load-balanced RPC can answer `pending` nonce queries from
        // a node that has not seen the previous transaction yet, which reuses its nonce.
        let provider = ProviderBuilder::new()
            .with_cached_nonce_management()
            .wallet(EthereumWallet::from(signer))
            .connect_client(client)
            .erased();
        Ok(Self { provider, sender })
    }

    pub async fn chain_info(&self) -> anyhow::Result<ChainInfo> {
        let chain_id = self.provider.get_chain_id().await?;
        let client_version = self
            .provider
            .get_client_version()
            .await
            .unwrap_or_else(|_| "unknown".to_string());
        let block = self
            .provider
            .get_block(BlockId::latest())
            .await?
            .context("latest block not found")?;
        Ok(ChainInfo {
            chain_id,
            client_version,
            block_number: block.header.number,
            block_gas_limit: block.header.gas_limit,
            base_fee_per_gas: block.header.base_fee_per_gas,
        })
    }

    /// `maxFeePerGas` probe ops get when their spec does not pin one: twice the base fee plus
    /// [`OP_PRIORITY_FEE`].
    pub async fn default_max_fee(&self) -> anyhow::Result<u128> {
        let base_fee = self
            .provider
            .get_block(BlockId::latest())
            .await?
            .and_then(|b| b.header.base_fee_per_gas)
            .unwrap_or(1) as u128;
        Ok(base_fee * 2 + OP_PRIORITY_FEE)
    }

    /// Estimates, sends and waits for `tx`, then reconciles the receipt against the
    /// sender's balance change.
    ///
    /// The balance check assumes nothing else moves the sender's balance in the same
    /// block, which holds as long as the harness EOA is used by one run at a time.
    pub async fn send(&self, tx: TransactionRequest) -> anyhow::Result<TxOutcome> {
        let tx = tx.with_from(self.sender);
        let estimate = self.estimate_gas(&tx).await?;
        if estimate > TX_GAS_CAP {
            bail!("estimate {estimate} exceeds the 2^24 transaction gas cap");
        }
        let gas_limit = (estimate + estimate * GAS_LIMIT_HEADROOM_PERCENT / 100).min(TX_GAS_CAP);
        self.send_with_limit(tx, estimate, gas_limit).await
    }

    /// As [`Harness::send`], but with exactly `gas_limit`, which may exceed [`TX_GAS_CAP`] to give
    /// the transaction an EIP-8037 state-gas reservoir of `gas_limit - 2^24`. Sent even when
    /// `eth_estimateGas` fails (e.g. a transaction expected to revert); `estimate` is then 0.
    pub async fn send_with_gas_limit(
        &self,
        tx: TransactionRequest,
        gas_limit: u64,
    ) -> anyhow::Result<TxOutcome> {
        let tx = tx.with_from(self.sender);
        let estimate = match self.estimate_gas(&tx).await {
            Ok(estimate) => estimate,
            Err(e) => {
                eprintln!("eth_estimateGas failed, sending anyway: {e:#}");
                0
            }
        };
        self.send_with_limit(tx, estimate, gas_limit).await
    }

    async fn estimate_gas(&self, tx: &TransactionRequest) -> anyhow::Result<u64> {
        // Only the transaction parameter: Besu behind the devnet's RPC proxy rejects the
        // optional block parameter that `Provider::estimate_gas` sends.
        let estimate: U64 = self
            .provider
            .raw_request("eth_estimateGas".into(), (tx.clone(),))
            .await
            .context("eth_estimateGas failed")?;
        Ok(estimate.to::<u64>())
    }

    async fn send_with_limit(
        &self,
        tx: TransactionRequest,
        estimate: u64,
        gas_limit: u64,
    ) -> anyhow::Result<TxOutcome> {
        let value = tx.value.unwrap_or_default();
        let pending = self
            .provider
            .send_transaction(tx.with_gas_limit(gas_limit))
            .await?;
        let tx_hash = *pending.tx_hash();
        let receipt = pending
            .with_timeout(Some(RECEIPT_TIMEOUT))
            .get_receipt()
            .await
            .with_context(|| format!("no receipt for {tx_hash} (dropped?)"))?;
        let block_number = receipt
            .block_number
            .context("receipt has no block number")?;

        let balance_change = self.balance_change(block_number).await;
        Ok(TxOutcome {
            tx_hash: receipt.transaction_hash,
            block_number,
            success: receipt.status(),
            estimate,
            gas_limit,
            gas_used: receipt.gas_used,
            effective_gas_price: receipt.effective_gas_price,
            value,
            balance_change,
            charged_gas: charged_gas(
                balance_change,
                value,
                U256::ZERO,
                receipt.effective_gas_price,
            ),
            logs: receipt.inner.logs().to_vec(),
        })
    }

    /// `debug_traceCall` with reth's `stateGasTracer` at the latest block: the transaction-level
    /// split of `gasUsed` into execution and (net) state gas under EIP-8037.
    pub async fn trace_state_gas(
        &self,
        tx: &TransactionRequest,
        state_overrides: Option<&serde_json::Value>,
    ) -> anyhow::Result<StateGasTrace> {
        let raw = self
            .debug_trace_call(tx, json!({ "tracer": "stateGasTracer" }), state_overrides)
            .await
            .context("debug_traceCall with stateGasTracer")?;
        let field = |name: &str| {
            raw.get(name)
                .and_then(serde_json::Value::as_str)
                .and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok())
                .with_context(|| format!("stateGasTracer result has no {name}: {raw}"))
        };
        Ok(StateGasTrace {
            gas_used: field("gasUsed")?,
            execution_gas_used: field("executionGasUsed")?,
            state_gas_used: field("stateGasUsed")?,
            gas_refund: field("gasRefund")?,
            raw,
        })
    }

    /// `debug_traceCall` with `callTracer` (with logs) at the latest block.
    pub async fn trace_calls(
        &self,
        tx: &TransactionRequest,
        state_overrides: Option<&serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        self.debug_trace_call(
            tx,
            json!({ "tracer": "callTracer", "tracerConfig": { "withLog": true } }),
            state_overrides,
        )
        .await
        .context("debug_traceCall with callTracer")
    }

    async fn debug_trace_call(
        &self,
        tx: &TransactionRequest,
        mut options: serde_json::Value,
        state_overrides: Option<&serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        if let Some(overrides) = state_overrides {
            options["stateOverrides"] = overrides.clone();
        }
        let tx = tx.clone().with_from(tx.from.unwrap_or(self.sender));
        Ok(self
            .provider
            .raw_request("debug_traceCall".into(), (tx, "latest", options))
            .await?)
    }

    async fn balance_change(&self, block_number: u64) -> Option<I256> {
        let before = self
            .provider
            .get_balance(self.sender)
            .block_id(BlockId::number(block_number - 1))
            .await
            .ok()?;
        let after = self
            .provider
            .get_balance(self.sender)
            .block_id(BlockId::number(block_number))
            .await
            .ok()?;
        Some(I256::try_from(after).ok()? - I256::try_from(before).ok()?)
    }

    /// Deploys `init_code` through the CREATE2 deployer unless code already exists at the
    /// resulting address. Returns the address. Safe to call on every run, so fixtures are
    /// re-created automatically after a devnet reset.
    pub async fn ensure_create2(&self, salt: B256, init_code: &Bytes) -> anyhow::Result<Address> {
        let deployed = CREATE2_DEPLOYER.create2_from_code(salt, init_code);
        if !self.provider.get_code_at(deployed).await?.is_empty() {
            return Ok(deployed);
        }
        if self
            .provider
            .get_code_at(CREATE2_DEPLOYER)
            .await?
            .is_empty()
        {
            bail!("CREATE2 deployer {CREATE2_DEPLOYER} has no code on this chain");
        }

        let mut input = salt.to_vec();
        input.extend_from_slice(init_code);
        let outcome = self
            .send(
                TransactionRequest::default()
                    .with_to(CREATE2_DEPLOYER)
                    .with_input(Bytes::from(input)),
            )
            .await?;
        if !outcome.success || self.provider.get_code_at(deployed).await?.is_empty() {
            bail!(
                "CREATE2 deployment to {deployed} failed (tx {})",
                outcome.tx_hash
            );
        }
        Ok(deployed)
    }
}
