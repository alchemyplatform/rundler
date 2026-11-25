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

//! Simulating calls with an EIP-8037 state-gas reservoir.

use alloy_network::TransactionBuilder;
use alloy_primitives::{Address, B256, Bytes, U64, U256};
use alloy_rpc_types_eth::{
    BlockId, BlockNumberOrTag,
    state::{AccountOverride, StateOverride},
};
use alloy_sol_types::SolCall;
use anyhow::Context;
use rundler_contracts::v0_7::{RESERVOIR_PROBE_V0_7_DEPLOYED_BYTECODE, ReservoirProbe::probeCall};
use rundler_types::{TX_MAX_GAS_LIMIT, constants::SIMULATION_SENDER};
use serde::Deserialize;
use serde_json::json;

use crate::{EvmProvider, ProviderResult, TransactionRequest};

/// The reservoir a [`reservoir_probe_call`] gets: enough for the new slot it writes
const RESERVOIR_PROBE_RESERVOIR_GAS: u64 = 200_000;

/// The result of one call simulated with `eth_simulateV1`.
#[derive(Clone, Debug)]
pub struct SimulatedCall {
    /// Whether the call succeeded.
    pub success: bool,
    /// The call's output, or its revert data if it reverted.
    pub return_data: Bytes,
    /// Gas used by the call, as a transaction's receipt would report it.
    pub gas_used: u64,
    /// Logs the call emitted (none if it reverted).
    pub logs: Vec<SimulatedLog>,
}

/// A log emitted by a call simulated with `eth_simulateV1`.
#[derive(Clone, Debug, Deserialize)]
pub struct SimulatedLog {
    /// The emitting contract.
    pub address: Address,
    /// The log's topics.
    pub topics: Vec<B256>,
    /// The log's data.
    pub data: Bytes,
}

#[derive(Debug, Deserialize)]
struct RawSimulatedBlock {
    calls: Vec<RawSimulatedCall>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSimulatedCall {
    status: U64,
    return_data: Bytes,
    gas_used: U64,
    #[serde(default)]
    logs: Vec<SimulatedLog>,
}

/// What the calls of a simulation pay for their gas.
///
/// Simulations run in validation mode (see [`simulate_call`]), which checks each call's fees
/// against the block's base fee and its sender's balance against its gas at its fee cap. Either
/// way, each call's nonce is dropped, so it is its sender's next one: a sender can have
/// transactions pending that the simulated block does not include.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulatedFees {
    /// Nothing: the block's base fee is set to 0 and each call's fees are dropped, so its gas
    /// price is 0 and its sender needs no balance. For a simulation whose sender is not the one
    /// that will pay (estimation and admission), or on a chain whose node's base fee check a
    /// bundle cannot meet (`bundle_simulation_omit_gas_fees`).
    Zero,
    /// The calls' own fees, at the base fee the node computes for the simulated block, as the
    /// transaction will pay them onchain: `GASPRICE`, `BASEFEE` and the EntryPoint's gas price
    /// are what it will see. The sender must hold its gas at its fee cap, and a fee cap below
    /// the base fee fails the request before any call runs
    /// ([`ProviderError::is_base_fee_too_low`](crate::ProviderError::is_base_fee_too_low)).
    AsSent,
}

/// Simulates `tx` as a transaction with `eth_simulateV1`, so that its gas above
/// [`TX_MAX_GAS_LIMIT`] goes to an EIP-8037 state-gas reservoir, as a transaction's does.
///
/// The simulation runs in validation mode, which applies the transaction rules, the reservoir
/// among them: reth v2.10 gives a call no reservoir without it (reth v2.7 gave one either way).
/// Validation mode also checks fees, nonces and balances, which `fees` sets up.
///
/// The simulated block's gas limit is set to the call's gas: a call whose gas is above what is
/// left of the block's gas limit fails (reth v2.10). No higher: a node rejects a block gas limit
/// override above both its live block gas limit and its `rpc.gascap`, before running any call.
/// `tx` must have a gas limit.
///
/// Whether a node gives calls a reservoir is checked with [`simulate_call_after_reservoir_probe`].
pub async fn simulate_call<P: EvmProvider>(
    provider: &P,
    tx: TransactionRequest,
    block_id: Option<BlockId>,
    state_override: StateOverride,
    fees: SimulatedFees,
) -> ProviderResult<SimulatedCall> {
    let block_gas_limit = tx.gas.context("a simulated call needs a gas limit")?;
    let mut calls = simulate_block(
        provider,
        vec![tx],
        block_gas_limit,
        block_id,
        state_override,
        fees,
    )
    .await?;
    Ok(calls.remove(0))
}

/// The result of [`simulate_call_after_reservoir_probe`].
#[derive(Clone, Debug)]
pub struct ProbedCall {
    /// Whether the `ReservoirProbe` got a state-gas reservoir. If not, the node's `eth_simulateV1`
    /// gives calls none, and `call` ran without one.
    pub found_reservoir: bool,
    /// The simulated call.
    pub call: SimulatedCall,
}

/// As [`simulate_call`], after a `ReservoirProbe` call in the same request (so on the same node)
/// that checks whether the node's `eth_simulateV1` gives calls a state-gas reservoir, which `tx`
/// relies on.
///
/// The probe is its own call rather than wrapping `tx`, which would see what `tx` left of the
/// reservoir. It runs first, and the block's gas limit is the larger of the two calls' gas plus
/// [`RESERVOIR_PROBE_GAS_HEADROOM`], which covers what the probe uses: `tx` gets its full gas,
/// and the override stays within the `rpc.gascap` that reservoir-mode simulations require.
///
/// With [`SimulatedFees::AsSent`], the probe pays `tx`'s fees, so it passes the node's checks
/// against the base fee as `tx` does, from a sender of its own that a state override funds, so
/// it leaves `tx`'s sender's balance and nonce as they are.
///
/// An error if the probe used more than [`RESERVOIR_PROBE_GAS_HEADROOM`]: `tx` may then have run
/// with less gas than requested, so its result can't be trusted.
pub async fn simulate_call_after_reservoir_probe<P: EvmProvider>(
    provider: &P,
    tx: TransactionRequest,
    block_id: Option<BlockId>,
    mut state_override: StateOverride,
    fees: SimulatedFees,
) -> ProviderResult<ProbedCall> {
    let tx_gas = tx.gas.context("a simulated call needs a gas limit")?;
    let probe = reservoir_probe_call(&mut state_override, &tx, fees);
    let block_gas_limit = probed_block_gas_limit(probe.gas.unwrap_or_default(), tx_gas);
    let mut calls = simulate_block(
        provider,
        vec![probe, tx],
        block_gas_limit,
        block_id,
        state_override,
        fees,
    )
    .await?;
    let call = calls.remove(1);
    let found_reservoir = reservoir_probe_found_reservoir(&calls[0])?;
    Ok(ProbedCall {
        found_reservoir,
        call,
    })
}

/// The block gas limit for a reservoir probe with `probe_gas` followed by a call with `tx_gas`:
/// the call needs its gas left after what the probe used, at most
/// [`RESERVOIR_PROBE_GAS_HEADROOM`].
fn probed_block_gas_limit(probe_gas: u64, tx_gas: u64) -> u64 {
    probe_gas
        .max(tx_gas)
        .saturating_add(RESERVOIR_PROBE_GAS_HEADROOM)
}

/// Simulates `txs` one after the other in one block with a gas limit of `block_gas_limit`, in one
/// `eth_simulateV1` request (so on one node), see [`simulate_call`].
async fn simulate_block<P: EvmProvider>(
    provider: &P,
    txs: Vec<TransactionRequest>,
    block_gas_limit: u64,
    block_id: Option<BlockId>,
    state_override: StateOverride,
    fees: SimulatedFees,
) -> ProviderResult<Vec<SimulatedCall>> {
    let count = txs.len();
    let txs: Vec<TransactionRequest> = txs.into_iter().map(|tx| simulated_tx(tx, fees)).collect();
    let block_overrides = match fees {
        SimulatedFees::Zero => {
            json!({ "gasLimit": U64::from(block_gas_limit), "baseFeePerGas": U64::ZERO })
        }
        // The node's base fee for the simulated block
        SimulatedFees::AsSent => json!({ "gasLimit": U64::from(block_gas_limit) }),
    };
    let payload = json!({
        "validation": true,
        "blockStateCalls": [{
            "blockOverrides": block_overrides,
            "stateOverrides": state_override,
            "calls": txs,
        }],
    });
    let block_id = block_id.unwrap_or(BlockNumberOrTag::Latest.into());
    // Requested as plain JSON (rather than `RawSimulatedBlock`) so callers can mock it.
    let blocks: serde_json::Value = provider
        .request("eth_simulateV1", (payload, block_id))
        .await?;
    let blocks: Vec<RawSimulatedBlock> =
        serde_json::from_value(blocks).context("invalid eth_simulateV1 result")?;
    let calls: Vec<SimulatedCall> = blocks
        .into_iter()
        .next()
        .context("eth_simulateV1 result has no block")?
        .calls
        .into_iter()
        .map(|call| SimulatedCall {
            success: call.status == U64::from(1),
            return_data: call.return_data,
            gas_used: call.gas_used.to(),
            logs: call.logs,
        })
        .collect();
    if calls.len() != count {
        Err(anyhow::anyhow!(
            "eth_simulateV1 returned {} calls for {count}",
            calls.len()
        ))?;
    }
    Ok(calls)
}

/// `tx` as it is simulated: without its nonce, and without its fees if `fees` is
/// [`SimulatedFees::Zero`]
fn simulated_tx(mut tx: TransactionRequest, fees: SimulatedFees) -> TransactionRequest {
    tx.nonce = None;
    match fees {
        SimulatedFees::Zero => {
            tx.gas_price = None;
            tx.max_fee_per_gas = None;
            tx.max_priority_fee_per_gas = None;
            tx.max_fee_per_blob_gas = None;
        }
        SimulatedFees::AsSent => {}
    }
    tx
}

/// Adds a `ReservoirProbe` at a random address (so it cannot collide with a caller's override)
/// to `state_override` and returns a call to it, run before `tx`. Read its result with
/// [`reservoir_probe_found_reservoir`].
///
/// With [`SimulatedFees::AsSent`], the call pays `tx`'s fees, from a random sender that
/// `state_override` funds well beyond them: what the probe pays is not what is simulated, and a
/// chain may charge a sender more up front than its gas at its fee cap.
fn reservoir_probe_call(
    state_override: &mut StateOverride,
    tx: &TransactionRequest,
    fees: SimulatedFees,
) -> TransactionRequest {
    let probe = Address::random();
    state_override.insert(
        probe,
        AccountOverride {
            code: Some(RESERVOIR_PROBE_V0_7_DEPLOYED_BYTECODE.clone()),
            ..Default::default()
        },
    );
    let gas = TX_MAX_GAS_LIMIT + RESERVOIR_PROBE_RESERVOIR_GAS;
    let mut call = TransactionRequest::default()
        .to(probe)
        .input(Bytes::from(probeCall {}.abi_encode()).into())
        .with_gas_limit(gas);
    match fees {
        SimulatedFees::Zero => call.from(SIMULATION_SENDER),
        SimulatedFees::AsSent => {
            let sender = Address::random();
            state_override.insert(
                sender,
                AccountOverride {
                    balance: Some(U256::from(u128::MAX)),
                    ..Default::default()
                },
            );
            call.gas_price = tx.gas_price;
            call.max_fee_per_gas = tx.max_fee_per_gas;
            call.max_priority_fee_per_gas = tx.max_priority_fee_per_gas;
            call.from(sender)
        }
    }
}

/// The most gas a reservoir probe may use (it uses 28,301 on Sepolia, reth v2.10).
///
/// A node applies its `rpc.gascap` to an `eth_simulateV1` request as a whole: each call's gas used
/// is taken from it, and a later call's gas limit is lowered, without an error, to what is left
/// (reth v2.10). The probe runs first, so it takes up to this much from the call after it, and
/// the simulated block's gas limit includes it. Reservoir-mode simulations therefore need an
/// `rpc.gascap` of at least `2^24 + max_reservoir_gas + RESERVOIR_PROBE_GAS_HEADROOM`, with
/// `max_reservoir_gas` counted as at least the probe's own reservoir (200,000).
pub const RESERVOIR_PROBE_GAS_HEADROOM: u64 = 100_000;

/// Whether the [`reservoir_probe_call`] `result` got a state-gas reservoir.
///
/// An error if the probe used more than [`RESERVOIR_PROBE_GAS_HEADROOM`]: the call after it may
/// then have run with less gas than requested, so its result can't be trusted.
fn reservoir_probe_found_reservoir(result: &SimulatedCall) -> anyhow::Result<bool> {
    anyhow::ensure!(
        result.gas_used <= RESERVOIR_PROBE_GAS_HEADROOM,
        "the reservoir probe used {} gas, above its headroom of {RESERVOIR_PROBE_GAS_HEADROOM}: \
         the calls after it may have run with less gas than requested",
        result.gas_used
    );
    Ok(result.success
        && probeCall::abi_decode_returns(&result.return_data)
            .context("should decode the reservoir probe's result")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A reth v2.7 eth_simulateV1 result (trimmed): one block with one call.
    const RETH_SIMULATE: &str = r#"[{
        "number": "0xb5f8fc",
        "gasLimit": "0x11e1a300",
        "calls": [{
            "returnData": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "logs": [{
                "address": "0x0000000071727de22e5e9d8baf0edac6f37da032",
                "topics": ["0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f"],
                "data": "0x01",
                "blockNumber": "0xb5f8fc",
                "logIndex": "0x0"
            }],
            "gasUsed": "0x2421e64",
            "status": "0x1"
        }]
    }]"#;

    #[test]
    fn simulated_calls_drop_the_nonce_and_zero_fees() {
        let tx = TransactionRequest::default()
            .nonce(7)
            .max_fee_per_gas(10)
            .max_priority_fee_per_gas(1)
            .gas_price(5)
            .with_gas_limit(100_000);
        let zero = simulated_tx(tx.clone(), SimulatedFees::Zero);
        assert_eq!(zero.nonce, None);
        assert_eq!(zero.max_fee_per_gas, None);
        assert_eq!(zero.max_priority_fee_per_gas, None);
        assert_eq!(zero.gas_price, None);
        assert_eq!(zero.gas, Some(100_000));
        let as_sent = simulated_tx(tx, SimulatedFees::AsSent);
        assert_eq!(as_sent.nonce, None);
        assert_eq!(as_sent.max_fee_per_gas, Some(10));
        assert_eq!(as_sent.max_priority_fee_per_gas, Some(1));
        assert_eq!(as_sent.gas_price, Some(5));
        assert_eq!(as_sent.gas, Some(100_000));
    }

    const MAX_FEE: u128 = 2_000_000_000;
    const PRIORITY_FEE: u128 = 100_000_000;

    fn tx_with_fees(sender: Address) -> TransactionRequest {
        TransactionRequest::default()
            .from(sender)
            .to(Address::repeat_byte(2))
            .nonce(7)
            .max_fee_per_gas(MAX_FEE)
            .max_priority_fee_per_gas(PRIORITY_FEE)
            .with_gas_limit(TX_MAX_GAS_LIMIT + 1_000_000)
    }

    /// An `eth_simulateV1` result of a probe that found a reservoir, then a call that succeeded
    fn probed_result() -> serde_json::Value {
        let probe = json!({
            "status": "0x1",
            "returnData": Bytes::from(probeCall::abi_encode_returns(&true)),
            "gasUsed": "0x6e8d",
        });
        let call = json!({ "status": "0x1", "returnData": "0x", "gasUsed": "0x5208" });
        json!([{ "calls": [probe, call] }])
    }

    /// The calls and state overrides of an `eth_simulateV1` request
    fn simulated_calls(payload: &serde_json::Value) -> (Vec<TransactionRequest>, StateOverride) {
        let block = &payload["blockStateCalls"][0];
        let calls = serde_json::from_value(block["calls"].clone()).unwrap();
        let state_override = serde_json::from_value(block["stateOverrides"].clone()).unwrap();
        (calls, state_override)
    }

    /// As sent, the probe and the call pay the call's fees at the node's base fee for the
    /// simulated block, and the probe has a sender of its own, funded for at least its gas at
    /// that fee cap
    #[tokio::test]
    async fn probed_simulation_pays_the_fees_as_sent() {
        let sender = Address::repeat_byte(1);
        let mut provider = crate::MockEvmProvider::new();
        provider
            .expect_request::<(serde_json::Value, BlockId), serde_json::Value>()
            .times(1)
            .returning(move |method, (payload, _)| {
                assert_eq!(method, "eth_simulateV1");
                assert_eq!(payload["validation"], true);
                let block_overrides = &payload["blockStateCalls"][0]["blockOverrides"];
                assert!(block_overrides.get("baseFeePerGas").is_none());
                let (calls, state_override) = simulated_calls(&payload);
                let [probe, call] = &calls[..] else {
                    panic!("expected the probe and the call, got {calls:?}");
                };
                for tx in [probe, call] {
                    assert_eq!(tx.nonce, None);
                    assert_eq!(tx.max_fee_per_gas, Some(MAX_FEE));
                    assert_eq!(tx.max_priority_fee_per_gas, Some(PRIORITY_FEE));
                }
                assert_eq!(call.from, Some(sender));
                assert!(!state_override.contains_key(&sender));
                let probe_sender = probe.from.unwrap();
                assert_ne!(probe_sender, sender);
                let probe_balance = state_override[&probe_sender].balance.unwrap();
                assert!(probe_balance >= U256::from(probe.gas.unwrap()) * U256::from(MAX_FEE));
                Ok(probed_result())
            });
        let probed = simulate_call_after_reservoir_probe(
            &provider,
            tx_with_fees(sender),
            None,
            StateOverride::default(),
            SimulatedFees::AsSent,
        )
        .await
        .unwrap();
        assert!(probed.found_reservoir);
        assert!(probed.call.success);
    }

    /// With zero fees, the block's base fee is 0, the calls carry no fees and the probe's sender
    /// needs no balance
    #[tokio::test]
    async fn probed_simulation_with_zero_fees() {
        let mut provider = crate::MockEvmProvider::new();
        provider
            .expect_request::<(serde_json::Value, BlockId), serde_json::Value>()
            .times(1)
            .returning(|_, (payload, _)| {
                let block_overrides = &payload["blockStateCalls"][0]["blockOverrides"];
                assert_eq!(block_overrides["baseFeePerGas"], "0x0");
                let (calls, state_override) = simulated_calls(&payload);
                for tx in &calls {
                    assert_eq!(tx.nonce, None);
                    assert_eq!(tx.max_fee_per_gas, None);
                    assert_eq!(tx.max_priority_fee_per_gas, None);
                    assert_eq!(tx.gas_price, None);
                }
                assert_eq!(calls[0].from, Some(SIMULATION_SENDER));
                // Only the probe's code: no sender is funded
                let probe = *calls[0].to.unwrap().to().unwrap();
                assert_eq!(state_override.len(), 1);
                assert!(state_override[&probe].code.is_some());
                assert_eq!(state_override[&probe].balance, None);
                Ok(probed_result())
            });
        let probed = simulate_call_after_reservoir_probe(
            &provider,
            tx_with_fees(Address::repeat_byte(1)),
            None,
            StateOverride::default(),
            SimulatedFees::Zero,
        )
        .await
        .unwrap();
        assert!(probed.found_reservoir);
    }

    #[test]
    fn reads_reservoir_probe_result() {
        let call = |success, found: bool, gas_used| SimulatedCall {
            success,
            return_data: probeCall::abi_encode_returns(&found).into(),
            gas_used,
            logs: vec![],
        };
        assert!(reservoir_probe_found_reservoir(&call(true, true, 28_301)).unwrap());
        assert!(!reservoir_probe_found_reservoir(&call(true, false, 28_301)).unwrap());
        assert!(!reservoir_probe_found_reservoir(&call(false, true, 28_301)).unwrap());
        assert!(
            reservoir_probe_found_reservoir(&call(true, true, RESERVOIR_PROBE_GAS_HEADROOM))
                .unwrap()
        );
        // Above its headroom, the calls after it may have been given less gas
        assert!(
            reservoir_probe_found_reservoir(&call(true, true, RESERVOIR_PROBE_GAS_HEADROOM + 1))
                .is_err()
        );
    }

    /// The block gas limit of a probed simulation stays within the `rpc.gascap` that reservoir
    /// mode requires (`2^24 + max_reservoir_gas + RESERVOIR_PROBE_GAS_HEADROOM`, with
    /// `max_reservoir_gas` counted as at least the probe's reservoir) at the largest reservoir,
    /// and leaves the call its full gas after the probe. A node rejects an override above both its
    /// block gas limit and its cap.
    #[test]
    fn probed_block_gas_limit_fits_the_required_gas_cap() {
        let probe_gas = TX_MAX_GAS_LIMIT + RESERVOIR_PROBE_RESERVOIR_GAS;
        for max_reservoir_gas in [
            50_000,
            RESERVOIR_PROBE_RESERVOIR_GAS,
            10_000_000,
            60_000_000,
            1_000_000_000,
        ] {
            let required_gas_cap = TX_MAX_GAS_LIMIT
                + max_reservoir_gas.max(RESERVOIR_PROBE_RESERVOIR_GAS)
                + RESERVOIR_PROBE_GAS_HEADROOM;
            for reservoir_gas in [0, max_reservoir_gas / 2, max_reservoir_gas] {
                let tx_gas = TX_MAX_GAS_LIMIT + reservoir_gas;
                let block_gas_limit = probed_block_gas_limit(probe_gas, tx_gas);
                assert!(
                    block_gas_limit <= required_gas_cap,
                    "{block_gas_limit} > {required_gas_cap} (R {reservoir_gas})"
                );
                assert!(block_gas_limit >= probe_gas);
                assert!(block_gas_limit >= tx_gas + RESERVOIR_PROBE_GAS_HEADROOM);
            }
        }
        // A 60M-block chain with max_reservoir_gas 60M and R 10M: the previous sizing,
        // 2 * (probe + call), sent 87,508,864, above both the block gas limit and the cap.
        assert_eq!(
            probed_block_gas_limit(probe_gas, TX_MAX_GAS_LIMIT + 10_000_000),
            26_877_216
        );
    }

    /// A call without a gas limit is an error, not a simulation with a block gas limit of 0
    #[tokio::test]
    async fn simulated_call_needs_a_gas_limit() {
        // No expectations: the provider must not be called
        let provider = crate::MockEvmProvider::new();
        let tx = TransactionRequest::default().to(Address::ZERO);
        let error = simulate_call(
            &provider,
            tx.clone(),
            None,
            StateOverride::default(),
            SimulatedFees::Zero,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("needs a gas limit"), "{error}");
        let error = simulate_call_after_reservoir_probe(
            &provider,
            tx,
            None,
            StateOverride::default(),
            SimulatedFees::Zero,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("needs a gas limit"), "{error}");
    }

    #[test]
    fn parses_reth_simulate_result() {
        let blocks: Vec<RawSimulatedBlock> = serde_json::from_str(RETH_SIMULATE).unwrap();
        let call = &blocks[0].calls[0];
        assert_eq!(call.status, U64::from(1));
        assert_eq!(call.gas_used, U64::from(37_887_588));
        assert_eq!(call.return_data.len(), 32);
        assert_eq!(call.logs.len(), 1);
        assert_eq!(call.logs[0].topics.len(), 1);
    }

    #[test]
    fn parses_reverted_simulated_call() {
        let json = r#"[{"calls": [{"returnData": "0x08c379a0", "gasUsed": "0x5208",
            "status": "0x0", "error": {"code": 3, "message": "execution reverted"}}]}]"#;
        let blocks: Vec<RawSimulatedBlock> = serde_json::from_str(json).unwrap();
        let call = &blocks[0].calls[0];
        assert_eq!(call.status, U64::ZERO);
        assert!(call.logs.is_empty());
    }
}
