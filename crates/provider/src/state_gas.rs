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
use alloy_primitives::{Address, B256, Bytes, U64};
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

/// Simulates `tx` as a transaction with `eth_simulateV1`, so that its gas above
/// [`TX_MAX_GAS_LIMIT`] goes to an EIP-8037 state-gas reservoir, as a transaction's does.
///
/// The simulation runs in validation mode, which applies the transaction rules, the reservoir
/// among them: reth v2.10 gives a call no reservoir without it (reth v2.7 gave one either way).
/// Validation mode also checks fees, nonces and balances, which are not what is simulated here:
/// the block's base fee is set to 0 and each call's nonce and fees are dropped, so its gas price
/// is 0, its sender needs no balance, and its nonce is the sender's next one. The block's gas
/// limit is raised for the calls, which `eth_simulateV1` otherwise caps a call's gas at.
///
/// Whether a node gives calls a reservoir is checked with [`reservoir_probe_call`].
pub async fn simulate_call<P: EvmProvider>(
    provider: &P,
    tx: TransactionRequest,
    block_id: Option<BlockId>,
    state_override: StateOverride,
) -> ProviderResult<SimulatedCall> {
    let mut calls = simulate_calls(provider, vec![tx], block_id, state_override).await?;
    Ok(calls.remove(0))
}

/// As [`simulate_call`], for `txs` run one after the other in one block, in one request (so on
/// one node).
pub async fn simulate_calls<P: EvmProvider>(
    provider: &P,
    txs: Vec<TransactionRequest>,
    block_id: Option<BlockId>,
    state_override: StateOverride,
) -> ProviderResult<Vec<SimulatedCall>> {
    let count = txs.len();
    let txs: Vec<TransactionRequest> = txs.into_iter().map(without_nonce_and_fees).collect();
    let block_gas_limit = txs
        .iter()
        .map(|tx| tx.gas.unwrap_or_default())
        .fold(0_u64, u64::saturating_add)
        .saturating_mul(2);
    let payload = json!({
        "validation": true,
        "blockStateCalls": [{
            "blockOverrides": {
                "gasLimit": U64::from(block_gas_limit),
                "baseFeePerGas": U64::ZERO,
            },
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

/// `tx` without its nonce and fees, see [`simulate_call`]
fn without_nonce_and_fees(mut tx: TransactionRequest) -> TransactionRequest {
    tx.nonce = None;
    tx.gas_price = None;
    tx.max_fee_per_gas = None;
    tx.max_priority_fee_per_gas = None;
    tx.max_fee_per_blob_gas = None;
    tx
}

/// Adds a `ReservoirProbe` at a random address (so it cannot collide with a caller's override)
/// to `state_override` and returns a call to it, to run in the same [`simulate_calls`] request
/// (so on the same node) as calls that rely on a state-gas reservoir. Read its result with
/// [`reservoir_probe_found_reservoir`].
///
/// The probe is its own call rather than wrapping the others, which would see what they left of
/// the reservoir.
pub fn reservoir_probe_call(state_override: &mut StateOverride) -> TransactionRequest {
    let probe = Address::random();
    state_override.insert(
        probe,
        AccountOverride {
            code: Some(RESERVOIR_PROBE_V0_7_DEPLOYED_BYTECODE.clone()),
            ..Default::default()
        },
    );
    TransactionRequest::default()
        .from(SIMULATION_SENDER)
        .to(probe)
        .input(Bytes::from(probeCall {}.abi_encode()).into())
        .with_gas_limit(TX_MAX_GAS_LIMIT + RESERVOIR_PROBE_RESERVOIR_GAS)
}

/// The most gas a [`reservoir_probe_call`] may use (it uses 28,301 on Sepolia, reth v2.10).
///
/// A node applies its `rpc.gascap` to an `eth_simulateV1` request as a whole: each call's gas used
/// is taken from it, and a later call's gas limit is lowered, without an error, to what is left
/// (reth v2.10). The probe runs first, so it takes up to this much from the calls after it.
/// Reservoir-mode simulations therefore need an `rpc.gascap` of at least
/// `2^24 + max_reservoir_gas + RESERVOIR_PROBE_GAS_HEADROOM`.
pub const RESERVOIR_PROBE_GAS_HEADROOM: u64 = 100_000;

/// Whether the [`reservoir_probe_call`] `result` got a state-gas reservoir.
///
/// An error if the probe used more than [`RESERVOIR_PROBE_GAS_HEADROOM`]: the calls after it may
/// then have run with less gas than requested, so their results can't be trusted.
pub fn reservoir_probe_found_reservoir(result: &SimulatedCall) -> anyhow::Result<bool> {
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
    fn simulated_calls_drop_nonce_and_fees() {
        let tx = TransactionRequest::default()
            .nonce(7)
            .max_fee_per_gas(10)
            .max_priority_fee_per_gas(1)
            .gas_price(5)
            .with_gas_limit(100_000);
        let tx = without_nonce_and_fees(tx);
        assert_eq!(tx.nonce, None);
        assert_eq!(tx.max_fee_per_gas, None);
        assert_eq!(tx.max_priority_fee_per_gas, None);
        assert_eq!(tx.gas_price, None);
        assert_eq!(tx.gas, Some(100_000));
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
