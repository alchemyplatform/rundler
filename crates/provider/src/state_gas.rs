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
/// is 0, its sender needs no balance, and its nonce is the sender's next one.
///
/// The simulated block's gas limit is set to the call's gas, since `eth_simulateV1` caps a call's
/// gas at it. No higher: a node rejects a block gas limit override above both its live block gas
/// limit and its `rpc.gascap` (reth v2.10), before running any call.
///
/// Whether a node gives calls a reservoir is checked with [`simulate_call_after_reservoir_probe`].
pub async fn simulate_call<P: EvmProvider>(
    provider: &P,
    tx: TransactionRequest,
    block_id: Option<BlockId>,
    state_override: StateOverride,
) -> ProviderResult<SimulatedCall> {
    let block_gas_limit = tx.gas.unwrap_or_default();
    let mut calls = simulate_block(
        provider,
        vec![tx],
        block_gas_limit,
        block_id,
        state_override,
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
/// An error if the probe used more than [`RESERVOIR_PROBE_GAS_HEADROOM`]: `tx` may then have run
/// with less gas than requested, so its result can't be trusted.
pub async fn simulate_call_after_reservoir_probe<P: EvmProvider>(
    provider: &P,
    tx: TransactionRequest,
    block_id: Option<BlockId>,
    mut state_override: StateOverride,
) -> ProviderResult<ProbedCall> {
    let probe = reservoir_probe_call(&mut state_override);
    let block_gas_limit =
        probed_block_gas_limit(probe.gas.unwrap_or_default(), tx.gas.unwrap_or_default());
    let mut calls = simulate_block(
        provider,
        vec![probe, tx],
        block_gas_limit,
        block_id,
        state_override,
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
) -> ProviderResult<Vec<SimulatedCall>> {
    let count = txs.len();
    let txs: Vec<TransactionRequest> = txs.into_iter().map(without_nonce_and_fees).collect();
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
/// to `state_override` and returns a call to it. Read its result with
/// [`reservoir_probe_found_reservoir`].
fn reservoir_probe_call(state_override: &mut StateOverride) -> TransactionRequest {
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

/// The most gas a reservoir probe may use (it uses 28,301 on Sepolia, reth v2.10).
///
/// A node applies its `rpc.gascap` to an `eth_simulateV1` request as a whole: each call's gas used
/// is taken from it, and a later call's gas limit is lowered, without an error, to what is left
/// (reth v2.10). The probe runs first, so it takes up to this much from the call after it, and
/// the simulated block's gas limit includes it. Reservoir-mode simulations therefore need an
/// `rpc.gascap` of at least `2^24 + max_reservoir_gas + RESERVOIR_PROBE_GAS_HEADROOM`.
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

    /// The block gas limit of a probed simulation stays within the `rpc.gascap` that reservoir
    /// mode requires (`2^24 + max_reservoir_gas + RESERVOIR_PROBE_GAS_HEADROOM`) at the largest
    /// reservoir, and leaves the call its full gas after the probe. A node rejects an override
    /// above both its block gas limit and its cap.
    #[test]
    fn probed_block_gas_limit_fits_the_required_gas_cap() {
        let probe_gas = TX_MAX_GAS_LIMIT + RESERVOIR_PROBE_RESERVOIR_GAS;
        for max_reservoir_gas in [
            RESERVOIR_PROBE_RESERVOIR_GAS,
            10_000_000,
            60_000_000,
            1_000_000_000,
        ] {
            let required_gas_cap =
                TX_MAX_GAS_LIMIT + max_reservoir_gas + RESERVOIR_PROBE_GAS_HEADROOM;
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
        // Codex's mainnet example: max_reservoir_gas 60M, R 10M. The previous sizing,
        // 2 * (probe + call), sent 87,508,864.
        assert_eq!(
            probed_block_gas_limit(probe_gas, TX_MAX_GAS_LIMIT + 10_000_000),
            26_877_216
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
