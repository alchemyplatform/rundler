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

use alloy_primitives::{Address, B256, Bytes, U64};
use alloy_rpc_types_eth::{BlockId, BlockNumberOrTag, state::StateOverride};
use anyhow::Context;
use serde::Deserialize;
use serde_json::json;

use crate::{EvmProvider, ProviderResult, TransactionRequest};

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

/// Simulates `tx` as a transaction with `eth_simulateV1`.
///
/// Unlike `eth_call`, reth v2.7's `eth_simulateV1` gives a call's gas above
/// [`TX_MAX_GAS_LIMIT`](rundler_types::TX_MAX_GAS_LIMIT) to an EIP-8037 state-gas reservoir, as a
/// transaction gets. The block's gas limit is raised for `tx`, which `eth_simulateV1` otherwise
/// caps a call's gas at.
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
    let block_gas_limit = txs
        .iter()
        .map(|tx| tx.gas.unwrap_or_default())
        .fold(0_u64, u64::saturating_add)
        .saturating_mul(2);
    let payload = json!({
        "blockStateCalls": [{
            "blockOverrides": { "gasLimit": U64::from(block_gas_limit) },
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
