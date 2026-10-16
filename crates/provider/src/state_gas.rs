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

//! Tracing the EIP-8037 state gas of a call, and simulating calls with a state-gas reservoir.

use alloy_primitives::{Address, B256, Bytes, U64};
use alloy_rpc_types_eth::{BlockId, BlockNumberOrTag, state::StateOverride};
use alloy_rpc_types_trace::geth::CallFrame;
use anyhow::Context;
use serde::Deserialize;
use serde_json::json;

use crate::{EvmProvider, ProviderResult, TransactionRequest};

/// A call's gas split into execution and EIP-8037 state gas, with its call frames.
///
/// Clients differ on whether a call's gas above
/// [`TX_MAX_GAS_LIMIT`](rundler_types::TX_MAX_GAS_LIMIT) goes to a state-gas reservoir, as in a
/// transaction. Without one (reth v2.7), the whole call gas is `gas_left`, and state charges are
/// metered and bounded by each frame's gas. With one (besu, geth, later reth), state is charged
/// to the reservoir first and does not show in the frames' gas used.
#[derive(Clone, Debug)]
pub struct StateGasTrace {
    /// Execution gas used by the call.
    pub execution_gas_used: u64,
    /// Net state gas used by the call: charges minus refills. Zero if the call reverted, since
    /// a top-level revert undoes all state.
    pub state_gas_used: u64,
    /// Refund counter at the end of the call.
    pub gas_refund: u64,
    /// The root call frame (with nested calls and logs). Per-frame `gas_used` counts execution
    /// gas, and the state gas not charged to a reservoir.
    pub frame: CallFrame,
}

impl StateGasTrace {
    /// The revert or halt error of the root call, if it failed.
    pub fn error(&self) -> Option<&str> {
        self.frame.error.as_deref()
    }
}

/// The root of a `callTracer` result, with the EIP-8037 fields clients add to it
/// (ethereum/execution-apis#852; reth names the execution part `executionGasUsed`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawStateGasFrame {
    #[serde(flatten)]
    frame: CallFrame,
    #[serde(alias = "regularGasUsed")]
    execution_gas_used: Option<U64>,
    state_gas_used: Option<U64>,
    gas_refund: Option<U64>,
}

impl TryFrom<RawStateGasFrame> for StateGasTrace {
    type Error = anyhow::Error;

    fn try_from(raw: RawStateGasFrame) -> Result<Self, Self::Error> {
        Ok(Self {
            execution_gas_used: raw
                .execution_gas_used
                .context("trace has no executionGasUsed: node does not report EIP-8037 gas")?
                .to(),
            state_gas_used: raw
                .state_gas_used
                .context("trace has no stateGasUsed: node does not report EIP-8037 gas")?
                .to(),
            gas_refund: raw.gas_refund.map(|r| r.to()).unwrap_or_default(),
            frame: raw.frame,
        })
    }
}

/// Traces `tx` with `callTracer` (with logs) and returns its execution and state gas.
///
/// Fails if the node does not report EIP-8037 state gas on the root frame.
pub async fn trace_call_state_gas<P: EvmProvider>(
    provider: &P,
    tx: TransactionRequest,
    block_id: Option<BlockId>,
    state_override: StateOverride,
) -> ProviderResult<StateGasTrace> {
    let options = json!({
        "tracer": "callTracer",
        "tracerConfig": { "withLog": true },
        "stateOverrides": state_override,
    });
    let block_id = block_id.unwrap_or(BlockNumberOrTag::Latest.into());
    // Requested as plain JSON (rather than `RawStateGasFrame`) so callers can mock the trace.
    let trace: serde_json::Value = provider
        .request("debug_traceCall", (tx, block_id, options))
        .await?;
    let raw: RawStateGasFrame =
        serde_json::from_value(trace).context("invalid callTracer result")?;
    Ok(raw.try_into()?)
}

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
    let block_gas_limit = tx.gas.unwrap_or_default().saturating_mul(2);
    let payload = json!({
        "blockStateCalls": [{
            "blockOverrides": { "gasLimit": U64::from(block_gas_limit) },
            "stateOverrides": state_override,
            "calls": [tx],
        }],
    });
    let block_id = block_id.unwrap_or(BlockNumberOrTag::Latest.into());
    // Requested as plain JSON (rather than `RawSimulatedBlock`) so callers can mock it.
    let blocks: serde_json::Value = provider
        .request("eth_simulateV1", (payload, block_id))
        .await?;
    let blocks: Vec<RawSimulatedBlock> =
        serde_json::from_value(blocks).context("invalid eth_simulateV1 result")?;
    let call = blocks
        .into_iter()
        .next()
        .and_then(|block| block.calls.into_iter().next())
        .context("eth_simulateV1 result has no call")?;
    Ok(SimulatedCall {
        success: call.status == U64::from(1),
        return_data: call.return_data,
        gas_used: call.gas_used.to(),
        logs: call.logs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A reth v2.7 callTracer root frame (trimmed).
    const RETH_ROOT: &str = r#"{
        "from": "0xa6dea2e10bce3e8bd93814937f8d863486ddb714",
        "gas": "0xbebc200",
        "gasUsed": "0x1d8700",
        "to": "0x0000000071727de22e5e9d8baf0edac6f37da032",
        "input": "0x765e827f",
        "calls": [{
            "from": "0x0000000071727de22e5e9d8baf0edac6f37da032",
            "gas": "0x493e0",
            "gasUsed": "0x1ad",
            "to": "0xfd5d8f31bdd2a41aca1866a51c6b11dc0c6fa545",
            "input": "0x19822f7c",
            "value": "0x0",
            "type": "CALL"
        }],
        "value": "0x0",
        "type": "CALL",
        "executionGasUsed": "0x1c2f90",
        "stateGasUsed": "0x17e80",
        "gasRefund": "0x2710"
    }"#;

    #[test]
    fn parses_reth_root_frame() {
        let raw: RawStateGasFrame = serde_json::from_str(RETH_ROOT).unwrap();
        let trace = StateGasTrace::try_from(raw).unwrap();
        assert_eq!(trace.execution_gas_used, 0x1c2f90);
        assert_eq!(trace.state_gas_used, 97_920);
        assert_eq!(trace.gas_refund, 10_000);
        assert_eq!(trace.frame.calls.len(), 1);
        assert!(trace.error().is_none());
    }

    #[test]
    fn accepts_regular_gas_used_name() {
        let json = RETH_ROOT.replace("executionGasUsed", "regularGasUsed");
        let raw: RawStateGasFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(
            StateGasTrace::try_from(raw).unwrap().execution_gas_used,
            0x1c2f90
        );
    }

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

    #[test]
    fn rejects_trace_without_state_gas() {
        let json = RETH_ROOT
            .replace(r#""stateGasUsed": "0x17e80","#, "")
            .replace("executionGasUsed", "unused");
        let raw: RawStateGasFrame = serde_json::from_str(&json).unwrap();
        assert!(StateGasTrace::try_from(raw).is_err());
    }
}
