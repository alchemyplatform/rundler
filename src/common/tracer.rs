use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
};

use anyhow::Context;
use ethers::{
    providers::{JsonRpcClient, Middleware, Provider},
    types::{transaction::eip2718::TypedTransaction, Address, BlockId, Bytes, OpCode, U256},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{contracts::entry_point::EntryPoint, types::UserOperation};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TracerOutput {
    pub phases: Vec<Phase>,
    pub revert_data: Option<String>,
    pub accessed_contract_addresses: Vec<Address>,
    pub associated_slots_by_address: AssociatedSlotsByAddress,
    pub factory_called_create2_twice: bool,
    pub expected_storage: Vec<ExpectedStorage>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Phase {
    pub forbidden_opcodes_used: Vec<OpCode>,
    pub used_invalid_gas_opcode: bool,
    pub storage_accesses: Vec<StorageAccess>,
    pub called_handle_ops: bool,
    pub called_with_value: bool,
    pub ran_out_of_gas: bool,
    pub undeployed_contract_accesses: Vec<Address>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageAccess {
    pub address: Address,
    pub slots: Vec<U256>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedStorage {
    pub address: Address,
    pub slots: Vec<ExpectedSlot>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedSlot {
    pub slot: U256,
    pub value: U256,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssociatedSlotsByAddress(HashMap<Address, BTreeSet<U256>>);

impl AssociatedSlotsByAddress {
    pub fn is_associated_slot(&self, address: Address, slot: U256) -> bool {
        if slot == address.as_bytes().into() {
            return true;
        }
        let Some(associated_slots) = self.0.get(&address) else {
            return false;
        };
        let Some(&next_smallest_slot) = associated_slots.range(..(slot + 1)).next_back() else {
            return false;
        };
        slot - next_smallest_slot < 128.into()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GasTracerOutput {
    pub phases: Vec<GasPhase>,
    pub revert_data: Option<String>,
    pub gas_used: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GasPhase {
    pub gas_used: u64,
    pub gas_remaining_at_conclusion: u64,
    pub account_revert_data: Option<String>,
}

/// Runs the bundler's custom tracer on the entry point's `simulateValidation`
/// method for the provided user operation.
pub async fn trace_simulate_validation(
    entry_point: &EntryPoint<impl Middleware>,
    op: UserOperation,
    block_id: BlockId,
) -> anyhow::Result<TracerOutput> {
    let tx = entry_point.simulate_validation(op).tx;
    trace_call(
        entry_point.client().provider(),
        tx,
        block_id,
        validation_tracer_js(),
    )
    .await
}

/// Runs the bundler's custom tracer on the entry point's `simulateHandleOp`
/// method for the provided user operation.
pub async fn trace_simulate_handle_op(
    entry_point: &EntryPoint<impl Middleware>,
    op: UserOperation,
    block_id: BlockId,
) -> anyhow::Result<GasTracerOutput> {
    let tx = entry_point
        .simulate_handle_op(op, Address::default(), Bytes::default())
        .tx;
    trace_call(
        entry_point.client().provider(),
        tx,
        block_id,
        gas_tracer_js(),
    )
    .await
}

async fn trace_call<T>(
    provider: &Provider<impl JsonRpcClient>,
    tx: TypedTransaction,
    block_id: BlockId,
    tracer_code: &str,
) -> anyhow::Result<T>
where
    T: Debug + DeserializeOwned + Serialize,
{
    let out = provider
        .request(
            "debug_traceCall",
            (tx, block_id, serde_json::json!({ "tracer": tracer_code })),
        )
        .await
        .context("failed to run bundler trace")?;
    Ok(out)
}

fn validation_tracer_js() -> &'static str {
    include_str!("../../tracer/dist/validationTracer.js").trim_end_matches(";\n")
}

fn gas_tracer_js() -> &'static str {
    include_str!("../../tracer/dist/gasTracer.js").trim_end_matches(";\n")
}
