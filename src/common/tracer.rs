use crate::common::contracts::entry_point::EntryPoint;
use crate::common::types::UserOperation;
use anyhow::Context;
use ethers::providers::{JsonRpcClient, Middleware, Provider};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, OpCode, H256, U256};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TracerOutput {
    pub block_hash: H256,
    pub phases: Vec<Phase>,
    pub revert_data: String,
    pub accessed_contract_addresses: Vec<Address>,
    pub associated_slots_by_address: AssociatedSlotsByAddress,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Phase {
    pub banned_opcodes_used: Vec<OpCode>,
    pub used_invalid_gas_opcode: bool,
    pub create2_count: u32,
    pub storage_accesses: Vec<StorageAccess>,
    pub called_entry_point: bool,
    pub called_with_value: bool,
    pub ran_out_of_gas: bool,
    pub undeployed_contract_accesses: Vec<Address>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageAccess {
    pub address: Address,
    pub accesses: Vec<SlotAccess>,
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotAccess {
    pub slot: U256,
    pub initial_value: Option<U256>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssociatedSlotsByAddress(HashMap<Address, BTreeSet<U256>>);

impl AssociatedSlotsByAddress {
    pub fn is_associated_slot(&self, address: Address, slot: U256) -> bool {
        if slot == address.as_bytes().into() {
            return true;
        }
        let associated_slots = match self.0.get(&address) {
            Some(slots) => slots,
            None => return false,
        };
        let &next_smallest_slot = match associated_slots.range(..(slot + 1)).next_back() {
            Some(slot) => slot,
            None => return false,
        };
        slot - next_smallest_slot < 128.into()
    }
}

pub async fn trace_op_validation(
    entry_point: &EntryPoint<impl Middleware>,
    op: UserOperation,
) -> anyhow::Result<TracerOutput> {
    let tx = entry_point.simulate_validation(op).tx;
    trace_call(entry_point.client().provider(), tx, tracer_js()).await
}

async fn trace_call<T>(
    provider: &Provider<impl JsonRpcClient>,
    tx: TypedTransaction,
    tracer_code: &str,
) -> anyhow::Result<T>
where
    T: Debug + DeserializeOwned + Serialize,
{
    let out = provider
        .request(
            "debug_traceCall",
            (tx, "latest", serde_json::json!({ "tracer": tracer_code })),
        )
        .await
        .context("failed to run bundler trace")?;
    Ok(out)
}

fn tracer_js() -> &'static str {
    include_str!("../../tracer/dist/index.js").trim_end_matches(";\n")
}
