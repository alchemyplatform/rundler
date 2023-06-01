use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
};

use anyhow::Context;
use ethers::{
    providers::{JsonRpcClient, Middleware, Provider},
    types::{transaction::eip2718::TypedTransaction, Address, BlockId, U256},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::common::{
    context::LogWithContext,
    contracts::i_entry_point::IEntryPoint,
    types::{ExpectedStorage, UserOperation},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TracerOutput {
    pub phases: Vec<Phase>,
    pub revert_data: Option<String>,
    pub accessed_contract_addresses: Vec<Address>,
    pub associated_slots_by_address: AssociatedSlotsByAddress,
    pub factory_called_create2_twice: bool,
    pub expected_storage: ExpectedStorage,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Phase {
    pub forbidden_opcodes_used: Vec<String>,
    pub forbidden_precompiles_used: Vec<String>,
    pub storage_accesses: Vec<StorageAccess>,
    pub called_banned_entry_point_method: bool,
    pub addresses_calling_with_value: Vec<Address>,
    pub called_non_entry_point_with_value: bool,
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

/// Runs the bundler's custom tracer on the entry point's `simulateValidation`
/// method for the provided user operation.
pub async fn trace_simulate_validation(
    entry_point: &IEntryPoint<impl Middleware>,
    op: UserOperation,
    block_id: BlockId,
    max_validation_gas: u64,
) -> anyhow::Result<TracerOutput> {
    let pvg = op.pre_verification_gas;
    let tx = entry_point
        .simulate_validation(op)
        .gas(U256::from(max_validation_gas) + pvg)
        .tx;
    trace_call(
        entry_point.client().provider(),
        tx,
        block_id,
        validation_tracer_js(),
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
    T: Debug + DeserializeOwned + Serialize + Send,
{
    let out = provider
        .request(
            "debug_traceCall",
            (tx, block_id, serde_json::json!({ "tracer": tracer_code })),
        )
        .await
        .log_context("failed to run bundler trace")?;
    Ok(out)
}

fn validation_tracer_js() -> &'static str {
    include_str!("../../tracer/dist/validationTracer.js").trim_end_matches(";export{};")
}

pub fn parse_combined_tracer_str<A, B>(combined: &str) -> anyhow::Result<(A, B)>
where
    A: std::str::FromStr,
    B: std::str::FromStr,
    <A as std::str::FromStr>::Err: std::error::Error + Send + Sync + 'static,
    <B as std::str::FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    let (a, b) = combined
        .split_once(':')
        .context("tracer combined should contain two parts")?;
    Ok((a.parse()?, b.parse()?))
}
