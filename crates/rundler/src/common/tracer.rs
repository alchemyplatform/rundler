use std::{
    collections::{BTreeSet, HashMap},
    convert::TryFrom,
    fmt::Debug,
    sync::Arc,
};

use anyhow::{bail, Context};
use ethers::types::{
    transaction::eip2718::TypedTransaction, Address, BlockId, GethDebugTracerType,
    GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace, U256,
};
#[cfg(test)]
use mockall::automock;
use rundler_provider::{EntryPoint, Provider};
use rundler_types::UserOperation;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tonic::async_trait;

use super::{
    context::LogWithContext,
    types::{EntryPointLike, ProviderLike},
};
use crate::common::types::{ExpectedStorage, UserOperation};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationTracerOutput {
    pub phases: Vec<Phase>,
    pub revert_data: Option<String>,
    pub accessed_contract_addresses: Vec<Address>,
    pub associated_slots_by_address: AssociatedSlotsByAddress,
    pub factory_called_create2_twice: bool,
    pub expected_storage: ExpectedStorage,
}

impl TryFrom<GethTrace> for SimulationTracerOutput {
    type Error = anyhow::Error;
    fn try_from(trace: GethTrace) -> Result<Self, Self::Error> {
        match trace {
            GethTrace::Unknown(value) => Ok(SimulationTracerOutput::deserialize(&value)?),
            GethTrace::Known(_) => {
                bail!("Failed to deserialize simulation trace")
            }
        }
    }
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

#[cfg_attr(test, automock)]
#[async_trait]
pub trait SimulateValidationTracer: Send + Sync + 'static {
    async fn trace_simulate_validation(
        &self,
        op: UserOperation,
        block_id: BlockId,
        max_validation_gas: u64,
    ) -> anyhow::Result<SimulationTracerOutput>;
}

#[derive(Debug)]
pub struct SimulateValidationTracerImpl<P, E>
where
    P: ProviderLike,
    E: EntryPointLike,
{
    provider: Arc<P>,
    entry_point: Arc<E>,
}

/// Runs the bundler's custom tracer on the entry point's `simulateValidation`
/// method for the provided user operation.

#[async_trait]
impl<P, E> SimulateValidationTracer for SimulateValidationTracerImpl<P, E>
where
    P: ProviderLike,
    E: EntryPointLike,
{
    async fn trace_simulate_validation(
        &self,
        op: UserOperation,
        block_id: BlockId,
        max_validation_gas: u64,
    ) -> anyhow::Result<SimulationTracerOutput> {
        let tx = self
            .entry_point
            .simulate_validation(op, max_validation_gas)
            .await?;

        let asdf = self
            .provider
            .debug_trace_call(
                &tx,
                Some(block_id),
                GethDebugTracingCallOptions {
                    tracing_options: GethDebugTracingOptions {
                        tracer: Some(GethDebugTracerType::JsTracer(
                            validation_tracer_js().to_string(),
                        )),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await?;
        return SimulationTracerOutput::try_from(asdf);
    }
}

impl<P, E> SimulateValidationTracerImpl<P, E>
where
    P: ProviderLike,
    E: EntryPointLike,
{
    pub fn new(provider: Arc<P>, entry_point: Arc<E>) -> Self {
        Self {
            provider,
            entry_point,
        }
    }
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
