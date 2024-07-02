// This file is part of Rundler. //
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

use std::{collections::HashMap, convert::TryFrom, fmt::Debug, sync::Arc};

use anyhow::bail;
use async_trait::async_trait;
use ethers::types::{
    Address, BlockId, GethDebugTracerType, GethDebugTracingCallOptions, GethDebugTracingOptions,
    GethTrace, U256,
};
use rundler_provider::{Provider, SimulationProvider};
use rundler_types::{v0_7::UserOperation, Opcode};
use serde::Deserialize;

use crate::{simulation::context::ContractInfo, ExpectedStorage};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub(super) struct TracerOutput {
    pub(super) calls_from_entry_point: Vec<TopLevelCallInfo>,
    pub(super) keccak: Vec<String>,
    pub(super) calls: Vec<CallInfo>,
    pub(super) expected_storage: ExpectedStorage,
    pub(super) logs: Vec<LogInfo>,
    pub(super) debug: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TopLevelCallInfo {
    pub(super) top_level_method_sig: String,
    pub(super) top_level_target_address: String,
    pub(super) opcodes: HashMap<Opcode, u64>,
    pub(super) access: HashMap<Address, AccessInfo>,
    pub(super) contract_info: HashMap<Address, ContractInfo>,
    pub(super) ext_code_access_info: HashMap<Address, Opcode>,
    pub(super) oog: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AccessInfo {
    pub(super) reads: HashMap<U256, U256>,
    pub(super) writes: HashMap<U256, u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub(super) enum CallInfo {
    Exit(ExitInfo),
    Method(MethodInfo),
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct ExitInfo {
    #[serde(rename = "type")]
    pub(super) exit_type: ExitType,
    #[serde(rename = "gasUsed")]
    pub(super) gas_used: u64,
    pub(super) data: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(super) enum ExitType {
    Return,
    Revert,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct MethodInfo {
    #[serde(rename = "type")]
    pub(super) method_type: Opcode,
    pub(super) from: Address,
    pub(super) to: Address,
    pub(super) method: String,
    pub(super) value: Option<U256>,
    pub(super) gas: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub(super) struct LogInfo {
    pub(super) topics: Vec<String>,
    pub(super) data: String,
}

impl TryFrom<GethTrace> for TracerOutput {
    type Error = anyhow::Error;
    fn try_from(trace: GethTrace) -> Result<Self, Self::Error> {
        match trace {
            GethTrace::Unknown(value) => Ok(TracerOutput::deserialize(&value)?),
            GethTrace::Known(_) => {
                bail!("Failed to deserialize simulation trace")
            }
        }
    }
}

/// Trait for tracing the simulation of a user operation.
#[async_trait]
pub(super) trait SimulateValidationTracer: Send + Sync + 'static {
    /// Traces the simulation of a user operation.
    async fn trace_simulate_validation(
        &self,
        op: UserOperation,
        block_id: BlockId,
    ) -> anyhow::Result<TracerOutput>;
}

/// Tracer implementation for the bundler's custom tracer.
#[derive(Debug)]
pub(crate) struct SimulateValidationTracerImpl<P, E> {
    provider: Arc<P>,
    entry_point: E,
    max_validation_gas: u64,
    tracer_timeout: String,
}

/// Runs the bundler's custom tracer on the entry point's `simulateValidation`
/// method for the provided user operation.

#[async_trait]
impl<P, E> SimulateValidationTracer for SimulateValidationTracerImpl<P, E>
where
    P: Provider,
    E: SimulationProvider<UO = UserOperation>,
{
    async fn trace_simulate_validation(
        &self,
        op: UserOperation,
        block_id: BlockId,
    ) -> anyhow::Result<TracerOutput> {
        let (tx, state_override) = self
            .entry_point
            .get_tracer_simulate_validation_call(op, self.max_validation_gas);

        let out = self
            .provider
            .debug_trace_call(
                tx,
                Some(block_id),
                GethDebugTracingCallOptions {
                    tracing_options: GethDebugTracingOptions {
                        tracer: Some(GethDebugTracerType::JsTracer(
                            validation_tracer_js().to_string(),
                        )),
                        timeout: Some(self.tracer_timeout.clone()),
                        ..Default::default()
                    },
                    state_overrides: Some(state_override),
                },
            )
            .await?;

        TracerOutput::try_from(out)
    }
}

impl<P, E> SimulateValidationTracerImpl<P, E> {
    /// Creates a new instance of the bundler's custom tracer.
    pub(crate) fn new(
        provider: Arc<P>,
        entry_point: E,
        max_validation_gas: u64,
        tracer_timeout: String,
    ) -> Self {
        Self {
            provider,
            entry_point,
            max_validation_gas,
            tracer_timeout,
        }
    }
}

fn validation_tracer_js() -> &'static str {
    include_str!("../../../tracer/dist/validationTracerV0_7.js").trim_end_matches(";export{};")
}
