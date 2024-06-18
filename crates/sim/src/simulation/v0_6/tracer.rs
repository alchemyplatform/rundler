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

use std::{convert::TryFrom, fmt::Debug, sync::Arc};

use anyhow::bail;
use async_trait::async_trait;
use ethers::types::{
    BlockId, GethDebugTracerType, GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace,
};
use rundler_provider::{Provider, SimulationProvider};
use rundler_types::v0_6::UserOperation;
use serde::Deserialize;

use crate::simulation::context::TracerOutput;

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

        TracerOutput::try_from(
            self.provider
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
                .await?,
        )
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
    include_str!("../../../tracer/dist/validationTracerV0_6.js").trim_end_matches(";export{};")
}
