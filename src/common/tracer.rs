use crate::common::contracts::entry_point::EntryPoint;
use crate::common::types::UserOperation;
use anyhow::Context;
use ethers::providers::{JsonRpcClient, Middleware, Provider};
use ethers::types::transaction::eip2718::TypedTransaction;
use serde_json::Value;

pub async fn trace_op_validation(
    entry_point: &EntryPoint<impl Middleware>,
    op: UserOperation,
) -> anyhow::Result<Value> {
    let tx = entry_point.simulate_validation(op).tx;
    bundler_trace_call(entry_point.client().provider(), tx).await
}

async fn bundler_trace_call(
    provider: &Provider<impl JsonRpcClient>,
    tx: TypedTransaction,
) -> anyhow::Result<Value> {
    let out = provider
        .request(
            "debug_traceCall",
            (tx, "latest", serde_json::json!({ "tracer": tracer_js() })),
        )
        .await
        .context("failed to run bundler trace")?;
    Ok(out)
}

fn tracer_js() -> &'static str {
    include_str!("../../tracer/dist/index.js").trim_end_matches(";\n")
}
