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

//! E7: state-heavy ops bundled alone above the 2^24 cap (EntryPoint v0.6 or v0.7).
//!
//! Each op deploys a contract of `size` bytes from its execution phase (`ExecAccount.execute` ->
//! `BlobDeployer.deploy`), which costs far more EIP-8037 state gas than fits under 2^24 for large
//! sizes. The op is measured with reth's `stateGasTracer` (tx-level net state gas `S` of the real
//! `handleOps([op])`), then sent alone with `tx.gas = 2^24 + R`, which gives it a state-gas
//! reservoir of exactly `R`. State paid from the reservoir is invisible to `gasleft()`, so the
//! EntryPoint does not charge it; the op carries `S` in `preVerificationGas` instead.
//!
//! Variants per size:
//! - **exact**: `R = S`, `PVG = base + S`. The proposed design.
//! - **under**: `R = S - spill`. The last `spill` of state falls through to `gas_left` of the
//!   deploying frame, where the EntryPoint meters it (bounded by `callGasLimit`).
//! - **over**: `R = S + extra`. The unused reservoir should be refunded to the bundler.
//! - **bso**: fees and PVG 0, `R = S`, as a bundler-sponsored op (billed offchain).
//! - **capped**: `R = 0` (today's 2^24 cap) with the same limits, as the control.
//!
//! Traces cannot see a reservoir: reth's `debug_traceCall` (like `eth_call`) gives the whole call
//! gas to `gas_left`, so in a trace state gas is metered and bounded by the op's limits. `S` is
//! therefore measured on a probe op whose `callGasLimit` covers execution and state, and the op
//! that is sent gets a `callGasLimit` for execution only.
//!
//! Plus two direct transactions per size (no EntryPoint), to check the reservoir and the tracer
//! in isolation: `BlobDeployer.deploy` and `BlobDeployer.deployThenRevert` (state created then
//! rolled back by a top-level revert), both with `tx.gas = 2^24 + S_direct`.

use alloy_network::TransactionBuilder;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{SolCall, SolEvent, SolValue};
use anyhow::bail;
use rundler_contracts::v0_7::{
    ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE, IEntryPoint, IEntryPointSimulations,
};
use rundler_types::{
    EntryPointVersion, PvgState, UserOperation as _, UserOperationVariant, chain::ChainSpec,
    v0_6 as uo_v0_6, v0_7 as uo_v0_7,
};
use serde::Serialize;
use serde_json::json;

use crate::{
    bundle::{handle_ops_calldata, pseudo_random_bytes},
    contracts::{BlobDeployer, ExecAccount, ExecAccountV06, INonceManagerLite},
    fixtures::{self, EpVersion, Fixtures},
    harness::{Harness, OP_PRIORITY_FEE, StateGasTrace, TX_GAS_CAP, TxOutcome},
};

/// Verification gas limit. The account is deployed and prefunded, so validation is cheap; the
/// first op's nonce write is state gas and comes from the reservoir.
const VERIFICATION_GAS_LIMIT: u128 = 300_000;
/// Slack over the execution gas derived from the probe, for validation-phase state that the
/// derivation subtracts from the execute frame (at most one new nonce slot, 97,920).
const CALL_GAS_SLACK: u128 = 100_000;
/// State gas the **under** variant leaves out of the reservoir.
const UNDER_SPILL: u64 = 200_000;
/// Extra reservoir the **over** variant adds.
const OVER_EXTRA: u64 = 2_000_000;
/// EIP-8037 state gas per byte of deployed code.
const CODE_DEPOSIT_STATE_GAS_PER_BYTE: u64 = 1_530;
/// EIP-8037 state gas for creating a new account.
const NEW_ACCOUNT_STATE_GAS: u64 = 183_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Variant {
    Exact,
    Under,
    Over,
    Bso,
    Capped,
}

const VARIANTS: [Variant; 5] = [
    Variant::Exact,
    Variant::Under,
    Variant::Over,
    Variant::Bso,
    Variant::Capped,
];

impl Variant {
    fn reservoir(self, state_gas: u64) -> u64 {
        match self {
            Variant::Exact | Variant::Bso => state_gas,
            Variant::Under => state_gas.saturating_sub(UNDER_SPILL),
            Variant::Over => state_gas + OVER_EXTRA,
            Variant::Capped => 0,
        }
    }
}

/// What the callTracer saw for one traced `handleOps`.
#[derive(Debug, Clone, Serialize)]
struct CallTraceSummary {
    /// Top-level error, if the call reverted.
    error: Option<String>,
    /// Execution gas used by the account's `execute` frame (state from the reservoir excluded).
    execute_gas_used: Option<u64>,
    /// `UserOperationEvent.success` of the op.
    op_success: Option<bool>,
    /// Whether `BlobDeployer.Deployed` was emitted.
    deployed: bool,
    /// Root-frame fields beyond the standard callTracer ones (e.g. execution-apis#852's
    /// `stateGasUsed`), if the client reports any.
    root_extra: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
struct OpCase {
    size: usize,
    variant: Variant,
    call_gas_limit: u128,
    /// Rundler's required PVG for this op alone, without state gas (Glamsterdam schedule).
    base_pvg: u128,
    pre_verification_gas: u128,
    max_fee_per_gas: u128,
    /// callTracer of the probe: the real `handleOps` with `callGasLimit` = half the trace gas.
    probe: CallTraceSummary,
    /// `stateGasTracer` on the probe (the real `handleOps([op])`, with the probe's limits).
    handle_ops_trace: StateGasTrace,
    /// `stateGasTracer` on `EntryPointSimulations.simulateHandleOp(probe op)` (v0.7 only), as
    /// rundler would trace it during estimation.
    simulation_trace: Option<StateGasTrace>,
    /// `size * 1,530 + 183,600`: code deposit plus the new account.
    composed_state_gas: u64,
    reservoir: u64,
    /// The bundle transaction's outcome (`tx.gas = 2^24 + reservoir`).
    tx: Option<TxOutcome>,
    op_success: Option<bool>,
    deployed: Option<bool>,
    actual_gas_used: Option<u128>,
    actual_gas_cost: Option<U256>,
    /// `actualGasUsed - preVerificationGas`: what the EntryPoint metered (v0.7: incl. penalty).
    metered_gas: Option<i128>,
    /// `receipt.gasUsed - metered_gas`: what PVG has to cover.
    unmetered_gas: Option<i128>,
    /// `actualGasUsed - receipt.gasUsed`, in gas: >= 0 when the op paid for all the gas the
    /// bundler spent (at equal prices).
    gas_margin: Option<i128>,
    /// `actualGasCost - receipt.gasUsed * effectiveGasPrice`, in wei.
    wei_margin: Option<i128>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DirectCase {
    size: usize,
    name: &'static str,
    trace: Option<StateGasTrace>,
    gas_limit: u64,
    tx: Option<TxOutcome>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    experiment: &'static str,
    fixtures: Fixtures,
    account: Address,
    deployer: Address,
    trace_gas: u64,
    ops: Vec<OpCase>,
    direct: Vec<DirectCase>,
}

struct Ctx<'a> {
    harness: &'a Harness,
    fixtures: &'a Fixtures,
    spec: &'a ChainSpec,
    account: Address,
    deployer: Address,
    trace_gas: u64,
}

pub async fn run(
    harness: &Harness,
    fixtures: &Fixtures,
    spec: &ChainSpec,
    sizes: &[usize],
    trace_gas: Option<u64>,
) -> anyhow::Result<Report> {
    let deployer = harness
        .ensure_create2(B256::ZERO, &BlobDeployer::BYTECODE)
        .await?;
    let account_code = match fixtures.entry_point_version {
        EpVersion::V0_6 => &ExecAccountV06::BYTECODE,
        EpVersion::V0_7 => &ExecAccount::BYTECODE,
    };
    let mut init_code = account_code.to_vec();
    init_code.extend_from_slice(&fixtures.entry_point.abi_encode());
    let account = harness
        .ensure_create2(B256::ZERO, &Bytes::from(init_code))
        .await?;
    let trace_gas = match trace_gas {
        Some(gas) => gas,
        None => harness.chain_info().await?.block_gas_limit,
    };
    eprintln!("account {account}, deployer {deployer}, trace gas {trace_gas}");

    let ctx = Ctx {
        harness,
        fixtures,
        spec,
        account,
        deployer,
        trace_gas,
    };
    let mut ops = Vec::new();
    let mut direct = Vec::new();
    for &size in sizes {
        direct.extend(direct_cases(&ctx, size).await);
        for variant in VARIANTS {
            let case = op_case(&ctx, size, variant).await?;
            eprintln!(
                "size={size:>6} {:<7} S={:>9} sim={:>9} composed={:>9} R={:>9} gas_used={:>9} op_ok={:?} deployed={:?} unmetered={:?} gas_margin={:?}{}",
                format!("{variant:?}").to_lowercase(),
                case.handle_ops_trace.state_gas_used,
                case.simulation_trace
                    .as_ref()
                    .map(|t| t.state_gas_used.to_string())
                    .unwrap_or_else(|| "-".into()),
                case.composed_state_gas,
                case.reservoir,
                case.tx.as_ref().map(|t| t.gas_used).unwrap_or_default(),
                case.op_success,
                case.deployed,
                case.unmetered_gas,
                case.gas_margin,
                case.error
                    .as_ref()
                    .map(|e| format!(" ERROR {e}"))
                    .unwrap_or_default(),
            );
            ops.push(case);
        }
    }
    Ok(Report {
        experiment: "e7-isolated-state",
        fixtures: fixtures.clone(),
        account,
        deployer,
        trace_gas,
        ops,
        direct,
    })
}

async fn op_case(ctx: &Ctx<'_>, size: usize, variant: Variant) -> anyhow::Result<OpCase> {
    let harness = ctx.harness;
    let nonce = account_nonce(ctx).await?;
    let call_data = deploy_call_data(ctx.deployer, size);
    let max_fee = match variant {
        Variant::Bso => 0,
        _ => harness.default_max_fee().await?,
    };
    let priority_fee = if variant == Variant::Bso {
        0
    } else {
        OP_PRIORITY_FEE
    };
    let build = |cgl: u128, pvg: u128| {
        build_op(
            ctx,
            nonce,
            call_data.clone(),
            cgl,
            pvg,
            max_fee,
            priority_fee,
        )
    };
    let pvg_state = PvgState {
        sender_deposit_is_zero: Some(false),
        authority: None,
    };
    let base_pvg = |uo: &UserOperationVariant| {
        uo.required_pre_verification_gas(ctx.spec, 1, 0, None, &pvg_state)
    };

    // `debug_traceCall` gives the whole call gas to `gas_left` and leaves the reservoir empty
    // (no 2^24 split, as for eth_call), so in a trace every state charge is metered and bounded
    // by the op's limits. The probe therefore gets a callGasLimit covering execution *and* state.
    let probe_call_gas_limit = u128::from(ctx.trace_gas / 2);

    // Fund the deposit for the probe's prefund (the largest of the case) before tracing, so
    // validation never needs `missingAccountFunds` (AA21 otherwise).
    let composed_state_gas = size as u64 * CODE_DEPOSIT_STATE_GAS_PER_BYTE + NEW_ACCOUNT_STATE_GAS;
    let probe_op = build(probe_call_gas_limit, u128::from(composed_state_gas) * 2);
    ensure_deposit(ctx, probe_op.max_gas_cost()).await?;

    // 1. Probe with the real handleOps: `S` (tx-level net state gas) from stateGasTracer, and
    //    the execute frame's gas (execution + its state) from callTracer.
    let probe_op = build(probe_call_gas_limit, base_pvg(&probe_op));
    let probe_request = handle_ops_request(ctx, &probe_op, ctx.trace_gas);
    let probe_trace = harness.trace_calls(&probe_request, None).await?;
    if let Ok(path) = std::env::var("PVG_DUMP_TRACE") {
        std::fs::write(path, serde_json::to_string_pretty(&probe_trace)?)?;
    }
    let probe = summarize_calls(&probe_trace, ctx.account);
    let Some(execute_gas) = probe.execute_gas_used else {
        bail!("probe trace has no execute frame: {probe:?}");
    };
    if probe.op_success != Some(true) || !probe.deployed {
        bail!("probe op did not deploy (size {size}): {probe:?}");
    }
    let trace = harness.trace_state_gas(&probe_request, None).await?;
    let simulation_trace = match ctx.fixtures.entry_point_version {
        EpVersion::V0_7 => Some(trace_simulate_handle_op(ctx, &probe_op).await?),
        EpVersion::V0_6 => None,
    };

    // 2. callGasLimit for the real send, where the reservoir pays the state: the execute frame's
    //    gas minus S (S also holds validation-phase state, hence the slack), plus 10% (plus the
    //    spill for the under variant).
    let execution_gas = u128::from(execute_gas.saturating_sub(trace.state_gas_used));
    let mut call_gas_limit = (execution_gas + CALL_GAS_SLACK) * 11 / 10;
    if variant == Variant::Under {
        call_gas_limit += u128::from(UNDER_SPILL) * 11 / 10;
    }

    // 3. PVG = base + S (twice: PVG's own bytes move `base`). State does not depend on the
    //    limits, so the probe's S stands for the real op.
    let mut op = build(call_gas_limit, 0);
    let mut pvg = 0;
    for _ in 0..2 {
        pvg = if variant == Variant::Bso {
            0
        } else {
            base_pvg(&op) + u128::from(trace.state_gas_used)
        };
        op = build(call_gas_limit, pvg);
    }
    let base = base_pvg(&op);

    let reservoir = variant.reservoir(trace.state_gas_used);
    let mut case = OpCase {
        size,
        variant,
        call_gas_limit,
        base_pvg: base,
        pre_verification_gas: pvg,
        max_fee_per_gas: max_fee,
        probe,
        handle_ops_trace: trace,
        simulation_trace,
        composed_state_gas,
        reservoir,
        tx: None,
        op_success: None,
        deployed: None,
        actual_gas_used: None,
        actual_gas_cost: None,
        metered_gas: None,
        unmetered_gas: None,
        gas_margin: None,
        wei_margin: None,
        error: None,
    };

    // 4. Send it alone with tx.gas = 2^24 + R.
    ensure_deposit(ctx, op.max_gas_cost()).await?;
    let request = TransactionRequest::default()
        .with_to(ctx.fixtures.entry_point)
        .with_input(handle_ops_calldata(
            std::slice::from_ref(&op),
            harness.sender,
        ));
    let mut tx = match harness
        .send_with_gas_limit(request, TX_GAS_CAP + reservoir)
        .await
    {
        Ok(tx) => tx,
        Err(e) => {
            case.error = Some(format!("{e:#}"));
            return Ok(case);
        }
    };
    let (event, deployed) = decode_logs(ctx, &tx);
    case.deployed = Some(deployed);
    if let Some(event) = event {
        let actual_gas_used = event.actualGasUsed.to::<u128>();
        tx.account_for_inflow(event.actualGasCost);
        let metered = actual_gas_used as i128 - pvg as i128;
        let cost = U256::from(tx.gas_used) * U256::from(tx.effective_gas_price);
        case.op_success = Some(event.success);
        case.actual_gas_used = Some(actual_gas_used);
        case.actual_gas_cost = Some(event.actualGasCost);
        case.metered_gas = Some(metered);
        case.unmetered_gas = Some(tx.gas_used as i128 - metered);
        case.gas_margin = Some(actual_gas_used as i128 - tx.gas_used as i128);
        case.wei_margin = Some(
            i128::try_from(event.actualGasCost).unwrap_or(i128::MAX)
                - i128::try_from(cost).unwrap_or(i128::MAX),
        );
    } else if !tx.success {
        case.error = Some(format!("bundle reverted: {}", tx.tx_hash));
    }
    case.tx = Some(tx);
    Ok(case)
}

/// `BlobDeployer.deploy` and `deployThenRevert` sent directly from the harness EOA with a
/// reservoir sized from the tracer.
async fn direct_cases(ctx: &Ctx<'_>, size: usize) -> Vec<DirectCase> {
    let mut cases = Vec::new();
    let deploy = |revert: bool| {
        let salt = B256::random();
        let size = U256::from(size);
        let input: Bytes = if revert {
            BlobDeployer::deployThenRevertCall { salt, size }
                .abi_encode()
                .into()
        } else {
            BlobDeployer::deployCall { salt, size }.abi_encode().into()
        };
        TransactionRequest::default()
            .with_to(ctx.deployer)
            .with_input(input)
    };

    // Size the reservoir from the non-reverting deploy; the reverting one creates the same
    // state before it reverts.
    let deploy_trace = ctx
        .harness
        .trace_state_gas(&deploy(false).with_gas_limit(ctx.trace_gas), None)
        .await;
    let state_gas = deploy_trace.as_ref().map(|t| t.state_gas_used).unwrap_or(0);
    let gas_limit = TX_GAS_CAP + state_gas;
    for (name, revert) in [("deploy", false), ("deploy-then-revert", true)] {
        let trace = if revert {
            ctx.harness
                .trace_state_gas(&deploy(true).with_gas_limit(ctx.trace_gas), None)
                .await
        } else {
            deploy_trace
                .as_ref()
                .map(Clone::clone)
                .map_err(|e| anyhow::anyhow!("{e:#}"))
        };
        let mut case = DirectCase {
            size,
            name,
            trace: None,
            gas_limit,
            tx: None,
            error: None,
        };
        match trace {
            Ok(t) => case.trace = Some(t),
            Err(e) => case.error = Some(format!("trace: {e:#}")),
        }
        match ctx
            .harness
            .send_with_gas_limit(deploy(revert), gas_limit)
            .await
        {
            Ok(tx) => case.tx = Some(tx),
            Err(e) => case.error = Some(format!("send: {e:#}")),
        }
        eprintln!(
            "size={size:>6} direct {name:<19} trace={:?} gas_limit={gas_limit} gas_used={:?} success={:?}{}",
            case.trace
                .as_ref()
                .map(|t| (t.execution_gas_used, t.state_gas_used)),
            case.tx.as_ref().map(|t| t.gas_used),
            case.tx.as_ref().map(|t| t.success),
            case.error
                .as_ref()
                .map(|e| format!(" ERROR {e}"))
                .unwrap_or_default(),
        );
        cases.push(case);
    }
    cases
}

fn deploy_call_data(deployer: Address, size: usize) -> Bytes {
    ExecAccount::executeCall {
        target: deployer,
        value: U256::ZERO,
        data: BlobDeployer::deployCall {
            salt: B256::random(),
            size: U256::from(size),
        }
        .abi_encode()
        .into(),
    }
    .abi_encode()
    .into()
}

fn build_op(
    ctx: &Ctx<'_>,
    nonce: U256,
    call_data: Bytes,
    call_gas_limit: u128,
    pre_verification_gas: u128,
    max_fee: u128,
    priority_fee: u128,
) -> UserOperationVariant {
    let signature = pseudo_random_bytes(65);
    match ctx.fixtures.entry_point_version {
        EpVersion::V0_6 => uo_v0_6::UserOperationBuilder::new(
            ctx.spec,
            uo_v0_6::UserOperationRequiredFields {
                sender: ctx.account,
                nonce,
                init_code: Bytes::new(),
                call_data,
                call_gas_limit,
                verification_gas_limit: VERIFICATION_GAS_LIMIT,
                pre_verification_gas,
                max_fee_per_gas: max_fee,
                max_priority_fee_per_gas: priority_fee,
                paymaster_and_data: Bytes::new(),
                signature,
            },
        )
        .build()
        .into(),
        EpVersion::V0_7 => uo_v0_7::UserOperationBuilder::new(
            ctx.spec,
            EntryPointVersion::V0_7,
            uo_v0_7::UserOperationRequiredFields {
                sender: ctx.account,
                nonce,
                call_data,
                call_gas_limit,
                verification_gas_limit: VERIFICATION_GAS_LIMIT,
                pre_verification_gas,
                max_priority_fee_per_gas: priority_fee,
                max_fee_per_gas: max_fee,
                signature,
            },
        )
        .build()
        .into(),
    }
}

fn handle_ops_request(ctx: &Ctx<'_>, op: &UserOperationVariant, gas: u64) -> TransactionRequest {
    TransactionRequest::default()
        .with_from(ctx.harness.sender)
        .with_to(ctx.fixtures.entry_point)
        .with_input(handle_ops_calldata(
            std::slice::from_ref(op),
            ctx.harness.sender,
        ))
        .with_gas_limit(gas)
}

/// `simulateHandleOp(op, 0, "")` on the EntryPoint address with its code replaced by
/// `EntryPointSimulations`, as rundler simulates v0.7 ops.
async fn trace_simulate_handle_op(
    ctx: &Ctx<'_>,
    op: &UserOperationVariant,
) -> anyhow::Result<StateGasTrace> {
    let packed = uo_v0_7::UserOperation::from(op.clone()).pack();
    let input = IEntryPointSimulations::simulateHandleOpCall {
        op: packed,
        target: Address::ZERO,
        targetCallData: Bytes::new(),
    }
    .abi_encode();
    let request = TransactionRequest::default()
        .with_from(Address::random())
        .with_to(ctx.fixtures.entry_point)
        .with_input(input)
        .with_gas_limit(ctx.trace_gas);
    let overrides = json!({
        ctx.fixtures.entry_point.to_string(): { "code": ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE.to_string() }
    });
    ctx.harness
        .trace_state_gas(&request, Some(&overrides))
        .await
}

async fn account_nonce(ctx: &Ctx<'_>) -> anyhow::Result<U256> {
    let ret = ctx
        .harness
        .provider
        .call(
            TransactionRequest::default()
                .with_to(ctx.fixtures.entry_point)
                .with_input(
                    INonceManagerLite::getNonceCall {
                        sender: ctx.account,
                        key: Default::default(),
                    }
                    .abi_encode(),
                ),
        )
        .await?;
    Ok(INonceManagerLite::getNonceCall::abi_decode_returns(&ret)?)
}

/// Keeps the account's EntryPoint deposit at least twice the prefund, so it never pays
/// `missingAccountFunds` and its deposit slot never goes to zero.
async fn ensure_deposit(ctx: &Ctx<'_>, prefund: U256) -> anyhow::Result<()> {
    let ep = ctx.fixtures.entry_point;
    let deposit = fixtures::deposit_of(ctx.harness, ep, ctx.account).await?;
    let target = prefund * U256::from(2) + U256::from(1);
    if deposit < target {
        fixtures::deposit_to(
            ctx.harness,
            ep,
            ctx.account,
            target * U256::from(2) - deposit,
        )
        .await?;
    }
    Ok(())
}

/// The op's UserOperationEvent and whether `BlobDeployer.Deployed` was emitted.
fn decode_logs(ctx: &Ctx<'_>, tx: &TxOutcome) -> (Option<IEntryPoint::UserOperationEvent>, bool) {
    let mut event = None;
    let mut deployed = false;
    for log in &tx.logs {
        let topic0 = log.topic0().copied();
        if log.address() == ctx.fixtures.entry_point
            && topic0 == Some(IEntryPoint::UserOperationEvent::SIGNATURE_HASH)
        {
            event = log
                .log_decode::<IEntryPoint::UserOperationEvent>()
                .ok()
                .map(|l| l.inner.data);
        } else if log.address() == ctx.deployer
            && topic0 == Some(BlobDeployer::Deployed::SIGNATURE_HASH)
        {
            deployed = true;
        }
    }
    (event, deployed)
}

fn summarize_calls(trace: &serde_json::Value, account: Address) -> CallTraceSummary {
    const STANDARD: [&str; 12] = [
        "from",
        "gas",
        "gasUsed",
        "to",
        "input",
        "output",
        "error",
        "revertReason",
        "calls",
        "logs",
        "value",
        "type",
    ];
    let mut summary = CallTraceSummary {
        error: trace.get("error").and_then(|e| e.as_str()).map(|e| {
            let output = trace
                .get("output")
                .and_then(|o| o.as_str())
                .unwrap_or_default();
            format!("{e} {output}")
        }),
        execute_gas_used: None,
        op_success: None,
        deployed: false,
        root_extra: serde_json::Value::Object(
            trace
                .as_object()
                .map(|o| {
                    o.iter()
                        .filter(|(k, _)| !STANDARD.contains(&k.as_str()))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default(),
        ),
    };
    let execute_selector = format!(
        "0x{}",
        alloy_primitives::hex::encode(ExecAccount::executeCall::SELECTOR)
    );
    let uo_event_topic = IEntryPoint::UserOperationEvent::SIGNATURE_HASH.to_string();
    let deployed_topic = BlobDeployer::Deployed::SIGNATURE_HASH.to_string();
    let account = account.to_string().to_lowercase();

    let mut stack = vec![trace];
    while let Some(frame) = stack.pop() {
        let to = frame.get("to").and_then(|v| v.as_str()).unwrap_or_default();
        let input = frame
            .get("input")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if to.to_lowercase() == account && input.starts_with(&execute_selector) {
            summary.execute_gas_used = frame
                .get("gasUsed")
                .and_then(|v| v.as_str())
                .and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok());
        }
        for log in frame
            .get("logs")
            .and_then(|l| l.as_array())
            .into_iter()
            .flatten()
        {
            let topic0 = log
                .get("topics")
                .and_then(|t| t.get(0))
                .and_then(|t| t.as_str())
                .unwrap_or_default();
            if topic0 == uo_event_topic {
                // data = nonce | success | actualGasCost | actualGasUsed
                let data = log.get("data").and_then(|d| d.as_str()).unwrap_or_default();
                let data = data.trim_start_matches("0x");
                summary.op_success = data.get(64..128).map(|w| w.trim_start_matches('0') == "1");
            } else if topic0 == deployed_topic {
                summary.deployed = true;
            }
        }
        stack.extend(
            frame
                .get("calls")
                .and_then(|c| c.as_array())
                .into_iter()
                .flatten(),
        );
    }
    summary
}
