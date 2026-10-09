# Plan: isolated "state-heavy" user ops on Glamsterdam (tx.gas > 2^24)

> **Status (2026-10-09):** Phase 0 (harness experiment E7) is done on Sepolia for v0.6 and v0.7; see [Phase 0 results](#phase-0-results-sepolia-2026-10-09). Later phases are a proposal, amended by those results.
>
> - **Network:** Sepolia only. It already runs Glamsterdam; the devnet is no longer used.
> - **Guard:** not decided. It could be per request (an HTTP header or param), a ChainSpec flag, or both. Settle this before Phase 1. Below, "the flag" means whichever guard is chosen.

## Phase 0 results (Sepolia, 2026-10-09)

Setup: Sepolia RPC on reth v2.7.0, block gas limit 200M, base fee about 15 wei.

Reports:
- `results/e7-v0.7-sepolia-11155111-1791545919.json`
- `results/e7-v0.6-sepolia-11155111-1791546950.json`, plus `…-1791547058.json`, which re-runs 4 kB after a nonce race

Each op deploys a contract of 4 / 16 / 24 kB from its execution phase.

| | 4 kB | 16 kB | 24 kB (EIP-170 max) |
| --- | --- | --- | --- |
| `S`, real `handleOps`, `stateGasTracer` | 6,450,480 | 25,251,120 | 37,784,880 |
| composed `size × 1,530 + 183,600` | 6,450,480 | 25,251,120 | 37,784,880 |
| `tx.gas` for **exact** (`2^24 + S`) | 23.2M | 42.0M | 54.6M |
| **exact**: op ok, gas margin (v0.7 / v0.6) | ✓ +11,224 / −1,328 | ✓ +11,263 / −1,328 | ✓ +11,293 / −1,328 |
| **under** (`R = S − 200k`): gas margin | +213k / +199k | same | same |
| **over** (`R = S + 2M`): `gasUsed`, margin | same as exact | same | same |
| **bso** (fees 0, PVG 0): op ok, bundler pays | ✓ −6.47M | ✓ −25.3M | ✓ −37.8M |
| **capped** (`tx.gas = 2^24`) | op fails, nothing deployed | same | same |

Gas margin is `actualGasUsed − receipt.gasUsed`. It is ≥ 0 when the op paid for everything the bundler spent, at equal prices. The wei margin in the reports is negative only because the harness tips about 0.7 gwei while the op pays about 1,015 wei/gas.

Findings:

1. **The reservoir works onchain, on both EntryPoints, up to the 24 kB maximum.**
   - With `tx.gas = 2^24 + S` and an execution-only `callGasLimit`, the op deploys.
   - `PVG = base + S` pays the bundler back exactly: the margin is constant across sizes. On v0.7, the +11k is the 10% penalty on the harness's deliberate `callGasLimit` slack. On v0.6, the −1,328 is the known base-PVG gap that #1349 fixes, unrelated to state gas.
   - Sepolia accepted and mined transactions up to 56.6M gas.
2. **`S` is exactly the EIP-8037 arithmetic.** 1,530 per code byte, 183,600 per new account, and 97,920 for a new slot (the account's first nonce write). So `S` can be cross-checked offline.
3. **An undersized reservoir is safe; an oversized one is free.**
   - **under:** the missing state spills into the deploying frame's `gas_left`. There it is metered, so the user pays it twice: once in PVG and once in actual gas.
   - **over:** the unused reservoir is refunded to the transaction sender, so `gasUsed` is the same as **exact**.
   - So rundler should size `R = S` (not more). That caps how much state gas can stay hidden from the EntryPoint.
4. **A top-level revert charges no state gas.**
   - `deployThenRevert` with `tx.gas = 2^24 + S` used only execution gas: 30,919 at 4 kB, 37,799 at 24 kB.
   - A reverted isolated bundle therefore costs at most about 2^24 of execution gas.
   - `stateGasTracer` reports `stateGasUsed = 0` and **no error field** for a reverted call. It cannot tell a revert from "no state".
5. **Traces and calls have no reservoir (reth 2.7).**
   - `debug_traceCall`, like eth_call, gives the whole call gas to `gas_left`: inside a 200M trace, `innerHandleOp` was forwarded 196.7M. A state charge is therefore metered and bounded by the op's limits.
   - An op with an execution-only `callGasLimit` **fails** in a trace and in eth_call, even though it succeeds onchain.
   - This changes the plan:
     - **Measure `S` on a probe** whose limits cover execution plus state (E7 uses `callGasLimit` = half the trace gas).
     - **Split `S` by phase to get execution-only limits.** Subtract the state each phase charges from what that phase's estimate measured. reth reports state gas only on the root frame, so the split needs a separate trace of validation alone (`simulateValidation`).
     - **The pre-submit check must use the probe-shaped op.** Calling the real isolated op would show its execution failing.
     - **Drop the "pre-existing bug" in Phase 1.** On reth, a large `max_gas_estimation_gas` does not hide state gas: there is no reservoir in calls. It must still not undercount on clients that do apply the 2^24 split. Check that per client.
6. **Use `callTracer` rather than `stateGasTracer`.**
   - reth's `callTracer` root frame already carries `executionGasUsed`, `stateGasUsed` and `gasRefund` (inner frames carry none). It also reports the revert error and, with `withLog`, the `UserOperationEvent`.
   - So one trace gives `S`, the top-level revert, and whether the op succeeded.
7. **`eth_estimateGas` cannot size these bundles.** For the 24 kB bundle it returned 642,333 against 37.9M used: the cheapest run that doesn't revert is one where the op's execution quietly runs out of gas. `tx.gas` must come from the trace.
8. **`EntryPointSimulations.simulateHandleOp` (v0.7 state override) reports one slot (97,920) more than the real `handleOps`.** A plausible cause is that its storage layout puts a written slot, e.g. the reentrancy guard, where the canonical EntryPoint's storage is empty; I haven't checked. Either way the error is conservative for estimation. Subtract it, or trace a non-overridden path, if exactness matters.
9. **BSO works as is.** Fees 0 and PVG 0 give `actualGasCost = 0`, and the bundler pays `S` plus overhead. In a single-op bundle, the receipt's `gasUsed` × price is exactly the op's cost, so offchain billing can use it directly.
10. **Isolation-mode estimation works with no hand sizing.**
    - Variants **estimated** and **estimated-deploy**. Reports: `results/e7-v0.7-sepolia-est-11155111-1791548390.json` and `results/e7-v0.6-sepolia-est-11155111-1791548523.json`.
    - VGL and CGL are derived from simulation of the op with every limit at its maximum (fees 0, PVG 0), the way rundler estimates:
      - `S` = state gas of `handleOps([op])`.
      - `S_v` = the same with `callGasLimit = 0`: execution fails and its state rolls back, so what remains is the validation and EntryPoint state.
      - `S_c = S − S_v`.
      - `VGL = (simulated preOpGas − S_v + deposit_transfer_overhead) × 1.1`.
      - `CGL = (execute frame gasUsed − S_c) × 64/63 + 3,000`.
      - `PVG = base + S`, sent with `tx.gas = 2^24 + S`.
    - All 12 cases (4/16/24 kB × existing or `initCode`-deployed sender × v0.6/v0.7) succeeded.

    | | VGL (v0.7 / v0.6) | CGL | `S_v` | gas margin (v0.7 / v0.6) |
    | --- | --- | --- | --- | --- |
    | estimated, 4 / 16 / 24 kB | 59,378 / 59,063 | 22,330 / 26,328 / 29,319 | 0 | +364…+375 / −1,328 |
    | estimated-deploy, 4 / 16 / 24 kB | 88,387 / 87,771 | same | 1,650,870 | +379…+390 / −1,320 |

    - A v0.7 margin of about +370 means CGL is tight, so the unused-gas penalty is negligible. The v0.6 −1.3k is the #1349 PVG gap again.
    - `S_v` for a fresh sender is account creation + `ExecAccount` code + the first nonce write. It is subtracted from VGL correctly: VGL stays below 90k although validation creates 1.65M of state.
    - The first attempt hit **AA26** because it left out `deposit_transfer_overhead`. The simulation runs at fee 0, so the EntryPoint skips the deposit debit, and rundler adds that overhead for self-paying ops. It is needed here too.
    - CGL from the execute frame's `gasUsed` is tighter than a binary search would be. A binary search keeps the 1/64 of `S` withheld at each nested call, about 1.2M at 24 kB.
11. **Harness note.** A load-balanced RPC can return a stale pending nonce, which made the harness reuse a nonce: one case failed and an earlier run hung waiting for a receipt. The harness now tracks nonces locally and times out receipts after 3 minutes. A builder lane sending 50M-gas transactions should watch for the same problem.

## Context

Today every bundle stays at or below `TX_MAX_GAS_LIMIT` (2^24). That keeps the EIP-8037 state-gas reservoir empty, so the EntryPoint meters state gas as ordinary gas (see the report [The 2²⁴ Ceiling](https://claude.ai/code/artifact/86300a56-6234-4404-a759-92ba082407c5)). The cost is that any op whose state gas does not fit under about 0.9 × 2^24 is now impossible. A 24 kB contract deployment needs about 37.8M of state gas alone.

The admission check `TotalGasLimitTooHigh` (`crates/sim/src/precheck.rs:297-309`) rejects these ops, and so does estimation's `GasTotalTooLarge` (`crates/sim/src/estimation/v0_7.rs:223-236`).

**Goal:**
- Measure an op's tx-level state gas `S` with `debug_traceCall` and the `stateGasTracer`.
- Bundle that op **alone** with `tx.gas = 2^24 + S`, so the reservoir is exactly `S`.
- Get the bundler paid for `S` in one of two ways:
  - **Onchain:** `S` is added to PVG.
  - **BSO:** billed offchain; PVG must be 0 there.

Everything is gated behind a guard (still to be decided), and with the guard off rundler behaves exactly as today.

## Why it works (EIP-8037 facts this relies on)

- **Reservoir sizing.** The reservoir is `evm_gas − min(2^24 − intrinsic, evm_gas)`. So `tx.gas = 2^24 + R` gives a reservoir of exactly `R`, and the full 2^24 execution budget is unaffected.
- **Charges draw from the reservoir first, from any frame.** That includes the EntryPoint's own nonce and deposit writes.
  - `S` must therefore be the **tx-level** total, which is what `stateGasTracer` returns: `{gasUsed, executionGasUsed, stateGasUsed, gasRefund}` (reth 2.7).
  - Any state beyond `R` spills into `gas_left` of the charging frame. That spill is metered by `preGas − gasleft()` and bounded by VGL/CGL.
- **Bundler loss from hidden state is bounded.**
  - Hidden, unmetered state can never exceed `R`. Sizing `R` = measured `S`, and requiring the payment to cover `S`, means the bundler never under-recovers.
  - An unused reservoir is refunded to the tx sender: `tx_gas_used = tx.gas − gas_left − reservoir`.
- **A top-level revert or halt restores the state-gas baseline.** A reverted isolated bundle costs only execution gas (≤ 2^24 × price), the same risk class as today.
- **Putting `S` in PVG avoids the v0.7 10% unused-gas penalty.** That penalty applies only to CGL + postOp.
- **Single op means no cross-op wrap (shape A from the report).**
  - The cross-phase wrap shapes B and C remain.
  - On v0.7 they degrade to `PrefundTooLow`: the op fails, the bundle survives, and the bundler gets the full prefund, which already includes `S`.
  - On v0.6 they revert the bundle (AA51). The pre-submit check must catch them.
- **BSO bonus:** gas price is 0, so `actualGasCost = 0`. The prefund check can never fail, so the wrap cannot hurt a BSO bundle.

## What the tracer has to measure and how

- `stateGasUsed` is the **net** state gas of the whole call. If the top-level call reverts, it is rolled back to 0. So the traced call **must not revert**.
- **v0.7+:** trace `EntryPointSimulations.simulateHandleOp` (it returns normally) under the existing EP-code state override. Reuse the request construction in `simulate_handle_op_inner` (`crates/provider/src/alloy/entry_point/v0_7.rs:822-881`).
- **v0.6:** `simulateHandleOp` always reverts.
  - With a real signature (at admission and bundle time), trace the actual `handleOps([op], beneficiary)` instead.
  - For estimation with a dummy signature, add `EntryPointSimulationsV06` (the v0.6 EP with a returning `simulateHandleOp`) under `crates/contracts/contracts/v0_6/src/`. Treat v0.6 as a follow-up phase.
- **Tx gas for traced calls:** `2^24 + probe_reservoir`. Default about 40M, bounded by the node's `rpc.gascap`, which defaults to 50M on reth and geth, so it must be raised on our nodes.
- **Avoid double counting.**
  - Fees in the traced simulation are 0, so the deposit is untouched and the existing `state_pre_verification_gas` zero-deposit term (`crates/types/src/user_operation/mod.rs:464-470`) stays separate.
  - So `R = S_trace + state_pre_verification_gas`.
  - At bundle time, tracing the real `handleOps` returns the combined figure directly.

## Implementation

### Phase 0: Validate with the harness (no rundler changes)

Add experiment **E7 `isolated-state`** to `test/pvg-calibration/` (new `src/experiments/isolated_state.rs`, and a `Deployer` probe in `contracts/src/Probes.sol` that CREATE2-deploys N bytes).

Run it on Sepolia with reth 2.7, for v0.7 first and then v0.6:

1. Op: `ProbeAccount` executes a deploy of 8 / 16 / 24 kB.
2. Trace the simulation (v0.7) and the real `handleOps` with `stateGasTracer`. Compare `S` against the composed arithmetic: 1,530 per byte, 183,600 per account, 97,920 per slot.
3. Submit `handleOps` with `tx.gas = 2^24 + S` and `PVG = base + S`. Assert:
   - success
   - beneficiary gain ≥ receipt cost (margin)
   - `receipt.gasUsed ≈ Σ actualGasUsed − S_in_pvg + S`
4. Variants:
   - `R = S − δ`: the spill is metered and the op still succeeds if CGL has headroom.
   - `R = S + δ`: the unused reservoir is refunded to the sender.
   - Gas price 0 (BSO-like).
   - A forced validation failure: confirm a reverted tx is charged no state gas.
5. Check whether the Sepolia send path (our providers and relays) accepts `tx.gas > 2^24`, and what each node's `rpc.gascap` is.

The rest of the plan depends on what E7 shows, so it goes first.

### Phase 1: Shared plumbing (flag-guarded)

- **`crates/types/src/chain.rs`:**
  - Add `glamsterdam_isolated_state_gas_enabled: bool` (default false), `isolated_state_gas_max` (cap on `R`, at most the block state-gas limit minus 2^24), `isolated_state_gas_min` (classification threshold), and `tx_max_gas_limit` (2^24).
  - Expose them through one accessor, `isolated_state_gas_settings() -> Option<…>`, so call sites never branch on the flag.
- **Provider:**
  - Add `EvmProvider::trace_state_gas(tx, block, overrides) -> StateGasUsage` in `crates/provider/src/traits/evm.rs`, implemented in `alloy/evm.rs`.
  - Per Phase 0 finding 6, prefer `callTracer` (with `withLog`), whose root frame on reth carries `stateGasUsed` as well as the revert error and the op's event. `stateGasTracer` is the fallback; pass it as `GethDebugTracerType::JsTracer("stateGasTracer")` (serializes as the native name). Parse the raw JSON in both cases. `GethTrace` is untagged and could otherwise mis-deserialize.
  - Make the tracer name configurable, with a fallback to the `callTracer` root `stateGasUsed` from execution-apis#852 for non-reth clients.
- **Entry-point provider:**
  - Add `trace_state_gas_simulate_handle_op(op, reservoir)` (v0.7+) and `trace_state_gas_handle_ops(op, beneficiary, gas)` (all versions), next to `get_tracer_simulate_validation_call`.
- **~~Pre-existing bug to fix in the same phase~~ (superseded by Phase 0 finding 5: reth calls have no reservoir; re-check on other clients):**
  - `--max_gas_estimation_gas` defaults to 550M (`bin/rundler/src/cli/mod.rs:457-464`). Under Glamsterdam that gives a non-empty reservoir during capped estimation, so state gas silently drops out of the VGL/CGL estimates.
  - Clamp it to `transaction_gas_limit()` when the Glamsterdam schedule is active (in the ChainSpec accessor).

### Phase 2: Estimation (`crates/sim/src/estimation/v0_7.rs`, then `v0_6.rs`)

- **Amended by Phase 0 finding 10.** Run the state-gas trace (`callTracer` root `stateGasUsed`) alongside the normal searches. Decide the mode from `S`: if the capped totals including `S` exceed `max_bundle_execution_gas`, the op is isolated. A binary search hitting its max is ambiguous, so don't decide from that.
- **Isolated:** derive the limits as in finding 10. `S_v` comes from a `callGasLimit = 0` trace, or from tracing `simulateValidation` on v0.7. VGL is the searched value minus `S_v`, plus `deposit_transfer_overhead`, with the usual buffer. CGL is the execute frame's `gasUsed` minus `S_c`, × 64/63, plus 3,000 (not the binary-search result). PVG = base + `S`.
- Original text, superseded by the above: run the normal capped estimation first.
- If it fails with `GasTotalTooLarge`, or CGL/VGL hit their max, and the flag is on, re-run in **isolated mode**:
  - VGL/CGL binary searches with `max_gas_estimation_gas = 2^24 + probe_reservoir`. They then measure execution only.
  - In parallel, `trace_state_gas_simulate_handle_op` gives `S`.
  - Return `PVG = required_pvg (existing formula) + S`.
  - Add a non-standard optional field `stateGas: S` to the estimate response (`crates/rpc/src/eth/…` estimate types), so wallet-server can price BSO and size `max_cost`.
- Reject with a clear error if `S > isolated_state_gas_max`.

### Phase 3: Admission and pool

- **Classification.** An op is a candidate if either:
  - **BSO:** a new permission `isolated_state_gas: bool`, set by wallet-server through a header in `crates/rpc/src/types/permissions.rs` and plumbed through `permissions.rs`, `op_pool.proto` and `protos.rs`. Or:
  - **Onchain:** `PVG − capped_required_pvg ≥ isolated_state_gas_min`.
- **Confirming a candidate.** Trace the real `handleOps` to get `S`. The op is isolated only if `computation + S` would not fit the capped bundle. Then require:
  - **onchain:** `PVG ≥ capped_required_pvg + S`
  - **BSO:** `(bundle_gas_limit + S) × price ≤ max_cost` (extend `precheck.rs:322-325` and `pool.rs:659-668`)
- **Storage.** Store `isolated_state_gas: Option<u64>` on the pool op (`crates/types/src/pool/traits.rs`, proto).
- **Re-check.** Repeat the coverage check on the pool's PVG/cost re-check (`crates/pool/src/mempool/pool.rs:600-668`).
- **Limitation (documented):** the ERC-7562 validation simulation still runs capped (`max_verification_gas`). Only state-heavy **execution** is supported at first. A large initCode or factory state is not.

### Phase 4: Builder

- **Assigner (`crates/builder/src/assigner.rs`):** isolated ops always get a single-op `WorkAssignment`. Reuse the `is_isolation` path (`:506-560`, `:676-695`). Limit isolated bundles to one in flight per builder.
- **Proposer (`crates/builder/src/bundle_proposer.rs`):**
  - Re-trace the real `handleOps` at bundle time to get `S_b`.
  - Re-check coverage (PVG or `max_cost`); skip the op if it is no longer covered.
  - Set `tx.gas = tx_max_gas_limit + S_b`. Do not apply the 1.05 multiplier to the reservoir part, and assert that computation × 1.05 ≤ 2^24.
  - Feed `S_b` through the existing per-op `state_gas` path (`get_bundle_gas_limit_inner`, `:2195-2258`) instead of a new one.
  - **Re-enable the pre-submit check** for isolated single-op bundles. It is currently skipped for v0.7 single-op bundles (`:1318-1325`). Use the trace's own error, or `call_handle_ops` with the same `tx.gas`. On v0.6 this is the AA51 wrap guard.
  - Treat AA51/AA95 from an isolated op as a hard reject, not a retry.
- **Tracker:** fee bumps keep the same `tx.gas`. Bundle metrics record `S_b`, receipt `gasUsed` and margin.

### Phase 5: Docs and metrics

- Update `docs/architecture/glamsterdam_pvg.md`.
- Add metrics: isolated ops admitted, bundled and reverted; `S_estimate` vs `S_b` vs receipt-derived state gas; bundler margin per isolated bundle.

## Recommended order

Phase 0, then 1, then a BSO-only rollout of phases 2–4 (explicit permission, gas price 0, no wrap risk, exact offchain billing from the single-op receipt), then the onchain PVG-surplus classification. v0.6 estimation (`EntryPointSimulationsV06`) comes last.

## Open risks to settle in E7

- Does reth's `stateGasTracer` report a revert or error, or only `stateGasUsed = 0`? Is there an equivalent on the clients we run elsewhere?
- What are the node `rpc.gascap` values? Does the transaction submission path accept `tx.gas > 2^24`?
- Block admission needs `execution_gas_available ≥ 2^24` and `state_gas_available ≥ tx.gas`. How long do large isolated txs wait for inclusion?
- Net vs peak state: if an op allocates and then refills, a reservoir sized at net can spill at the peak. That spill is metered, so it is safe, but it may push the op over CGL.

## Verification

- Unit tests:
  - ChainSpec accessor with the flag on and off (off gives identical results).
  - The `tx.gas = 2^24 + S` formula.
  - Classification and coverage checks (onchain and BSO).
  - Estimation fallback with mocked `trace_state_gas`.
  - The `max_gas_estimation_gas` clamp.
- `cargo test -p rundler-sim -p rundler-builder -p rundler-pool -p rundler-types`.
- Harness E7 on Sepolia, as in Phase 0.
- End-to-end in the style of E6, on Sepolia, with rundler started with the guard on:
  - Send a 20 kB-deploy op through `eth_estimateUserOperationGas` and then `eth_sendUserOperation`, both BSO and onchain.
  - Confirm it lands as a single-op bundle with `tx.gas > 2^24` and that the beneficiary margin is ≥ 0.
