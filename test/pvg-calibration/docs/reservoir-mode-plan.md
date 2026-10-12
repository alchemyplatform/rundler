# Plan: reservoir mode for state-heavy user ops on Glamsterdam

> **Terminology.** `StateGasMode` has two values:
>
> - **`Metered`** (today): `tx.gas ≤ 2^24`, so the EIP-8037 state-gas reservoir is empty. State gas is charged inside the op's limits, and the EntryPoint meters it like execution gas.
> - **`Reservoir`** (this plan): the op is bundled alone with `tx.gas = 2^24 + R`, so its state gas comes from the reservoir. The EntryPoint cannot see it, so the op pays for it through PVG.
>
> "Reservoir mode" means the latter. The harness keeps its original names (`isolated-state` command, `isolated_state.rs`). Rundler's `is_isolation` path (single-op bundles for suspect ops) is a separate feature; see [Builder](#builder-phase-4) for how the two interact.

## Status

| Phase | What | Status |
| --- | --- | --- |
| 0 | Validate the mechanics on Sepolia (harness E7) | Done. See [Phase 0 results](#phase-0-results-sepolia). |
| 1 | Plumbing: types, state-gas trace, simulation call | Done, #1351 |
| 2 | Estimation: normal first, then fall back to reservoir mode | Next |
| 3 | Admission and pool: mode from the PVG surplus | Planned |
| 4 | Builder: single-op bundle with `tx.gas = 2^24 + R` | Planned |
| 5 | Metrics, docs, end-to-end test through rundler | Planned |

## Decisions

- **Network** (2026-10-09): Sepolia only, which already runs Glamsterdam. The devnet is no longer used.
- **Guard** (2026-10-09): reservoir mode exists only while Glamsterdam is active (`ChainSpec::reservoir_mode_enabled_at`). There is no flag and no request header for now; a header may come later. Without Glamsterdam, behaviour is exactly today's.
- **Scope** (2026-10-09):
  - onchain payment first: self-paying ops and ops with an onchain paymaster such as Gas Manager
  - BSO is deferred; see the [BSO note](#note-bso-out-of-scope)
  - L1 only: the gas limit has no DA term, and no L2 has Glamsterdam
- **EntryPoint versions:** v0.7, v0.8 and v0.9. v0.6 is out of scope until there is a v0.6 simulation contract that returns instead of reverting, which [Estimation](#estimation-phase-2) needs.
- **The mode and the reservoir come from what the op paid** (2026-10-12):
  - **Mode:** reservoir mode iff `surplus = PVG − required_pvg(metered) ≥ T(op)`, with one shared threshold `T`. It is decided once and stored.
  - **Reservoir:** `R = surplus + zero-deposit refund term`.
  - **Where `S` is measured:** only during estimation. Admission and the builder do no state-gas tracing.
  - Rationale: see [Why R comes from the surplus](#why-r-comes-from-the-surplus).
- **VGL stays metered** (2026-10-12). It includes validation state, as today.
  - Admission's ERC-7562 validation simulation runs the op's real VGL with no reservoir, so a VGL without validation state would fail there. For example, a sender's first nonce write is 97,920.
  - Onchain, validation state still draws on the reservoir first. The state part of VGL then goes unused, which costs nothing because VGL has no unused-gas penalty.
  - Only CGL is execution-only. The postOp limit comes from the paymaster.
  - Validation state above `max_verification_gas` is a non-goal.
- **`max_uo_cost`** (2026-10-12): a separate, higher cap for reservoir-mode ops (`max_reservoir_uo_cost`, unset meaning no reservoir-mode ops). Operators opt in, and the cap still means "the most this op can cost".

## Context

Every bundle stays at or below `TX_MAX_GAS_LIMIT` (2^24). That keeps the reservoir empty, so the EntryPoint meters state gas as ordinary gas (see the report [The 2²⁴ Ceiling](https://claude.ai/code/artifact/86300a56-6234-4404-a759-92ba082407c5)). The cost is that an op whose execution plus state gas exceeds `max_bundle_execution_gas` (about 0.9 × 2^24 ≈ 15.1M) is impossible:

- estimation returns `GasTotalTooLarge`, or its binary search hits the max
- admission returns `TotalGasLimitTooHigh` (`crates/sim/src/precheck.rs:297-309`)

A contract deployment near the EIP-170 limit (24 kB) needs about 37.8M of state gas.

## How it works

These are the EIP-8037 facts the design relies on. Phase 0 confirmed each of them onchain.

- **Reservoir sizing.** `reservoir = evm_gas − min(2^24 − intrinsic, evm_gas)`. So `tx.gas = 2^24 + R` gives a reservoir of exactly `R`, and the full 2^24 execution budget is unchanged.
- **Every state charge draws on the reservoir first**, from any frame, including validation and the EntryPoint's own nonce and deposit writes.
- **Any state beyond `R` spills into the charging frame's `gas_left`.** There the EntryPoint meters it, and the op's limits bound it.
- **An unused reservoir is refunded** to the transaction sender: `tx_gas_used = tx.gas − gas_left − reservoir`.
- **A top-level revert or halt charges no state gas.** A reverted reservoir-mode bundle costs at most about 2^24 of execution gas, the same risk class as today.
- **Putting `S` in PVG avoids the v0.7 unused-gas penalty**, which applies only to CGL and the postOp limit.
- **Only some `gasleft()` wrap shapes remain.**
  - A single-op bundle removes the cross-op wrap (shape A in the report).
  - The cross-phase shapes B and C remain. On v0.7 they degrade to `PrefundTooLow`: the op fails, the bundle survives, and the bundler gets the full prefund.
- **Calls have no reservoir.** `debug_traceCall` and `eth_call` give the whole call gas to `gas_left` (reth 2.7, Phase 0 finding 5). So no node simulates a reservoir-mode bundle faithfully: in a call, its state is charged inside the op's limits.

### Why R comes from the surplus

- **The bundler cannot under-recover.** The state the EntryPoint cannot see is at most `R`, and the op's PVG pays for `R`.
- **If the real `S` is larger than `R`,** the rest spills into metered gas, inside the op's limits. The user pays for it, and the op may run out of gas: the safe direction, Phase 0 finding 3.
- **If the real `S` is smaller,** the unused reservoir is refunded to the bundler.
- **So measuring `S` again at admission or in the builder adds no protection for the bundler.** It would also be unreliable:
  - The only way to measure is a max-limit copy of the op (see [Measuring S](#measuring-s)). Raising the limits invalidates signatures that cover them.
  - A paymaster that signs over the gas limits (Gas Manager, `VerifyingPaymaster`) then returns `SIG_VALIDATION_FAILED` before its state writes and without a postOp context. `simulateHandleOp` reports that as a result, not a revert, so `S` would come back too low without any error.
  - Each trace costs up to the node's gas cap, and the pre-filter is a field the sender chooses.
- **The cost:** rundler does not check that a submitted op's CGL covers its execution. A wrong CGL fails onchain at the user's expense, as ops with bad limits do today. Validation is still fully checked by the ERC-7562 simulation.

## Measuring S

This is used only in estimation.

- **The max-limit copy.**
  - In a call, state is charged within the op's limits, so estimation simulates a copy whose CGL and postOp limit are far above execution plus state, with PVG 0.
  - It always uses `EntryPointSimulations.simulateHandleOp`, never the real `handleOps`: the copy's signature is invalid, and `simulateHandleOp` does not check it.
  - Rundler builds the call with `SimulationProvider::get_state_gas_simulate_handle_op_call` (#1351). It pre-sets `_senderCreator` (Phase 0 finding 8), so the traced state is exactly what `handleOps` creates.
- **Tracer:** `trace_call_state_gas` runs `callTracer`, whose root frame carries `executionGasUsed` / `stateGasUsed` / `gasRefund` (Phase 0 finding 6).
- **Split:**

  | Value | Measured as |
  | --- | --- |
  | `S` | `simulateHandleOp(max-limit copy)` |
  | `S_cv` | the same with `callGasLimit = 0`. Execution fails and its state rolls back; validation and postOp state remain. |
  | `S_c` (execution) | `S − S_cv` |

  `S_post` is not needed: rundler does not estimate the postOp limit.
- **Fees during the simulation:**
  - **Self-paying ops are simulated at fee 0.** As today, `deposit_transfer_overhead` covers the deposit debit the EntryPoint then skips.
  - **Paymaster ops are simulated at 1 wei,** so the paymaster's deposit debit is measured. Any larger fee times the max limits can exceed the paymaster's deposit and revert the trace with AA31.
- **What fee 0 hides from the trace:**
  - the deposit debit (covered by `deposit_transfer_overhead`)
  - the zero-deposit refund write (priced by `state_pre_verification_gas` and added to `R`)
  - the beneficiary compensation (`simulateHandleOp` does not compensate anyway; near zero for a funded builder EOA)
- **Signature-dependent paths:**
  - An account checking the dummy signature returns `SIG_VALIDATION_FAILED`; that is expected in estimation.
  - If the paymaster's validation fails on the paymaster data given to estimation, its validation-state writes and its postOp state are missing from `S`. That is the safe direction, but the user then pays that state twice.
  - Accounts or paymasters whose state depends on `userOpHash` or `gasleft()` also measure a different `S` on the copy.
  - See [Open questions](#open-questions) for Gas Manager.
- **Trace gas** must cover execution plus all of `S`, and it is bounded by the node's `rpc.gascap`. That is also the largest `S` estimation can measure; see [Limits](#limits).

## Estimation (Phase 2)

1. **Run normal (metered) estimation unchanged.**
2. **If it fails because the op does not fit, retry in reservoir mode.** The triggers:
   - `GasTotalTooLarge`
   - a CGL binary search reaching its max (`EstimateGasRevertAtMax`)
   - running out of gas in execution at the max

   A VGL search reaching `max_verification_gas` is a non-goal and is returned as today.
3. **Reservoir mode:**

   | Field | Value |
   | --- | --- |
   | VGL | the normal (metered) VGL estimate |
   | CGL | `(gas used by the EntryPoint's call into the sender − S_c) × 64/63 + 3,000 + headroom` |
   | postOp limit | supplied by the caller (the paymaster service) |
   | PVG | normal required PVG + `S` |

   - **CGL comes from the frame's `gasUsed`, not a binary search.** A search keeps the 1/64 of `S` withheld at each nested call: about 1.2M at 24 kB, which the v0.7 penalty would charge at 10% (Phase 0 finding 10).
   - **Headroom:** `max(10% of execution, 97,920)` against state drift between estimation and inclusion. See [Constraints](#constraints).
4. **The estimate must classify as reservoir mode.** Check `S ≥ T(estimated op)` with the same function admission uses. If it fails, return an error rather than an op that admission would put on the metered path, where it would burn its PVG.
5. **A real revert is not retried.** If the max-limit copy also fails, return the error as today.
6. **Above the [limits](#limits), return a clear error**, for example "state gas S exceeds the maximum M".
7. **Protect the node.** The fallback runs traces of up to the gas cap, and anyone can trigger them through `eth_estimateUserOperationGas`. Add a concurrency cap, a trace timeout, and a metric for fallback traces per second.
8. **The response is a normal estimate.** Its large PVG is the only sign of the mode. An optional `stateGas` field can come later.

## Admission and pool (Phase 3)

- **The threshold.** `T(op) = max_bundle_execution_gas − bundle_computation_gas_limit(op)` is one function in `rundler-sim`, used by estimation, admission and the builder. `bundle_computation_gas_limit` uses the static PVG, not the op's PVG.
- **The mode.** An op uses reservoir mode iff Glamsterdam is active and `surplus = PVG − required_pvg(metered) ≥ T(op)`.
  - It is decided once, at admission, and stored on the pool op as `state_gas_mode: StateGasMode`, with `R`.
  - A reservoir-mode op is **never** eligible for a metered bundle. A metered op never gets a reservoir.
  - An op that overpays PVG by `T` or more also uses reservoir mode. It still works, and the bundler is paid, since `R` is what the op paid for.
- **Checks for reservoir-mode ops:**
  - **No state-gas trace.**
  - **Unchanged:** precheck, the fee checks and the ERC-7562 validation simulation (VGL is metered, so validation state fits).
  - **Cost cap:** `max_reservoir_uo_cost` replaces `max_uo_cost` (`precheck.rs:329`). If it is unset, reject reservoir-mode ops.
  - **Size:** `R ≤ max reservoir`; see [Limits](#limits).
  - **Pool caps:** at most `N` reservoir-mode ops per sender and `M` in the pool.
- **Re-check.** The pool's periodic re-check (`crates/pool/src/mempool/pool.rs:600-668`) keeps the stored mode. If the op's PVG no longer covers `required_pvg(metered) + R` (for example, the required PVG changed), the op is dropped, not moved to the metered path.

## Builder (Phase 4)

- **Assignment.**
  - A reservoir-mode op always gets a single-op `WorkAssignment`, on the model of the assigner's `is_isolation` path (`crates/builder/src/assigner.rs:506-560`, `:676-695`).
  - It has its own cap (one reservoir-mode bundle in flight per builder) and does not take an `isolating_builders` slot.
  - If a reservoir-mode op becomes a suspect, skip isolation (it is already alone) but keep the suspect tracking.
- **Gas limit:** `tx.gas = TX_MAX_GAS_LIMIT + R`, exactly.
  - Bypass `get_bundle_gas_limit` and its caller's ×1.05 (`bundle_proposer.rs:1309-1312`) **entirely**. Otherwise the reservoir comes out wrong. Example: `(0.1M + 37.8M) × 1.05 = 39.8M` gives a 23M reservoir instead of 37.8M.
  - Assert that the op's computation gas × 1.05 ≤ 2^24.
  - L1 only: no DA term.
- **No state-gas trace and no faithful pre-submit check.** The real bundle fails in `eth_call` (no reservoir), so the existing skip of the pre-submit call for single-op v0.7 bundles (`bundle_proposer.rs:1318-1325`) stays.
- **At bundle time:** re-check the stored mode's conditions (PVG covers `required_pvg(metered) + R`), and drop the op if they fail.
- **Fee bumps keep the same `tx.gas`.**
- **AA51 / AA95 from a reservoir-mode op** is a hard reject, not a retry.
- **Use `eth_estimateGas` nowhere in this path.** It cannot size these bundles (Phase 0 finding 7).

## Constraints

- **State drift.** If the op's real state grows between estimation and inclusion, the extra spills into metered gas. CGL headroom of `max(10% of execution, one slot)` absorbs about one new slot; beyond that the op runs out of gas at the user's expense.
- **Net vs peak.** An op that allocates and then clears slots peaks above its net `S`. The reservoir is sized at net, so the gap spills into metered gas at the peak.
  - reth reports state gas only on the root frame, so the peak cannot be measured today.
  - Supported: ops whose peak exceeds net by at most about one slot, which is the headroom.
  - If clients report per-frame state gas (optional in execution-apis#852), measure the peak and size headroom from it.

## Limits

- **Largest `R`:** the block's state-gas room minus 2^24, and in estimation also the trace gas minus execution.
  - On Sepolia (200M blocks, 200M trace gas) this is not binding.
  - With a 50M `rpc.gascap` it is about 33M, below a 24 kB deploy.
  - Our nodes' gascap must be checked and raised.
- **Block admission:** a reservoir-mode transaction needs `execution_gas_available ≥ 2^24` and `state_gas_available ≥ tx.gas`, even if it uses far less execution gas. It may wait longer for inclusion than a normal bundle.
- **Pool:** per-sender and total caps, plus `max_reservoir_uo_cost`. Each reservoir-mode op occupies a whole bundle.

## Open questions

- **Gas Manager.**
  - Does its stub paymaster data pass validation in estimation?
  - Does its postOp create state?
  - If the stub fails validation and the postOp creates state, `S` under-counts the postOp state, which the user then pays twice. This needs a look at the real paymaster contract and `alchemy_requestGasAndPaymasterAndData`.
- **Faithful pre-submit simulation.** Can a node simulate a transaction with the reservoir split? geth applied the 2^24 cap to calls until v1.17.8 and then removed it (go-ethereum#35838). Worth raising with client teams.
- **Other clients.** Does Nethermind or Erigon report `stateGasUsed` on the `callTracer` root frame, and do their calls also have no reservoir? Phase 0 covered reth 2.7 only.

## Phase 0 results (Sepolia)

Setup: Sepolia RPC on reth v2.7.0, block gas limit 200M, base fee about 15 wei, 2026-10-09. Each op deploys a contract of 4 / 16 / 24 kB from its execution phase. Reports are in `results/` (git-ignored):

- `e7-v0.7-sepolia-11155111-1791545919.json`
- `e7-v0.6-sepolia-11155111-1791546950.json`, plus `…-1791547058.json`, which re-runs 4 kB after a nonce race
- `e7-v0.7-sepolia-est-…-1791548390.json` and `e7-v0.6-sepolia-est-…-1791548523.json`
- `e7-v0.7-sepolia-pm-…-1791557609.json` and `e7-v0.6-sepolia-pm-…-1791557739.json`

The 4 kB cases are below the metered cap, so rundler would not use reservoir mode for them. They check the mechanics at a small `S`. 16 kB and 24 kB are real reservoir-mode cases.

| | 4 kB | 16 kB | 24 kB (EIP-170 max) |
| --- | --- | --- | --- |
| `S` of `handleOps` | 6,450,480 | 25,251,120 | 37,784,880 |
| composed `size × 1,530 + 183,600` | 6,450,480 | 25,251,120 | 37,784,880 |
| `tx.gas` for **exact** (`2^24 + S`) | 23.2M | 42.0M | 54.6M |
| **exact**: op ok, gas margin (v0.7 / v0.6) | ✓ +11,224 / −1,328 | ✓ +11,263 / −1,328 | ✓ +11,293 / −1,328 |
| **under** (`R = S − 200k`): gas margin | +213k / +199k | same | same |
| **over** (`R = S + 2M`): `gasUsed`, margin | same as exact | same | same |
| **bso** (fees 0, PVG 0): op ok, bundler pays | ✓ −6.47M | ✓ −25.3M | ✓ −37.8M |
| **capped** (`tx.gas = 2^24`) | op fails, nothing deployed | same | same |

Gas margin is `actualGasUsed − receipt.gasUsed`. It is ≥ 0 when the op paid for everything the bundler spent, at equal prices. The wei margin in the reports is negative only because the harness tips about 0.7 gwei while the op pays about 1,015 wei/gas.

1. **The reservoir works onchain on both EntryPoints, up to the 24 kB maximum.**
   - With `tx.gas = 2^24 + S` and an execution-only CGL, the op deploys.
   - `PVG = base + S` pays the bundler back, and the margin is constant across sizes. On v0.7 the +11k is the 10% penalty on the harness's deliberate CGL slack. On v0.6 the −1,328 is the base-PVG gap that #1349 fixes, unrelated to state gas.
   - Sepolia accepted and mined transactions up to 56.6M gas.
2. **`S` is exactly the EIP-8037 arithmetic:** 1,530 per code byte, 183,600 per new account, 97,920 per new slot (the first one here is the account's first nonce write). So `S` can be cross-checked offline.
3. **An undersized reservoir is safe; an oversized one costs nothing extra.**
   - **under:** the missing state spills into the deploying frame's `gas_left`. There it is metered, so the user pays it twice.
   - **over:** the unused reservoir is refunded to the sender, so `gasUsed` is the same as **exact**. Oversizing does, however, let state stay hidden from the EntryPoint, so size `R = S`.
4. **A top-level revert charges no state gas.**
   - `deployThenRevert` with `tx.gas = 2^24 + S` used only execution gas: 30,919 at 4 kB and 37,799 at 24 kB.
   - `stateGasTracer` reports `stateGasUsed = 0` and no error for a reverted call; `callTracer` reports the error.
5. **Calls have no reservoir (reth 2.7).**
   - `debug_traceCall`, like `eth_call`, gives the whole call gas to `gas_left`. Inside a 200M trace, `innerHandleOp` was forwarded 196.7M.
   - So an op with an execution-only CGL fails in simulation, although it succeeds onchain. See [Measuring S](#measuring-s).
6. **`callTracer` is enough.** On reth its root frame carries `executionGasUsed`, `stateGasUsed` and `gasRefund` (inner frames carry none). It also gives the revert error and, with `withLog`, the `UserOperationEvent`.
7. **`eth_estimateGas` cannot size these bundles.** For the 24 kB bundle it returned 642,333 against 37.9M used: the cheapest run that does not revert is one where the op's execution quietly runs out of gas.
8. **`EntryPointSimulations` adds one new slot of its own, now fixed.**
   - Every simulation writes `_senderCreator`: slot 6 on v0.7, slot 4 on v0.8/v0.9.
   - That slot is empty in the real entry point's storage, so the simulation reported 97,920 more than `handleOps`.
   - The fix pre-sets the slot in the override to `ep.create(1)`. With it, the harness measured `sim = S` exactly (6,450,480 at 4 kB). Rundler's `get_state_gas_simulate_handle_op_call` does the same.
9. **BSO ops run, but billing would miss `S`.**
   - With fees 0 and PVG 0, `actualGasCost` is 0, and the bundler pays `S` plus overhead.
   - Today's BSO billing prices `actualGasUsed`, which leaves out reservoir-paid state. See the [BSO note](#note-bso-out-of-scope).
10. **Reservoir-mode estimation works with no hand sizing.**
    - Variants `estimated` and `estimated-deploy`; the derivation is in [Estimation](#estimation-phase-2).
    - All 12 cases (4/16/24 kB × existing or `initCode`-deployed sender × v0.6/v0.7) succeeded.

    | | VGL (v0.7 / v0.6) | CGL | `S_v` | gas margin (v0.7 / v0.6) |
    | --- | --- | --- | --- | --- |
    | estimated, 4 / 16 / 24 kB | 59,378 / 59,063 | 22,330 / 26,328 / 29,319 | 0 | +364…+375 / −1,328 |
    | estimated-deploy, 4 / 16 / 24 kB | 88,387 / 87,771 | same | 1,650,870 | +379…+390 / −1,320 |

    - **CGL is tight:** a v0.7 margin of about +370 means the penalty is negligible. See the headroom question in [Open questions](#open-questions).
    - **`S_v` is subtracted correctly.** For a fresh sender `S_v` is account creation + code + the first nonce write, and VGL stays below 90k although validation creates 1.65M of state. The harness skips the ERC-7562 validation simulation, which rundler would run at `max_verification_gas`.
    - **`deposit_transfer_overhead` is needed.** The first attempt hit AA26 without it.
    - **Rundler keeps VGL metered.** This VGL was execution-only (validation state subtracted), which works onchain but would fail rundler's ERC-7562 validation simulation, which runs without a reservoir. See [Decisions](#decisions).
11. **Paymaster-paid ops work too, including postOp state.**
    - Variants: `estimated-paymaster` (no postOp), `-post-op` (postOp creates no state) and `-post-op-state` (postOp writes a fresh slot).
    - All 18 cases (3 variants × 4/16/24 kB × v0.6/v0.7) succeeded, with `StatePaymaster` paying PVG = base + `S`, up to 37.9M.

    | | VGL (v0.7 / v0.6) | postOp limit (v0.7) | `S_post` | gas margin (v0.7 / v0.6) |
    | --- | --- | --- | --- | --- |
    | no postOp | 45,743 / 44,366 | 0 | – | +366…+377 / −1,324 |
    | postOp, no state | 45,865 / 44,486 | 4,971 | 0 | +513…+524 / −1,389 |
    | postOp writes a fresh slot | 46,184 / 44,803 | 17,554 | 97,920 | +451…+462 / −1,463 |

    - **The postOp slot is attributed correctly:** `S_post = 97,920`, with `S_v` and `S_c` unchanged. The execution-only postOp limit of 17,554 is enough onchain, although the postOp frame used 112,247 in simulation, because the reservoir pays for the slot.
    - **How `S_post` was measured:** on v0.7 as `simulateHandleOp − simulateHandleOpNoPostOp`. On v0.6, which has no NoPostOp simulation, the harness switched the paymaster to its stateless postOp mode, which rundler cannot do.
    - **The paymaster sets the postOp limit.** If it includes postOp state, the op still works, at the cost of the v0.7 penalty on the unused part (about 9.8k per slot).
    - Not covered: Gas Manager's real paymaster contract and its policy service.
12. **Harness note.** The load-balanced RPC returned stale pending nonces, so the harness reused one: a case failed, and an earlier run hung waiting for a receipt. The harness now tracks nonces locally and times out receipts after 3 minutes. A builder lane that sends 50M-gas transactions should watch for the same problem.

## Note: BSO (out of scope)

How BSO works today. This is from tracing `txn-engine` on 2026-10-09; it is not verified against production.

- **Before signing.** Wallet-server zeroes the fees, calls rundler's `eth_estimateUserOperationGas`, keeps VGL and CGL, and **sets PVG to 0** (`wallet-server/server/src/uoPreparation/gas.ts:135-140`). `wallet_sendPreparedCalls` rejects BSO ops with PVG > 0 (`:355-371`), and rundler requires PVG 0 for sponsored ops (`crates/rpc/src/eth/api.rs:79-88`).
- **`max_cost` is a budget cap, not an estimate.** It is the policy's `max_spend_per_uo_usd` / token price; on testnet it is 1 ETH. Rundler skips an op when `(bundle_gas_limit + required_pvg) × gas_price > max_cost`.
- **Billing happens after inclusion.**
  - `paymaster-jobs` `BlockIndexer` → `BsoCostCalculatorPipeline` prices each op as `actualGasUsed × effectiveGasPrice`, plus a share of the fixed tx overhead and of calldata/DA, × 1.3 markup.
  - The result goes to Kafka `paymaster-gas-sponsor-usage-event` (`sponsored_gas`).

**The problem.** Reservoir-paid state is not in `actualGasUsed`, and with PVG 0 nothing else carries it. In E7's 24 kB `bso` case, `actualGasUsed` was 60,160 while the bundler paid 37.87M.

**One possible design (not decided).** Let sponsored ops carry `PVG = S`: only `S`, because billing adds its own overhead and calldata share.
- At gas price 0 this costs nothing onchain, and the op still counts as BSO.
- PVG becomes part of `actualGasUsed`, so billing charges for `S` unchanged.
- It also lets the send-side PVG rule recognise the op.
- Changes needed:
  - rundler: allow PVG > 0 for sponsored ops, and add `S` to the `max_cost` check
  - wallet-server: keep PVG
- Open:
  - Is this how state gas should flow into BSO accounting?
  - Mainnet `max_spend_per_uo_usd` must allow about 38M gas.
  - Which confirm path is deployed today, and how Orb consumes the event.

## Verification

- **Unit tests (CI):**
  - the estimation fallback and the CGL derivation, with mocked state-gas traces
  - the shared threshold `T`, and estimation refusing an op that would not classify as reservoir mode
  - mode selection and its stickiness through the pool re-check
  - `max_reservoir_uo_cost`
  - `tx.gas = 2^24 + R` in the builder, bypassing the ×1.05
  - without Glamsterdam, behaviour identical to today
- `cargo test -p rundler-sim -p rundler-pool -p rundler-builder -p rundler-types -p rundler-provider`.
- **Manual gate per phase.** CI cannot exercise the real path: there is no devnet, and it needs EIP-8037 semantics and 50M-gas transactions. So harness E7 on Sepolia, and from Phase 4 the end-to-end run, are a manual gate before each phase merges.
- **End to end** (E6 style, on Sepolia, through a running rundler): send a 16 kB- and a 24 kB-deploy op through `eth_estimateUserOperationGas` and then `eth_sendUserOperation`, self-paying and with a paymaster. Confirm that each lands as a single-op bundle with `tx.gas = 2^24 + R` and a bundler margin ≥ 0.
