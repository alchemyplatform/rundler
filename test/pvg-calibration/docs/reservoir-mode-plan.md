# Plan: reservoir mode for state-heavy user ops on Glamsterdam

> **Terminology.** `StateGasMode` has two values:
>
> - **`Metered`** (today): `tx.gas ≤ 2^24`, so the EIP-8037 state-gas reservoir is empty. State gas is charged inside VGL/CGL, and the EntryPoint meters it like execution gas.
> - **`Reservoir`** (this plan): the op is bundled alone with `tx.gas = 2^24 + S`, so its state gas `S` comes from the reservoir. The EntryPoint cannot see it, so the op pays for it through PVG, and its gas limits cover execution only.
>
> "Reservoir mode" means the latter. The harness keeps its original names (`isolated-state` command, `isolated_state.rs`). Rundler's existing `is_isolation` builder path is an unrelated feature.

## Status

| Phase | What | Status |
| --- | --- | --- |
| 0 | Validate the mechanics on Sepolia (harness E7) | Done. See [Phase 0 results](#phase-0-results-sepolia). |
| 1 | Plumbing: types, state-gas trace, simulation call | Done, #1351 |
| 2 | Estimation: normal first, then fall back to reservoir mode | Next |
| 3 | Admission and pool: infer the mode from PVG / VGL / CGL | Planned |
| 4 | Builder: single-op bundle with `tx.gas = 2^24 + S` | Planned |
| 5 | Metrics, docs, end-to-end test through rundler | Planned |

## Decisions

Made on 2026-10-09; see also [Open questions](#open-questions).

- **Network:** Sepolia only, which already runs Glamsterdam. The devnet is no longer used.
- **Guard:** reservoir mode exists only while Glamsterdam is active (`ChainSpec::reservoir_mode_enabled_at`). There is no flag and no request header for now; a header may come later. Without Glamsterdam, behaviour is exactly today's.
- **The mode is inferred, never requested.**
  - Estimation falls back to reservoir mode only when normal estimation fails because the op does not fit.
  - `eth_sendUserOperation` infers the mode from the op's own PVG, VGL and CGL.
- **Scope:** onchain payment first, i.e. self-paying ops and ops with an onchain paymaster such as Gas Manager. BSO is deferred; see the [BSO note](#note-bso-out-of-scope).
- **EntryPoint versions:** v0.7, v0.8 and v0.9 only. v0.6 is out of scope until there is a v0.6 simulation contract that returns instead of reverting; see [Measuring S](#measuring-s).
- **State in execution and postOp only.** An op whose **validation** creates more state than fits under `max_verification_gas` is not supported. The ERC-7562 validation simulation runs at that gas with no reservoir, so such an op fails admission whatever mode it would use.

## Context

Every bundle stays at or below `TX_MAX_GAS_LIMIT` (2^24). That keeps the reservoir empty, so the EntryPoint meters state gas as ordinary gas (see the report [The 2²⁴ Ceiling](https://claude.ai/code/artifact/86300a56-6234-4404-a759-92ba082407c5)). The cost is that an op whose execution plus state gas exceeds `max_bundle_execution_gas` (about 0.9 × 2^24 ≈ 15.1M) is impossible:

- estimation returns `GasTotalTooLarge`, or its binary search hits the max
- admission returns `TotalGasLimitTooHigh` (`crates/sim/src/precheck.rs:297-309`)

A contract deployment near the EIP-170 limit (24 kB) needs about 37.8M of state gas.

## How it works

These are the EIP-8037 facts the design relies on. Phase 0 confirmed each of them onchain.

- **Reservoir sizing.** `reservoir = evm_gas − min(2^24 − intrinsic, evm_gas)`. So `tx.gas = 2^24 + R` gives a reservoir of exactly `R`, and the full 2^24 execution budget is unchanged.
- **Every state charge draws on the reservoir first**, from any frame, including the EntryPoint's own nonce and deposit writes. So `S` is the transaction-level total.
- **Any state beyond `R` spills into the charging frame's `gas_left`.** There the EntryPoint meters it (`preGas − gasleft()`), and the op's limits bound it.
- **Bundler loss from hidden state is bounded.** State the EntryPoint cannot see is at most `R`. With `R = S` and PVG covering `S`, the bundler never under-recovers.
- **An unused reservoir is refunded** to the transaction sender: `tx_gas_used = tx.gas − gas_left − reservoir`.
- **A top-level revert or halt charges no state gas.** A reverted reservoir-mode bundle costs at most about 2^24 of execution gas, the same risk class as today.
- **Putting `S` in PVG avoids the v0.7 unused-gas penalty**, which applies only to CGL and the postOp limit.
- **Only some `gasleft()` wrap shapes remain.**
  - A single-op bundle removes the cross-op wrap (shape A in the report).
  - The cross-phase shapes B and C remain. On v0.7 they degrade to `PrefundTooLow`: the op fails, the bundle survives, and the bundler gets the full prefund, which includes `S`.

## Measuring S

- **Calls have no reservoir.** `debug_traceCall` and `eth_call` give the whole call gas to `gas_left` (reth 2.7; Phase 0 finding 5). So in simulation, state is charged within the op's limits.
  - An op whose limits cover execution only **fails** in simulation, although it succeeds onchain.
  - Every measurement therefore uses a **max-limit copy** of the op: VGL, CGL and the postOp limit are set far above execution plus state, and PVG is 0.
- **Always `simulateHandleOp`, never the real `handleOps`.**
  - The gas limits are part of the userOpHash, so the max-limit copy has an invalid signature: a real `handleOps` reverts with AA24, and the revert wipes the state.
  - `EntryPointSimulations.simulateHandleOp` does not check signatures and returns normally.
  - Rundler builds this call with `SimulationProvider::get_state_gas_simulate_handle_op_call` (#1351). It pre-sets `EntryPointSimulations._senderCreator` (Phase 0 finding 8), so the traced state is exactly what `handleOps` creates.
  - v0.6's `simulateHandleOp` always reverts, so v0.6 needs a simulation contract that returns instead of reverting before any phase can support it.
- **Tracer:** `trace_call_state_gas` runs `callTracer`, whose root frame carries `executionGasUsed` / `stateGasUsed` / `gasRefund` (Phase 0 finding 6). It also gives the frames needed for the split below, and the revert error.
- **Split by phase:**

  | Value | Measured as |
  | --- | --- |
  | `S` | `simulateHandleOp(max-limit op)` |
  | `S_post` | `S − simulateHandleOpNoPostOp(max-limit op)` (0 without a postOp) |
  | `S_cv` | `simulateHandleOp(max-limit op with callGasLimit = 0)`. Execution fails and its state rolls back; postOp still runs. |
  | `S_c` (execution) | `S − S_cv` |
  | `S_v` (validation) | `S_cv − S_post` |

- **Fees during the simulation:**
  - **Self-paying ops are simulated at fee 0**, so the EntryPoint skips the deposit debit. Add `deposit_transfer_overhead` to VGL, as rundler already does.
  - **Paymaster ops are simulated at a constant nonzero fee**, so the paymaster's deposit debit is measured, as in rundler's verification search.
  - **Fee 0 also skips the zero-deposit refund write.** That write's state is priced separately by `state_pre_verification_gas`, and the reservoir must cover it too.
- **Trace gas.** The max-limit copy needs call gas for execution plus all of `S`. That is bounded by the node's `rpc.gascap`: reth and geth default to 50M, and the Alchemy Sepolia endpoint allowed 200M. This bound is also the largest `S` rundler can measure; see [Limits](#limits).

## Estimation (Phase 2)

1. **Run normal (metered) estimation unchanged.**
2. **If it fails because the op does not fit, retry in reservoir mode.** The triggers:
   - `GasTotalTooLarge`
   - a VGL or CGL binary search reaching its max (`EstimateGasRevertAtMax`)
   - running out of gas at the max

   With today's search ceilings, any op with execution plus state above about 15.1M fails this way. That is the same boundary the send-side rule uses.
3. **Reservoir mode:** measure `S`, `S_v`, `S_c` and `S_post` as in [Measuring S](#measuring-s). Then:

   | Field | Value |
   | --- | --- |
   | VGL | `(max-limit preOpGas − S_v [+ deposit_transfer_overhead if self-paying]) × 1.1` |
   | CGL | `(gas used by the EntryPoint's call into the sender − S_c) × 64/63 + 3,000`, plus the [headroom](#open-questions) |
   | postOp limit | supplied by the caller (the paymaster service); rundler does not estimate it |
   | PVG | normal required PVG + `S` |

   CGL comes from the frame's `gasUsed`, not a binary search. A search would also keep the 1/64 of `S` withheld at each nested call: about 1.2M at 24 kB, which the v0.7 penalty would charge at 10%. Phase 0 finding 10 validated this derivation onchain.
4. **A real revert is not retried.** If the max-limit copy also fails, return the error as today.
5. **Above the [limits](#limits), return a clear error**, for example "state gas S exceeds the maximum M".
6. **The response is a normal estimate.** Its large PVG is the only sign of the mode. An optional `stateGas` field can come later.

## Admission and pool (Phase 3)

An op uses reservoir mode iff Glamsterdam is active and all of the following hold:

1. **Cheap pre-filter, no RPC.** The op's PVG surplus over the metered requirement must be at least the smallest state gas that could not fit under the cap. Most ops fail this and take the normal path untouched.

   ```
   surplus = PVG − required_pvg(metered)
   surplus ≥ max_bundle_execution_gas − bundle_computation_gas_limit(op)
   ```

2. **Measure `S`** on the max-limit copy, as in [Measuring S](#measuring-s).
3. **Paid for and impossible metered:** `surplus ≥ S` and `bundle_computation_gas_limit(op) + S > max_bundle_execution_gas`. This matches the condition under which normal estimation falls back, so estimation and admission agree.
4. **The op's own limits cover execution.** The op's VGL, CGL and postOp limit must be at least what the derivation in [Estimation](#estimation-phase-2) gives, minus the buffers.
   - This is the only way to check that the real op will succeed, because no node can simulate it faithfully: calls have no reservoir.
   - It is the same comparison precheck makes today between an op's limits and the gas it needs.
5. **Pool limits:** at most `N` reservoir-mode ops per sender and `M` in the pool. See [Limits](#limits).

Otherwise the op takes the normal path. If it carries state its limits cannot hold, that path fails as it would today.

- **Store** `state_gas_mode: StateGasMode` and `S` on the pool op (`crates/types/src/pool/traits.rs`, proto).
- **Re-check** the coverage on the pool's PVG/cost re-check (`crates/pool/src/mempool/pool.rs:600-668`).
- `TotalGasLimitTooHigh` uses the static PVG, not the op's PVG, so it already lets reservoir-mode ops through: their limits are execution-only. `VerificationGasLimitTooHigh` applies unchanged.

## Builder (Phase 4)

- **Assignment.** A reservoir-mode op always gets a single-op `WorkAssignment`; the template is the assigner's `is_isolation` path (`crates/builder/src/assigner.rs:506-560`, `:676-695`). Allow at most one reservoir-mode bundle in flight per builder.
- **Re-measure `S_b` at bundle time** on the max-limit copy. Recheck the conditions from admission against `S_b`, and skip the op if they no longer hold.
- **Gas limit:** `tx.gas = TX_MAX_GAS_LIMIT + S_b + zero-deposit refund term`, exactly.
  - Use a separate path for this, **not** `get_bundle_gas_limit_inner`. That function computes `(computation + state) × 1.05`, which gives the wrong reservoir. Example: 0.1M of execution with `S` = 37.8M gives 39.8M, a 23M reservoir.
  - Assert that the op's computation gas × 1.05 ≤ 2^24.
- **No faithful pre-submit check.** The real bundle fails in `eth_call` (no reservoir). So the pre-submit check is the max-limit copy succeeding plus the limit checks above. The existing skip of the pre-submit call for single-op v0.7 bundles (`bundle_proposer.rs:1318-1325`) stays.
- **Fee bumps keep the same `tx.gas`.**
- **AA51 / AA95 from a reservoir-mode op** is a hard reject, not a retry.
- **Use `eth_estimateGas` nowhere in this path.** It cannot size these bundles (Phase 0 finding 7).

## Limits

- **Largest `S`:** `min(block state-gas room − 2^24, trace gas − execution)`.
  - On Sepolia (200M blocks, 200M trace gas) that is not binding.
  - With a 50M `rpc.gascap` it is about 33M, which is below a 24 kB deploy.
  - Our nodes' gascap must be checked and raised.
- **Block admission:** a reservoir-mode transaction needs `execution_gas_available ≥ 2^24` and `state_gas_available ≥ tx.gas`, even if it uses far less execution gas. It may wait longer for inclusion than a normal bundle.
- **Pool:** per-sender and total caps on reservoir-mode ops. Each one occupies a whole bundle, cannot be checked faithfully before submission, and may wait longer for a block.

## Open questions

- **Headroom against state drift.** Phase 0's derived CGL left about 370 gas of headroom. If `S` grows between estimation and inclusion, the extra state spills into `callGasLimit`. The op then runs out of gas, and the user pays PVG including `S` for a failed op. The options:
  - **CGL headroom (recommended):** for example `max(10% of execution, one new slot = 97,920)`. On v0.7 the user pays up to 10% of the unused headroom as the penalty.
  - **A reservoir buffer above `S`:** keeps CGL tight, but lets up to the buffer of state stay hidden from the EntryPoint, a bundler risk of buffer × price.
- **Net vs peak state.** An op that allocates and then refills can peak above its net `S`. A reservoir sized at net then spills at the peak. That is safe, because the spill is metered, but it can push the op over its CGL. The headroom above covers it.
- **Faithful pre-submit simulation.** Can a node simulate a transaction with the reservoir split (EIP-8037 semantics in `eth_call`)? geth applied the 2^24 cap to calls until v1.17.8 and then removed it (go-ethereum#35838). Worth raising with client teams; until then, admission and the builder rely on the limit checks.
- **Other clients.** Does Nethermind or Erigon report `stateGasUsed` on the `callTracer` root frame? Do their calls also have no reservoir? Phase 0 covered reth 2.7 only.
- **Validation state.** Supporting validation-phase state above `max_verification_gas` would need the ERC-7562 tracer to run with gas for `VGL + S_v`. Out of scope for now.

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

- **Unit tests:**
  - the estimation fallback and the limit derivation, with mocked state-gas traces
  - the admission rule (pre-filter, coverage, the op's limits against the derived requirements)
  - `tx.gas = 2^24 + S` in the builder, including the zero-deposit term
  - without Glamsterdam, behaviour identical to today
- `cargo test -p rundler-sim -p rundler-pool -p rundler-builder -p rundler-types -p rundler-provider`.
- **Harness E7 on Sepolia** after each phase, against the same reports.
- **End to end** (E6 style, on Sepolia, through a running rundler): send a 16 kB- and a 24 kB-deploy op through `eth_estimateUserOperationGas` and then `eth_sendUserOperation`, self-paying and with a paymaster. Confirm that each lands as a single-op bundle with `tx.gas = 2^24 + S` and a bundler margin ≥ 0.
