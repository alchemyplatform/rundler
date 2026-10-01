# PVG calibration

Experiments that measure the gas the EntryPoint does **not** meter. That gas is what
`preVerificationGas` has to pay the bundler back for. Rundler computes PVG with pure
arithmetic over ChainSpec constants (`pre_verification_execution_gas_limit` in
`crates/types/src/user_operation/mod.rs`), so nothing ever checks those constants
against a live chain. This harness does. Its first target is Glamsterdam
(EIP-8037 / EIP-8038, plus EIP-7976 / EIP-2780 if active), and it can be re-run
for any later fork.

## Layout

```
contracts/     foundry project with the probe fixtures (Probes.sol), built by build.rs
src/           rundler-pvg-calibration binary (standalone crate: own workspace, lockfile and target/)
results/       JSON reports (raw reports are git-ignored; commit summaries only)
.env.example   variables the binary reads
```

The fixtures have no dependencies and are deliberately trivial, so that their own
gas is small, deterministic and independent of calldata:

| Contract         | Purpose                                                                    |
| ---------------- | -------------------------------------------------------------------------- |
| `ProbeAccount`   | v0.7 account (also a 7702 delegate); accepts any signature, pays exactly `missingAccountFunds` |
| `ProbeFactory`   | CREATE2 factory for `ProbeAccount` (deploy-in-op path)                     |
| `ProbePaymaster` | sponsors everything; `paymasterData[0]` selects no-postOp / postOp mode    |
| `Burner`         | burns a fixed amount of gas, never reads calldata (E0 standard pricing)    |
| `Scratch`        | slots that the account (signature-driven) and paymaster (mode 2) set/clear |

Fixtures deploy through the CREATE2 deployer `0x4e59…956C` and are skipped if they
already have code. Every run therefore rebuilds its own fixtures after a devnet reset.

## Running

Requires `forge` (for `build.rs`). The crate is excluded from the rundler workspace, so run
it from this directory (it depends on `rundler-types` / `rundler-contracts` by path). The key
is read from the environment only:

```sh
export PVG_RPC_URL=https://rpc.plataberget.ethpandaops.io
export PVG_PRIVATE_KEY=...        # funded EOA; never commit it
cargo run -- --label devnet calibrate-chain
```

Baseline on a pre-Glamsterdam fork, using anvil's first dev account:

```sh
anvil --hardfork prague --port 8645
PVG_PRIVATE_KEY=<anvil dev key 0> cargo run -- \
  --rpc-url http://127.0.0.1:8645 --label anvil-prague calibrate-chain
```

### Local devnet node

The public devnet RPC (`rpc.plataberget` / `rpc.glamsterdam-devnet-8.ethpandaops.io`) sits
behind a proxy that fails often. Per-node RPCs need ethpandaops credentials. `devnet-node.sh`
runs a local geth + lighthouse node instead: lighthouse checkpoint-syncs and geth snap-syncs,
so it downloads current state and never executes old blocks. Sync takes about 10–20 minutes
and needs about 15 GB.

```sh
./devnet-node.sh start ~/pvg-devnet-node   # data dir outside the repo
./devnet-node.sh status                    # "synced" when ready
PVG_RPC_URL=http://127.0.0.1:8547 cargo run -- --label devnet calibrate-chain
./devnet-node.sh stop
```

RPC (including `debug_*`) is bound to `127.0.0.1:8547` only. Note that Besu behind the
public proxy accepts only the transaction parameter for `eth_estimateGas`, which the harness
sends.

Use one harness EOA per run at a time. The balance cross-check assumes nothing else
moves the sender's balance in the same block.

## Experiments

| ID | Command           | Measures                                                                            |
| -- | ----------------- | ----------------------------------------------------------------------------------- |
| E0 | `calibrate-chain` | base tx gas, value/new-account cost, standard calldata and floor per byte, and whether `receipt.gasUsed` equals the charged gas |
| E1 | `fixtures`        | deploys (or finds) EntryPoint v0.7 and the probes; prints addresses and EntryPoint code hash |
| E2 | `overhead`        | shared and per-op unmetered gas by payer × deploy path, beneficiary cost, penalty check |
| E3 | `calldata`        | unmetered gas per byte of `callData` and of `signature`, zero vs non-zero, floor-bound cases |
| E4 | `authorization`   | unmetered cost per EIP-7702 authorization by authority state (empty, funded, re-delegation), vs rundler's `authorization_gas_limit` |
| E5 | `hazards`         | storage shapes that move gas across metering spans: same-sender zero-deposit ops, exact paymaster drain, cross-op and cross-span slot clears |

Planned: E6 validation of the new formula, E7 v0.6.

On chains without the canonical EntryPoint v0.7 (anvil), E1 deploys the submodule's
EntryPoint built with the canonical settings (solc 0.8.23, 1M optimizer runs, viaIR). It is
gas-equivalent but has a different address and code hash, both recorded in every report.

### How E2/E3 measure unmetered gas

The harness EOA acts as the bundler and submits `handleOps` itself. Every op carries
`preVerificationGas = 0` and `callGasLimit = 0` with non-empty `callData`. The EntryPoint
still encodes and copies callData for the inner call, and then the account call fails for
lack of gas. With no unused execution gas, the v0.7 penalty is zero. So
`UserOperationEvent.actualGasUsed` is exactly the metered gas, and

```
unmetered = receipt.gasUsed − Σ actualGasUsed      (what PVG must cover)
```

Each report also records rundler's prediction for the same packed op: the
`pre_verification_execution_gas_limit` (what estimation returns) and the floor-aware
`required_pre_verification_gas` (what precheck and the builder enforce). It uses a ChainSpec
of rundler defaults with EIP-7623 enabled. `predicted − unmetered` < 0 means the bundler
loses that gas.

`ProbePaymaster.postOp` burns its remaining gas, so the postOp path has no penalty either.
E2's `penalty_check` verifies this: raising the postOp limit must raise metered gas by exactly
the increase and leave unmetered gas unchanged.

### E0 — reading the report

- `base_tx_gas`: plain call to an existing EOA. Compare with `transaction_intrinsic_gas`.
- `new_account_extra_gas`: value to a never-seen address minus value to an existing one.
- `per_byte.eoa_*`: calldata-only tx, so this is `max(standard, floor)`, normally the floor.
  Compare with `eip7623_calldata_floor_*`.
- `per_byte.burner_*`: execution dominates, so this is standard pricing unless the floor
  still binds. Compare with `calldata_*_byte_gas`.
- `receipts_match_charges`: `receipt.gasUsed` equals the sender's balance change divided
  by `effectiveGasPrice`. Later experiments use `receipt.gasUsed` as the bundler's cost,
  so if this is `false` stop and investigate first.

## Baseline: anvil `--hardfork prague` (foundry 1.8.3)

These results validate the method against rundler's current constants.

- **E0**: base 21,000; value to a new account +0; standard 4 / 16; floor 10 / 40; receipts match
  charges. All match rundler's ChainSpec defaults exactly.
- **E2**: `unmetered(N)` is linear in N (residuals < 10 gas).

  | typical op                   | shared   | per op   | rundler (per op, shared) | N=1 predicted − measured |
  | ---------------------------- | -------- | -------- | ------------------------ | ------------------------ |
  | deployed, any payer          | ≈ 32,710 | ≈ 12,200–12,840 | ≈ 23,930–24,520, 21,000 | +27 … +32 (postOp −36) |
  | deploy in op, any payer      | ≈ 32,705 | ≈ 13,140–13,790 | ≈ 24,880–25,480, 21,000 | +42 … +47 (postOp −22) |

  At N=1 rundler is exact to within 50 gas. That is how `per_user_op_v0_7_gas = 19,500` was
  calibrated. For N>1 rundler overcharges each extra op by ≈ 11.7k, because ≈ 11.7k of real
  per-bundle overhead is booked per op. Beneficiary: an existing third-party account adds
  2,512 and a fresh one 27,512. Self-pay with a zero deposit costs the same unmetered gas as
  prefunded, because the refund write's 20k is offset by the EIP-3529 refund of the earlier
  clear. At N=5 the refund cap bites (+1.8k).
- **E3**: signature bytes cost 4 / 16 per byte, plain calldata. callData bytes cost ≈ 4.26 per
  zero byte, because the EntryPoint also copies them. Rundler charges `4 + 4/32` per byte for
  both, so it overcharges signatures slightly (+534 at 4 KiB) and undercharges callData
  (−633 at 4 KiB). When the floor binds, rundler's floor-aware requirement overcharges by
  13–21k.

- **E4**: every authorization costs +12,500 unmetered for every authority kind (empty,
  funded, re-delegation to the same or another delegate). That is 25,000 charged minus the
  12,500 refund. The authorization also warms the sender, so metered gas drops by 2,500.
  Rundler charges 25,000 per authorization, so it overcharges by 12,500 here. **Anvil caveat:**
  anvil refunds even an authority that has never been used, although EIP-7702 refunds only
  when the authority exists. A plain type-4 transaction costs 36,800 for both an empty and a
  funded authority. So the empty-authority case must come from the devnet.
- **E5**: clearing a slot allocated earlier in the same bundle, whether by another op
  (cross-op) or by the op's own postOp (cross-span), costs the clearing op about +1k metered.
  It also lowers unmetered gas by about 19,900, because the EIP-3529 refund reduces gasUsed
  after metering. The bundler gains; nothing wraps. Two zero-deposit ops from one sender cost
  12.6k less unmetered than two distinct senders. Draining a paymaster deposit to exactly zero
  costs the same as a well-funded paymaster. These are the pre-8037 references. Under
  EIP-8037 the same clears refill `gas_left` inside a metering span, which is where
  `gasleft()` deltas can wrap.

`anvil --hardfork amsterdam` (foundry 1.8.3) prices gas exactly like prague. E0 is identical,
and a fresh-slot contract creation costs 75,180 on both. So it cannot stand in for a
Glamsterdam chain, and the devnet results are the authoritative ones.
