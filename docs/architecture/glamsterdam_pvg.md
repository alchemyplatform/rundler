# Glamsterdam pre-verification gas

`preVerificationGas` pays the bundler back for the gas the EntryPoint does not meter. Under Glamsterdam, part of that gas depends on on-chain state (EIP-8037 state gas), so on a chain with a `glamsterdam_activation` rundler reads that state when it computes or checks PVG.

## Constant terms

Besides the schedule values in [Chain Specification](./chain_spec.md#glamsterdam-gas-schedule-values), the static PVG of every op adds `call_data_word_gas` (6 under Glamsterdam, 0 before) per 32-byte word of its `callData`. The EntryPoint ABI-encodes `callData` into memory for `innerHandleOp` and decodes it there, outside its metered spans. Measured on the devnet, that costs about 5 gas per word on top of what `per_user_op_word_gas` charges for every byte of the packed op. Other fields (signature, initCode, paymasterData) are not copied this way and keep the existing pricing.

## State-dependent terms

`UserOperation::required_pre_verification_gas(.., &PvgState)` applies two terms to the execution gas, before the calldata floor top-up:

- **Zero-deposit refund write**, `state_pre_verification_gas`: adds `zero_deposit_refund_gas` (97,920). A self-paying op (no paymaster) whose sender has a zero EntryPoint deposit has that deposit taken to the prefund and back to zero during validation. The refund in `_postExecution` then re-creates the slot after the EntryPoint stops metering, at the price of a new storage slot. This happens once per sender per bundle; rundler charges every op whose sender's deposit is zero, which overcharges a second op from the same sender in one bundle.
- **EIP-7702 authority state**, `authorization_state_discount`: `authorization_gas_limit` is the worst case, `eip7702_authorization_gas` (235,606, an authority that does not exist). If the authority exists, `eip7702_authorization_new_account_gas` (183,600) is subtracted. If it already has code, `eip7702_authorization_delegation_gas` (35,190) is subtracted as well, leaving 16,816.

`PvgState` holds the sender's deposit (is it zero?) and the authority state (`Missing`, `NoCode`, `HasCode`). Unknown values are priced as the worst case. Before Glamsterdam all four fields are 0, so both terms are 0. On a chain without an activation no state is read.

## Where the state is read

| Component | When | State read |
| --- | --- | --- |
| Gas estimation (`sim/src/estimation`) | `eth_estimateUserOperationGas` | latest block, without the user's state override |
| Precheck (`sim/src/precheck.rs`) | pool admission | latest block; the `PvgState` is kept on the pool entry |
| Pool maintenance (`pool/src/mempool/pool.rs`) | every block | the state captured at precheck |
| Builder (`builder/src/bundle_proposer.rs`) | each bundle proposal | the bundle's block: PVG is re-checked on L1 too, and the zero-deposit gas is added to the bundle gas limit |

All reads go through `rundler_sim::gas::load_pvg_state`. The state is read as soon as an activation is configured, also before it, so operations admitted before the fork are not repriced as the worst case after it. The bundle gas limit and the delegation sender keep pricing authorizations at the worst case.

## Limits

- The v0.6 per-op value is provisional until it is measured on a v0.6 EntryPoint.
- Bundles must stay at or below the EIP-7825 cap (`transaction_gas_limit = 16777216`). Above it the EIP-8037 state-gas reservoir is non-empty, and the EntryPoint no longer sees all state gas. Gas estimation must stay at or below it too (`--max_gas_estimation_gas`).
- Clearing a slot that another op allocated earlier in the same bundle credits the refill to the `handleOps` frame, inside the clearing op's validation span. That lowers the clearing op's measured gas, and can make the EntryPoint's `gasleft()` subtraction underflow when the refill exceeds the span's own gas. Pricing does not address this.
