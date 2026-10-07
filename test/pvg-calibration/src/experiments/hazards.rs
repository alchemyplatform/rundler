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

//! E5: storage shapes whose cost moves between metered and unmetered gas (EntryPoint v0.6 or v0.7).
//!
//! Under EIP-8037 a slot that is zero at transaction start costs state-gas when written.
//! Clearing it again in the same transaction refills that gas directly into `gas_left`,
//! instead of adding to the refund counter as EIP-3529 does today. That refill can land in a
//! different metering span from the charge, or after the EntryPoint stops metering. Each
//! group below pairs a hazard shape with a reference that differs only in the hazard:
//!
//! - **deposit**: two ops from the same zero-deposit sender (the deposit slot is re-created
//!   by each op's post-metering refund write), and a paymaster whose deposit is drained to
//!   exactly zero.
//! - **cross-op**: op A allocates a Scratch slot during validation, and op B in the same
//!   bundle clears it during its own validation.
//! - **cross-span**: one op allocates a slot during validation, and its paymaster's postOp
//!   clears it.
//!
//! On a pre-8037 chain these cost little and behave normally. On a Glamsterdam chain they
//! are where `gasleft()` deltas can wrap and unmetered gas can jump. Any case that fails
//! (e.g. `AA26`, `AA51`) is recorded with its error instead of aborting the run.

use alloy_primitives::{B256, Bytes, U256};
use serde::Serialize;

use crate::{
    bundle::{BeneficiaryKind, BundleRun, BundleRunner, OpSpec, Payer, scratch_signature},
    fixtures::{self, Fixtures},
};

/// `paymasterPostOpGasLimit` for the cross-span group: enough for `Scratch.clear`
/// (`ProbePaymaster.postOp` burns the rest, so there is no penalty). v0.7 only: v0.6 gives
/// postOp the op's `verificationGasLimit`.
const CROSS_SPAN_POST_OP_GAS_LIMIT: u128 = 60_000;

#[derive(Debug, Serialize)]
struct CaseResult {
    group: &'static str,
    name: &'static str,
    run: Option<BundleRun>,
    error: Option<String>,
}

impl CaseResult {
    fn unmetered(&self) -> Option<i128> {
        self.run.as_ref().map(|r| r.unmetered_gas)
    }

    fn metered(&self, op: usize) -> Option<u128> {
        self.run
            .as_ref()
            .and_then(|r| r.ops.get(op))
            .map(|o| o.actual_gas_used)
    }
}

/// Hazard minus reference, per group. `None` where a case failed (see its `error`).
#[derive(Debug, Serialize)]
struct Summary {
    /// Unmetered: same zero-deposit sender twice minus two distinct zero-deposit senders.
    same_sender_zero_deposit_extra_unmetered: Option<i128>,
    /// Unmetered: same prefunded sender twice minus two distinct prefunded senders (the
    /// warm-slot effect alone, to separate from the deposit effect).
    same_sender_prefunded_extra_unmetered: Option<i128>,
    /// Unmetered: paymaster deposit drained to exactly zero minus a well-funded paymaster.
    paymaster_exact_drain_extra_unmetered: Option<i128>,
    /// Op B metered gas when it clears op A's slot, minus when it does nothing.
    cross_op_clear_metered_delta: Option<i128>,
    /// Unmetered, same comparison.
    cross_op_clear_unmetered_delta: Option<i128>,
    /// Op metered gas when postOp clears the slot validation allocated, minus not clearing.
    cross_span_clear_metered_delta: Option<i128>,
    /// Unmetered, same comparison.
    cross_span_clear_unmetered_delta: Option<i128>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    experiment: &'static str,
    fixtures: Fixtures,
    summary: Summary,
    cases: Vec<CaseResult>,
}

pub async fn run(runner: &BundleRunner<'_>) -> anyhow::Result<Report> {
    let mut cases = Vec::new();
    deposit_group(runner, &mut cases).await?;
    cross_op_group(runner, &mut cases).await;
    cross_span_group(runner, &mut cases).await;

    let find = |name: &str| cases.iter().find(|c| c.name == name);
    let unmetered_delta = |a: &str, b: &str| {
        find(a)
            .and_then(CaseResult::unmetered)
            .zip(find(b).and_then(CaseResult::unmetered))
            .map(|(a, b)| a - b)
    };
    let metered_delta = |a: &str, b: &str, op: usize| {
        find(a)
            .and_then(|c| c.metered(op))
            .zip(find(b).and_then(|c| c.metered(op)))
            .map(|(a, b)| a as i128 - b as i128)
    };
    let summary = Summary {
        same_sender_zero_deposit_extra_unmetered: unmetered_delta(
            "same-sender-zero-deposit",
            "distinct-senders-zero-deposit",
        ),
        same_sender_prefunded_extra_unmetered: unmetered_delta(
            "same-sender-prefunded",
            "distinct-senders-prefunded",
        ),
        paymaster_exact_drain_extra_unmetered: unmetered_delta(
            "paymaster-exact-drain",
            "paymaster-funded",
        ),
        cross_op_clear_metered_delta: metered_delta("a-set/b-clear", "a-set/b-none", 1),
        cross_op_clear_unmetered_delta: unmetered_delta("a-set/b-clear", "a-set/b-none"),
        cross_span_clear_metered_delta: metered_delta(
            "validation-set/postop-clear",
            "validation-set/postop-none",
            0,
        ),
        cross_span_clear_unmetered_delta: unmetered_delta(
            "validation-set/postop-clear",
            "validation-set/postop-none",
        ),
    };
    eprintln!("{}", serde_json::to_string_pretty(&summary)?);

    Ok(Report {
        experiment: "e5-state-hazards",
        fixtures: runner.fixtures.clone(),
        summary,
        cases,
    })
}

async fn record(
    runner: &BundleRunner<'_>,
    cases: &mut Vec<CaseResult>,
    group: &'static str,
    name: &'static str,
    specs: &[OpSpec],
) {
    let (run, error) = match runner
        .run(format!("{group}/{name}"), specs, BeneficiaryKind::Bundler)
        .await
    {
        Ok(run) => (Some(run), None),
        Err(e) => {
            eprintln!("{group}/{name}: FAILED: {e:#}");
            (None, Some(format!("{e:#}")))
        }
    };
    cases.push(CaseResult {
        group,
        name,
        run,
        error,
    });
}

async fn deposit_group(
    runner: &BundleRunner<'_>,
    cases: &mut Vec<CaseResult>,
) -> anyhow::Result<()> {
    const GROUP: &str = "deposit";
    let max_fee = runner.default_max_fee().await?;

    for (payer, same, distinct) in [
        (
            Payer::SelfZeroDeposit,
            "same-sender-zero-deposit",
            "distinct-senders-zero-deposit",
        ),
        (
            Payer::SelfPrefunded,
            "same-sender-prefunded",
            "distinct-senders-prefunded",
        ),
    ] {
        let mut spec = OpSpec::typical(payer, false);
        spec.max_fee = Some(max_fee);
        record(
            runner,
            cases,
            GROUP,
            distinct,
            &[spec.clone(), spec.clone()],
        )
        .await;

        // Two ops (nonces 0 and 1) from one prepared account, funded for both.
        let salt = U256::from_be_bytes(B256::random().0);
        let prefund = runner.prefund(&spec, max_fee);
        let (account_value, deposit_value) = match payer {
            Payer::SelfZeroDeposit => (prefund * U256::from(4), U256::ZERO),
            _ => (U256::ZERO, prefund * U256::from(4)),
        };
        runner
            .setup_probes(vec![salt], true, account_value, deposit_value)
            .await?;
        let sender = runner.fixtures.account_address(salt);
        record(
            runner,
            cases,
            GROUP,
            same,
            &[
                spec.clone().with_sender(sender, 0),
                spec.clone().with_sender(sender, 1),
            ],
        )
        .await;
    }

    // A paymaster whose deposit is exactly the op's prefund: validation debits it to zero
    // (a slot that was non-zero at transaction start), and the post-metering refund writes it
    // back.
    let mut spec = OpSpec::typical(Payer::Paymaster, false);
    spec.max_fee = Some(max_fee);
    record(runner, cases, GROUP, "paymaster-funded", &[spec.clone()]).await;
    let paymaster = fixtures::ensure_paymaster(
        runner.harness,
        runner.fixtures.entry_point_version,
        runner.fixtures.entry_point,
        B256::random(),
    )
    .await?;
    fixtures::deposit_to(
        runner.harness,
        runner.fixtures.entry_point,
        paymaster,
        runner.prefund(&spec, max_fee),
    )
    .await?;
    spec.paymaster = Some(paymaster);
    record(runner, cases, GROUP, "paymaster-exact-drain", &[spec]).await;
    Ok(())
}

async fn cross_op_group(runner: &BundleRunner<'_>, cases: &mut Vec<CaseResult>) {
    const GROUP: &str = "cross-op";
    let scratch = runner.fixtures.scratch;
    let op = |action: u8, key: B256| {
        let mut spec = OpSpec::typical(Payer::SelfPrefunded, false);
        spec.signature = scratch_signature(action, key, scratch);
        spec
    };
    // A fresh key per case, so every slot is zero at transaction start.
    for (name, a, b) in [
        ("a-none/b-none", 0u8, 0u8),
        ("a-set/b-none", 1, 0),
        ("a-set/b-clear", 1, 2),
    ] {
        let key = B256::random();
        record(runner, cases, GROUP, name, &[op(a, key), op(b, key)]).await;
    }
}

async fn cross_span_group(runner: &BundleRunner<'_>, cases: &mut Vec<CaseResult>) {
    const GROUP: &str = "cross-span";
    let scratch = runner.fixtures.scratch;
    let op = |sig_action: u8, clear_in_post_op: bool, key: B256| {
        let mut spec = OpSpec::typical(Payer::PaymasterPostOp, false);
        spec.signature = scratch_signature(sig_action, key, scratch);
        spec.post_op_gas_limit = CROSS_SPAN_POST_OP_GAS_LIMIT;
        // Same length either way: mode byte, key, scratch. Mode 1 ignores the rest.
        let mut data = vec![if clear_in_post_op { 0x02 } else { 0x01 }];
        data.extend_from_slice(key.as_slice());
        data.extend_from_slice(scratch.as_slice());
        spec.paymaster_data = Some(Bytes::from(data));
        spec
    };
    for (name, action, clear) in [
        ("validation-none/postop-none", 0u8, false),
        ("validation-set/postop-none", 1, false),
        ("validation-set/postop-clear", 1, true),
    ] {
        record(
            runner,
            cases,
            GROUP,
            name,
            &[op(action, clear, B256::random())],
        )
        .await;
    }
}
