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

//! E2: shared and per-op unmetered overhead (EntryPoint v0.6 or v0.7).
//!
//! For each (payer, deploy-in-op) configuration, bundles of N identical ops from distinct
//! senders are measured and `unmetered(N) = shared + N * per_op` is fitted. `shared` is
//! compared with `transaction_intrinsic_gas` and `per_op` with rundler's static PVG for the
//! op (`calldata_gas_cost + per_user_op_v0_6_gas` or `per_user_op_v0_7_gas`).

use serde::Serialize;

use crate::{
    bundle::{BeneficiaryKind, BundleRun, BundleRunner, DEFAULT_POST_OP_GAS_LIMIT, OpSpec, Payer},
    fit::{self, LineFit},
    fixtures::{EpVersion, Fixtures},
};

const BUNDLE_SIZES: [usize; 4] = [1, 2, 3, 5];
const PAYERS: [Payer; 4] = [
    Payer::SelfZeroDeposit,
    Payer::SelfPrefunded,
    Payer::Paymaster,
    Payer::PaymasterPostOp,
];

#[derive(Debug, Serialize)]
struct ConfigResult {
    label: String,
    payer: Payer,
    deploy_in_op: bool,
    /// Set if a bundle failed; `runs` then holds the bundles that completed before it.
    error: Option<String>,
    fit: Option<LineFit>,
    /// Mean of rundler's static PVG over the ops (identical ops, so all equal).
    predicted_per_op: f64,
    /// Rundler's shared term: `transaction_intrinsic_gas`.
    predicted_shared: u64,
    /// `predicted_per_op - fit.slope`. Negative: rundler undercharges every op by this much.
    per_op_error: Option<f64>,
    /// `predicted_shared - fit.intercept`. Negative: rundler undercharges every bundle.
    shared_error: Option<f64>,
    runs: Vec<BundleRun>,
}

#[derive(Debug, Serialize)]
struct BeneficiaryResult {
    beneficiary: BeneficiaryKind,
    /// Unmetered gas minus the same bundle with the bundler as beneficiary.
    extra_unmetered_gas: i128,
    run: BundleRun,
}

#[derive(Debug, Serialize)]
struct PenaltyCheck {
    post_op_gas_limits: [u128; 2],
    actual_gas_used: [u128; 2],
    unmetered_gas: [i128; 2],
    /// `ProbePaymaster.postOp` burns its whole limit, so with no penalty `actualGasUsed` grows
    /// by exactly the limit increase (within the burn loop's granularity). With a penalty it
    /// grows by 10% more.
    no_penalty: bool,
}

#[derive(Debug, Serialize)]
struct Summary {
    /// `per_op` of self-pay with zero deposit minus self-pay with a prefunded deposit, on a
    /// deployed account: the post-metering refund write that re-creates a zeroed deposit.
    zero_deposit_refund_write_gas: Option<f64>,
    /// `per_op` of deploy-in-op minus deployed, self-pay prefunded: unmetered deploy overhead.
    deploy_extra_per_op_gas: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    experiment: &'static str,
    fixtures: Fixtures,
    summary: Summary,
    configs: Vec<ConfigResult>,
    beneficiaries: Vec<BeneficiaryResult>,
    penalty_check: Option<PenaltyCheck>,
}

/// Runs the experiment. `only`, if set, is a comma-separated list; only parts whose label
/// contains one of its entries run:
/// config labels such as `Paymaster/deploy`, `beneficiary` and `penalty-check`. A failing
/// config is recorded with its error and the rest still run.
pub async fn run(runner: &BundleRunner<'_>, only: Option<&str>) -> anyhow::Result<Report> {
    let selected =
        |label: &str| only.is_none_or(|o| o.split(',').any(|o| label.contains(o.trim())));
    let mut configs = Vec::new();
    for deploy_in_op in [false, true] {
        for payer in PAYERS {
            if selected(&config_label(payer, deploy_in_op)) {
                configs.push(run_config(runner, payer, deploy_in_op).await);
            }
        }
    }

    let mut beneficiaries = Vec::new();
    if selected("beneficiary") {
        let baseline_spec = OpSpec::typical(Payer::SelfPrefunded, false);
        let baseline = runner
            .run(
                "beneficiary/bundler",
                std::slice::from_ref(&baseline_spec),
                BeneficiaryKind::Bundler,
            )
            .await?;
        for (kind, label) in [
            (BeneficiaryKind::Existing, "beneficiary/existing"),
            (BeneficiaryKind::Fresh, "beneficiary/fresh"),
        ] {
            let run = runner
                .run(label, std::slice::from_ref(&baseline_spec), kind)
                .await?;
            beneficiaries.push(BeneficiaryResult {
                beneficiary: kind,
                extra_unmetered_gas: run.unmetered_gas - baseline.unmetered_gas,
                run,
            });
        }
    }

    // v0.6 has no unused-gas penalty to check.
    let penalty_check =
        if runner.fixtures.entry_point_version == EpVersion::V0_7 && selected("penalty-check") {
            Some(penalty_check(runner).await?)
        } else {
            None
        };

    let per_op = |payer, deploy| {
        configs
            .iter()
            .find(|c| c.payer == payer && c.deploy_in_op == deploy)
            .and_then(|c| c.fit.as_ref())
            .map(|f| f.slope)
    };
    let diff = |a: Option<f64>, b: Option<f64>| a.zip(b).map(|(a, b)| a - b);
    let summary = Summary {
        zero_deposit_refund_write_gas: diff(
            per_op(Payer::SelfZeroDeposit, false),
            per_op(Payer::SelfPrefunded, false),
        ),
        deploy_extra_per_op_gas: diff(
            per_op(Payer::SelfPrefunded, true),
            per_op(Payer::SelfPrefunded, false),
        ),
    };

    Ok(Report {
        experiment: "e2-unmetered-overhead",
        fixtures: runner.fixtures.clone(),
        summary,
        configs,
        beneficiaries,
        penalty_check,
    })
}

fn config_label(payer: Payer, deploy_in_op: bool) -> String {
    format!(
        "{payer:?}/{}",
        if deploy_in_op { "deploy" } else { "deployed" }
    )
}

async fn run_config(runner: &BundleRunner<'_>, payer: Payer, deploy_in_op: bool) -> ConfigResult {
    let spec = OpSpec::typical(payer, deploy_in_op);
    let label = config_label(payer, deploy_in_op);
    let mut runs = Vec::new();
    let mut error = None;
    for n in BUNDLE_SIZES {
        match runner
            .run(
                label.clone(),
                &vec![spec.clone(); n],
                BeneficiaryKind::Bundler,
            )
            .await
        {
            Ok(run) => runs.push(run),
            Err(e) => {
                eprintln!("{label} (n={n}): FAILED: {e:#}");
                error = Some(format!("n={n}: {e:#}"));
                break;
            }
        }
    }

    let points: Vec<(f64, f64)> = runs
        .iter()
        .map(|r| (r.n as f64, r.unmetered_gas as f64))
        .collect();
    let fit = fit::line(&points);
    let statics: Vec<f64> = runs
        .iter()
        .flat_map(|r| r.ops.iter().map(|o| o.predicted_static_pvg as f64))
        .collect();
    let predicted_per_op = statics.iter().sum::<f64>() / statics.len().max(1) as f64;
    let predicted_shared = runner.spec.transaction_intrinsic_gas;

    ConfigResult {
        label,
        payer,
        deploy_in_op,
        error,
        per_op_error: fit.as_ref().map(|f| predicted_per_op - f.slope),
        shared_error: fit.as_ref().map(|f| predicted_shared as f64 - f.intercept),
        fit,
        predicted_per_op,
        predicted_shared,
        runs,
    }
}

async fn penalty_check(runner: &BundleRunner<'_>) -> anyhow::Result<PenaltyCheck> {
    let limits = [DEFAULT_POST_OP_GAS_LIMIT, DEFAULT_POST_OP_GAS_LIMIT + 5_000];
    let mut used = [0u128; 2];
    let mut unmetered = [0i128; 2];
    for (i, limit) in limits.iter().enumerate() {
        let mut spec = OpSpec::typical(Payer::PaymasterPostOp, false);
        spec.post_op_gas_limit = *limit;
        let run = runner
            .run(
                format!("penalty-check/postOp={limit}"),
                &[spec],
                BeneficiaryKind::Bundler,
            )
            .await?;
        used[i] = run.ops[0].actual_gas_used;
        unmetered[i] = run.unmetered_gas;
    }
    let limit_increase = (limits[1] - limits[0]) as i128;
    let used_increase = used[1] as i128 - used[0] as i128;
    Ok(PenaltyCheck {
        post_op_gas_limits: limits,
        actual_gas_used: used,
        unmetered_gas: unmetered,
        no_penalty: (used_increase - limit_increase).abs() < limit_increase / 20,
    })
}
