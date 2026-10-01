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

//! E3: size sweep (EntryPoint v0.7).
//!
//! Single-op bundles on a deployed account with a prefunded deposit, growing one field at
//! a time. The two fields cost different unmetered gas:
//! - `callData` is tx calldata *and* is ABI-encoded into memory for `innerHandleOp` and
//!   decoded again there, both outside the metered spans;
//! - `signature` is only tx calldata on the unmetered side (its copy into the account's
//!   `validateUserOp` call is metered).
//!
//! Rundler prices every packed-op byte the same way (`calldata_*_byte_gas` plus
//! `per_user_op_word_gas` per word), so the slopes show where that model is off. Points
//! where the calldata floor binds are flagged and excluded from the fits.

use alloy_primitives::Bytes;
use serde::Serialize;

use crate::{
    bundle::{BeneficiaryKind, BundleRunner, OpSpec, Payer, pseudo_random_bytes},
    fit::{self, LineFit},
    fixtures::Fixtures,
};

const SIZES: [usize; 5] = [4, 256, 1024, 4096, 16384];

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Field {
    CallData,
    Signature,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Fill {
    Zero,
    NonZero,
}

#[derive(Debug, Serialize)]
struct Point {
    size: usize,
    unmetered_gas: i128,
    predicted_pvg: u128,
    /// Positive: rundler overcharges; negative: the bundler loses this much.
    predicted_minus_unmetered: i128,
    /// Rundler's floor-aware requirement (what precheck and the builder enforce).
    predicted_required_pvg: u128,
    predicted_required_minus_unmetered: i128,
    floor_bound: bool,
    tx_hash: alloy_primitives::B256,
}

#[derive(Debug, Serialize)]
struct Sweep {
    field: Field,
    fill: Fill,
    /// Unmetered gas per byte of the field (floor-bound points excluded).
    measured: Option<LineFit>,
    /// Rundler's predicted PVG per byte of the field.
    predicted: Option<LineFit>,
    points: Vec<Point>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    experiment: &'static str,
    fixtures: Fixtures,
    sweeps: Vec<Sweep>,
}

pub async fn run(runner: &BundleRunner<'_>) -> anyhow::Result<Report> {
    let mut sweeps = Vec::new();
    for field in [Field::CallData, Field::Signature] {
        for fill in [Fill::Zero, Fill::NonZero] {
            sweeps.push(run_sweep(runner, field, fill).await?);
        }
    }
    Ok(Report {
        experiment: "e3-size-sweep",
        fixtures: runner.fixtures.clone(),
        sweeps,
    })
}

async fn run_sweep(runner: &BundleRunner<'_>, field: Field, fill: Fill) -> anyhow::Result<Sweep> {
    let mut points = Vec::new();
    for size in SIZES {
        let bytes: Bytes = match fill {
            Fill::Zero => vec![0u8; size].into(),
            Fill::NonZero => pseudo_random_bytes(size),
        };
        let mut spec = OpSpec::typical(Payer::SelfPrefunded, false);
        match field {
            Field::CallData => spec.call_data = bytes,
            Field::Signature => spec.signature = bytes,
        }
        let run = runner
            .run(
                format!("{field:?}/{fill:?}/{size}"),
                &[spec],
                BeneficiaryKind::Bundler,
            )
            .await?;
        points.push(Point {
            size,
            unmetered_gas: run.unmetered_gas,
            predicted_pvg: run.predicted_pvg_total,
            predicted_minus_unmetered: run.predicted_minus_unmetered,
            predicted_required_pvg: run.predicted_required_pvg_total,
            predicted_required_minus_unmetered: run.predicted_required_minus_unmetered,
            floor_bound: run.floor.floor_bound,
            tx_hash: run.tx.tx_hash,
        });
    }

    let unbound: Vec<&Point> = points.iter().filter(|p| !p.floor_bound).collect();
    let measured = fit::line(
        &unbound
            .iter()
            .map(|p| (p.size as f64, p.unmetered_gas as f64))
            .collect::<Vec<_>>(),
    );
    let predicted = fit::line(
        &unbound
            .iter()
            .map(|p| (p.size as f64, p.predicted_pvg as f64))
            .collect::<Vec<_>>(),
    );
    Ok(Sweep {
        field,
        fill,
        measured,
        predicted,
        points,
    })
}
