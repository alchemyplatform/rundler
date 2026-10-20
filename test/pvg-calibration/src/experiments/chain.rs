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

//! E0: chain calibration.
//!
//! Measures, with plain transactions, the transaction-level prices that the PVG formula
//! hardcodes as ChainSpec constants: the base transaction cost, the cost of a value
//! transfer to a new account, standard calldata pricing and the calldata floor
//! (EIP-7623, or EIP-7976 on Glamsterdam). It also checks that `receipt.gasUsed` is what
//! the sender is actually charged, which later experiments rely on.

use alloy_network::TransactionBuilder;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rpc_types_eth::TransactionRequest;
use rundler_types::chain::ChainSpec;
use serde::Serialize;

use crate::{
    contracts::Burner,
    harness::{ChainInfo, Harness, TxOutcome},
};

/// Calldata sizes, in bytes, for the per-byte measurements.
const CALLDATA_SIZES: [usize; 3] = [256, 1024, 4096];

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Target {
    /// The harness EOA itself.
    Sender,
    /// A random address with no history, funded by the first case that targets it.
    Fresh,
    /// The contract that burns a fixed amount of gas.
    Burner,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Fill {
    Zero,
    NonZero,
}

struct Case {
    name: String,
    target: Target,
    value: U256,
    calldata: Option<(Fill, usize)>,
}

#[derive(Debug, Serialize)]
struct CaseResult {
    name: String,
    target: Target,
    to: Address,
    value: U256,
    calldata_fill: Option<Fill>,
    calldata_len: usize,
    outcome: TxOutcome,
}

/// Per-byte calldata price at one size, from the EOA (calldata-only) and Burner
/// (execution-dominated) variants.
#[derive(Debug, Serialize)]
struct PerByte {
    size: usize,
    /// Gas per byte of a calldata-only tx: `max(standard, floor)`. Expected to be the floor.
    eoa_zero: f64,
    eoa_non_zero: f64,
    /// Gas per byte when execution dominates: standard pricing unless the floor still binds.
    burner_zero: f64,
    burner_non_zero: f64,
}

#[derive(Debug, Serialize)]
struct Derived {
    /// Plain call to an existing EOA, no value, no data.
    base_tx_gas: u64,
    /// Self-transfer, no value, no data.
    self_tx_gas: u64,
    /// Extra cost of sending value to an existing account.
    value_transfer_extra_gas: i64,
    /// Extra cost of sending value to an account that does not exist yet.
    new_account_extra_gas: i64,
    /// Execution cost of the Burner with empty calldata (above `base_tx_gas`).
    burner_execution_gas: i64,
    per_byte: Vec<PerByte>,
    /// Every case's `receipt.gasUsed` matched the balance-derived charge.
    receipts_match_charges: bool,
    /// Every case's `eth_estimateGas` was at least its `receipt.gasUsed`.
    estimates_cover_usage: bool,
}

/// What rundler's default (EIP-7623 enabled) ChainSpec assumes, for side-by-side reading.
#[derive(Debug, Serialize)]
struct Assumed {
    transaction_intrinsic_gas: u64,
    calldata_zero_byte_gas: u64,
    calldata_non_zero_byte_gas: u64,
    calldata_floor_zero_byte_gas: u64,
    calldata_floor_non_zero_byte_gas: u64,
}

#[derive(Debug, Serialize)]
pub struct Report {
    experiment: &'static str,
    chain: ChainInfo,
    sender: Address,
    burner: Address,
    fresh_account: Address,
    cases: Vec<CaseResult>,
    derived: Derived,
    assumed: Assumed,
}

impl Report {
    pub fn chain_id(&self) -> u64 {
        self.chain.chain_id
    }
}

pub async fn run(harness: &Harness) -> anyhow::Result<Report> {
    let chain = harness.chain_info().await?;
    let burner = harness
        .ensure_create2(B256::ZERO, &Burner::BYTECODE)
        .await?;
    let fresh_account = Address::random();

    let mut results = Vec::new();
    for case in cases() {
        let to = match case.target {
            Target::Sender => harness.sender,
            Target::Fresh => fresh_account,
            Target::Burner => burner,
        };
        let input = case
            .calldata
            .map(|(fill, len)| calldata(fill, len))
            .unwrap_or_default();
        let outcome = harness
            .send(
                TransactionRequest::default()
                    .with_to(to)
                    .with_value(case.value)
                    .with_input(input),
            )
            .await?;
        eprintln!(
            "{:<24} gas_used={:>8} estimate={:>8} charged={}",
            case.name,
            outcome.gas_used,
            outcome.estimate,
            outcome
                .charged_gas
                .map_or("n/a".to_string(), |g| g.to_string()),
        );
        results.push(CaseResult {
            name: case.name,
            target: case.target,
            to,
            value: case.value,
            calldata_fill: case.calldata.map(|(fill, _)| fill),
            calldata_len: case.calldata.map_or(0, |(_, len)| len),
            outcome,
        });
    }

    let derived = derive(&results)?;
    Ok(Report {
        experiment: "e0-chain-calibration",
        chain,
        sender: harness.sender,
        burner,
        fresh_account,
        cases: results,
        derived,
        assumed: assumed(),
    })
}

fn cases() -> Vec<Case> {
    let plain = |name: &str, target, value: u64| Case {
        name: name.to_string(),
        target,
        value: U256::from(value),
        calldata: None,
    };
    // Order matters: `fresh_value` must run first against the fresh account so that the
    // later `Fresh` cases target an account that exists.
    let mut cases = vec![
        plain("self_no_value", Target::Sender, 0),
        plain("fresh_value", Target::Fresh, 1),
        plain("existing_value", Target::Fresh, 1),
        plain("existing_no_value", Target::Fresh, 0),
        plain("burner_empty", Target::Burner, 0),
    ];
    for (target, prefix) in [(Target::Fresh, "eoa"), (Target::Burner, "burner")] {
        for size in CALLDATA_SIZES {
            for (fill, suffix) in [(Fill::Zero, "zero"), (Fill::NonZero, "non_zero")] {
                cases.push(Case {
                    name: format!("{prefix}_{suffix}_{size}"),
                    target,
                    value: U256::ZERO,
                    calldata: Some((fill, size)),
                });
            }
        }
    }
    cases
}

fn calldata(fill: Fill, len: usize) -> Bytes {
    let byte = match fill {
        Fill::Zero => 0x00,
        Fill::NonZero => 0xff,
    };
    Bytes::from(vec![byte; len])
}

fn derive(results: &[CaseResult]) -> anyhow::Result<Derived> {
    let gas = |name: &str| -> anyhow::Result<i64> {
        results
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.outcome.gas_used as i64)
            .ok_or_else(|| anyhow::anyhow!("missing case {name}"))
    };

    let base = gas("existing_no_value")?;
    let burner_empty = gas("burner_empty")?;
    let per_byte = CALLDATA_SIZES
        .iter()
        .map(|&size| -> anyhow::Result<PerByte> {
            let per = |name: String, reference: i64| -> anyhow::Result<f64> {
                Ok((gas(&name)? - reference) as f64 / size as f64)
            };
            Ok(PerByte {
                size,
                eoa_zero: per(format!("eoa_zero_{size}"), base)?,
                eoa_non_zero: per(format!("eoa_non_zero_{size}"), base)?,
                burner_zero: per(format!("burner_zero_{size}"), burner_empty)?,
                burner_non_zero: per(format!("burner_non_zero_{size}"), burner_empty)?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(Derived {
        base_tx_gas: base as u64,
        self_tx_gas: gas("self_no_value")? as u64,
        value_transfer_extra_gas: gas("existing_value")? - base,
        new_account_extra_gas: gas("fresh_value")? - gas("existing_value")?,
        burner_execution_gas: burner_empty - base,
        per_byte,
        receipts_match_charges: results.iter().all(|r| r.outcome.charge_matches_receipt()),
        estimates_cover_usage: results
            .iter()
            .all(|r| r.outcome.estimate >= r.outcome.gas_used),
    })
}

fn assumed() -> Assumed {
    let spec = ChainSpec {
        eip7623_enabled: true,
        ..ChainSpec::default()
    };
    Assumed {
        transaction_intrinsic_gas: spec.transaction_intrinsic_gas,
        calldata_zero_byte_gas: spec.calldata_zero_byte_gas,
        calldata_non_zero_byte_gas: spec.calldata_non_zero_byte_gas,
        calldata_floor_zero_byte_gas: spec.eip7623_calldata_floor_zero_byte_gas,
        calldata_floor_non_zero_byte_gas: spec.eip7623_calldata_floor_non_zero_byte_gas,
    }
}
