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

use alloy_primitives::B256;
use metrics::Histogram;
use rundler_provider::{BlockHashOrNumber, DAGasProvider, FeeEstimator};
use rundler_types::{chain::ChainSpec, da::DAGasData, UserOperation};
use rundler_utils::guard_timer::CustomTimerGuard;
use tracing::instrument;

/// Estimates only the DA gas portion for the given user operation
///
/// `random_op` is either the user operation submitted via `sendUserOperation`
/// or the user operation that was submitted via `estimateUserOperationGas` and filled
/// in via its `random_fill()` call. It is used to calculate the DA portion of the pre_verification_gas
/// on networks that require it.
///
/// Networks that require Data Availability (DA) pre_verification_gas are those that charge extra calldata fees
/// that can scale based on DA gas prices.
///
/// Returns estimated da gas
#[instrument(skip_all)]
async fn estimate_da_gas_only<UO: UserOperation, E: DAGasProvider<UO = UO>>(
    chain_spec: &ChainSpec,
    entry_point: &E,
    random_op: &UO,
    block: BlockHashOrNumber,
    gas_price: u128,
) -> anyhow::Result<u128> {
    // TODO(bundle): assuming a bundle size of 1
    let bundle_size = 1;

    let da_gas = if chain_spec.da_pre_verification_gas {
        entry_point
            .calc_da_gas(random_op.clone(), block, gas_price, bundle_size)
            .await?
            .0
    } else {
        0
    };

    Ok(da_gas)
}

/// Estimates only the DA gas portion for the given user operation with fee estimation
///
/// This function handles the gas price calculation internally and is meant to be called
/// from the estimation implementations.
///
/// Returns estimated da gas
#[instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
pub async fn estimate_da_gas_with_fees<
    UO: UserOperation,
    E: DAGasProvider<UO = UO>,
    F: FeeEstimator,
>(
    chain_spec: &ChainSpec,
    entry_point: &E,
    fee_estimator: &F,
    random_op: &UO,
    max_fee_per_gas: Option<u128>,
    max_priority_fee_per_gas: Option<u128>,
    block: BlockHashOrNumber,
    pvg_timer: Histogram,
) -> anyhow::Result<u128> {
    let _timer = CustomTimerGuard::new(pvg_timer);
    let gas_price = if !chain_spec.da_pre_verification_gas {
        return Ok(0);
    } else {
        let block_hash = match block {
            BlockHashOrNumber::Hash(hash) => hash,
            BlockHashOrNumber::Number(_) => {
                return Err(anyhow::anyhow!(
                    "Block number not supported for fee estimation"
                ))
            }
        };
        let (bundle_fees, base_fee) = fee_estimator.required_bundle_fees(block_hash, None).await?;
        if let (Some(max_fee), Some(prio_fee)) = (
            max_fee_per_gas.filter(|fee| *fee != 0),
            max_priority_fee_per_gas.filter(|fee| *fee != 0),
        ) {
            std::cmp::min(max_fee, base_fee.saturating_add(prio_fee))
        } else {
            base_fee.saturating_add(bundle_fees.max_priority_fee_per_gas)
        }
    };

    estimate_da_gas_only(chain_spec, entry_point, random_op, block, gas_price).await
}

/// Calculate the required pre_verification_gas for the given user operation and the provided base fee.
///
/// The effective gas price is calculated as min(base_fee + max_priority_fee_per_gas, max_fee_per_gas)
#[instrument(skip_all)]
pub async fn calc_required_pre_verification_gas<UO: UserOperation, E: DAGasProvider<UO = UO>>(
    chain_spec: &ChainSpec,
    entry_point: &E,
    op: &UO,
    block_hash: B256,
    base_fee: u128,
    verification_efficiency_accept_threshold: f64,
) -> anyhow::Result<(u128, DAGasData)> {
    // TODO(bundle): assuming a bundle size of 1
    let bundle_size = 1;

    let (da_gas, uo_data) = if chain_spec.da_pre_verification_gas {
        let (da_gas, uo_data, _) = entry_point
            .calc_da_gas(
                op.clone(),
                block_hash.into(),
                op.gas_price(base_fee),
                bundle_size,
            )
            .await?;
        (da_gas, uo_data)
    } else {
        (0, DAGasData::Empty)
    };

    Ok((
        op.required_pre_verification_gas(
            chain_spec,
            bundle_size,
            da_gas,
            Some(verification_efficiency_accept_threshold),
        ),
        uo_data,
    ))
}
