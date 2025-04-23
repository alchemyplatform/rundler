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
use rundler_provider::{BlockHashOrNumber, DAGasProvider};
use rundler_types::{chain::ChainSpec, da::DAGasData, UserOperation};
use tracing::instrument;

/// Returns the required pre_verification_gas for the given user operation
///
/// `full_op` is either the user operation submitted via `sendUserOperation`
/// or the user operation that was submitted via `estimateUserOperationGas` and filled
/// in via its `max_fill()` call. It is used to calculate the static portion of the pre_verification_gas
///
/// `random_op` is either the user operation submitted via `sendUserOperation`
/// or the user operation that was submitted via `estimateUserOperationGas` and filled
/// in via its `random_fill()` call. It is used to calculate the DA portion of the pre_verification_gas
/// on networks that require it.
///
/// Networks that require Data Availability (DA) pre_verification_gas are those that charge extra calldata fees
/// that can scale based on DA gas prices.
///
#[instrument(skip_all)]
pub async fn estimate_pre_verification_gas<UO: UserOperation, E: DAGasProvider<UO = UO>>(
    chain_spec: &ChainSpec,
    entry_point: &E,
    full_op: &UO,
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

    Ok(full_op.required_pre_verification_gas(chain_spec, bundle_size, da_gas))
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
        op.required_pre_verification_gas(chain_spec, bundle_size, da_gas),
        uo_data,
    ))
}
