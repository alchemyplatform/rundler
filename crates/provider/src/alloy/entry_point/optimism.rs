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

use alloy_primitives::{ruint::UintTryTo, Address, Bytes};
use alloy_provider::Provider as AlloyProvider;
use alloy_sol_types::sol;
use alloy_transport::Transport;
use anyhow::Context;

use crate::ProviderResult;

// From https://github.com/ethereum-optimism/optimism/blob/f93f9f40adcd448168c6ea27820aeee5da65fcbd/packages/contracts-bedrock/src/L2/GasPriceOracle.sol#L54
sol! {
    #[sol(rpc)]
    interface GasPriceOracle {
        function getL1Fee(bytes memory _data) external view returns (uint256);
    }
}

pub(crate) async fn estimate_l1_gas<AP: AlloyProvider<T>, T: Transport + Clone>(
    provider: AP,
    oracle_address: Address,
    data: Bytes,
    gas_price: u128,
) -> ProviderResult<u128> {
    let oracle = GasPriceOracle::GasPriceOracleInstance::new(oracle_address, provider);

    let l1_fee: u128 = oracle
        .getL1Fee(data)
        .call()
        .await?
        ._0
        .uint_try_to()
        .context("failed to convert L1 fee to u128")?;

    Ok(l1_fee.checked_div(gas_price).unwrap_or(u128::MAX))
}
