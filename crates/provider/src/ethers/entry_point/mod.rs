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

use ethers::{
    providers::Middleware,
    types::{Address, Bytes, Eip1559TransactionRequest, U256, U64},
};
use rundler_types::contracts::{
    arbitrum::node_interface::NodeInterface, optimism::gas_price_oracle::GasPriceOracle,
};

pub(crate) mod v0_6;
pub(crate) mod v0_7;

async fn estimate_arbitrum_l1_gas<P: Middleware + 'static>(
    arb_node: &NodeInterface<P>,
    address: Address,
    data: Bytes,
) -> anyhow::Result<U256> {
    let gas = arb_node
        .gas_estimate_l1_component(address, false, data)
        .call()
        .await?;
    Ok(U256::from(gas.0))
}

async fn estimate_optimism_l1_gas<P: Middleware + 'static>(
    opt_oracle: &GasPriceOracle<P>,
    address: Address,
    data: Bytes,
    gas_price: U256,
) -> anyhow::Result<U256> {
    // construct an unsigned transaction with default values just for L1 gas estimation
    let tx = Eip1559TransactionRequest::new()
        .from(Address::random())
        .to(address)
        .gas(U256::from(1_000_000))
        .max_priority_fee_per_gas(U256::from(100_000_000))
        .max_fee_per_gas(U256::from(100_000_000))
        .value(U256::from(0))
        .data(data)
        .nonce(U256::from(100_000))
        .chain_id(U64::from(100_000))
        .rlp();

    let l1_fee = opt_oracle.get_l1_fee(tx).call().await?;
    Ok(l1_fee.checked_div(gas_price).unwrap_or(U256::MAX))
}
