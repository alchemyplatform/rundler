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

use alloy_primitives::{Address, U256};
use metrics::Gauge;

pub(crate) fn set_balance_gauge(gauge: &Gauge, address: Address, balance: U256) {
    let eth_string = alloy_primitives::utils::format_ether(balance);
    match eth_string.parse::<f64>() {
        Ok(eth_f64) => {
            gauge.set(eth_f64);
            tracing::info!("account {address:?} balance: {eth_f64:.6}");
        }
        Err(err) => {
            tracing::error!("Parse balance {balance} to eth {eth_string} to f64 error {err:?}");
        }
    }
}
