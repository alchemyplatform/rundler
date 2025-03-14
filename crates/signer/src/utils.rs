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

//! Signing and sending transaction utilities

use std::time::Duration;

use alloy_primitives::{Address, B256, U256};
use metrics::Gauge;
use rundler_provider::{EvmProvider, TransactionReceipt};

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

/// Wait for a transaction to be mined
pub async fn wait_for_txn(
    provider: &impl EvmProvider,
    tx_hash: B256,
    max_retries: u64,
    poll_interval: Duration,
) -> anyhow::Result<TransactionReceipt> {
    for _ in 0..max_retries {
        let maybe_tx = provider.get_transaction_receipt(tx_hash).await?;
        let Some(tx) = maybe_tx else {
            tracing::debug!(
                "Transaction not found, retrying after {}ms",
                poll_interval.as_millis()
            );
            tokio::time::sleep(poll_interval).await;
            continue;
        };
        return Ok(tx);
    }

    anyhow::bail!("Transaction {tx_hash} not found after {max_retries} retries");
}

/// Get the nonce and fees for a transaction
pub async fn get_nonce_and_fees(
    provider: &impl EvmProvider,
    address: Address,
    base_fee_mult: f64,
    priority_fee_mult: f64,
) -> anyhow::Result<(u64, u128, u128)> {
    let (nonce, base_fee, priority_fee) = tokio::try_join!(
        provider.get_transaction_count(address),
        provider.get_pending_base_fee(),
        provider.get_max_priority_fee()
    )?;

    let priority_fee = (priority_fee as f64 * priority_fee_mult) as u128;
    let max_fee_per_gas = (base_fee as f64 * base_fee_mult) as u128 + priority_fee;

    Ok((nonce, max_fee_per_gas, priority_fee))
}
