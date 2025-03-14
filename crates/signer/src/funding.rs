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

use std::{cmp, collections::HashMap, sync::Arc, time::Duration};

use alloy_eips::eip2718::Encodable2718;
use alloy_network::{EthereumWallet, TransactionBuilder, TxSigner};
use alloy_primitives::{Address, Bytes, PrimitiveSignature, B256, U256};
use metrics::{Counter, Gauge};
use metrics_derive::Metrics;
use parking_lot::RwLock;
use rundler_contracts::multicall3;
use rundler_provider::{EvmProvider, TransactionRequest};
use tokio::sync::Notify;

use crate::{
    manager::{FundingSignerManager, SignerStatus},
    utils,
};

const GAS_BASE: u64 = 50_000;
const GAS_PER_CALL: u64 = 40_000;

pub(crate) struct FunderSettings {
    pub fund_below_balance: U256,
    pub fund_to_balance: U256,
    pub chain_id: u64,
    pub multicall3_address: Address,
    pub poll_interval: Duration,
    pub poll_max_retries: u64,
    pub priority_fee_multiplier: u64,
    pub base_fee_multiplier: u64,

    pub signer: Arc<dyn TxSigner<PrimitiveSignature> + Send + Sync + 'static>,
}

pub(crate) async fn funding_task<P: EvmProvider>(
    settings: FunderSettings,
    provider: P,
    statuses: Arc<RwLock<HashMap<Address, SignerStatus>>>,
    notify: Arc<Notify>,
) {
    let funding_signer_address = settings.signer.address();
    let wallet = EthereumWallet::new(settings.signer.clone());
    let metrics = FunderMetrics::default();

    let _ = get_update_funder_balance(&provider, &metrics, funding_signer_address).await;

    loop {
        tokio::select! {
            // update the funding balance every 60 seconds
            _ = tokio::time::sleep(Duration::from_secs(60)) => {
                let _ = get_update_funder_balance(&provider, &metrics, funding_signer_address).await;
                continue;
            }
            // wait for notify
            _ = notify.notified() => {}
        }

        metrics.funding_attempts.increment(1);
        match funding_task_inner(
            &settings,
            &provider,
            &statuses,
            &wallet,
            funding_signer_address,
            &metrics,
        )
        .await
        {
            Ok(true) => {
                tracing::info!("Funding successful, but funding is still required");
                notify.notify_one();
            }
            Ok(false) => {
                tracing::info!("Funding successful, no more funding required");
            }
            Err(err) => {
                metrics.funding_errors.increment(1);
                tracing::error!(
                    "Error during funding, retrying after {}ms: {err:?}",
                    settings.poll_interval.as_millis()
                );
                tokio::time::sleep(settings.poll_interval).await;
                notify.notify_one();
            }
        }
    }
}

async fn funding_task_inner<P: EvmProvider>(
    settings: &FunderSettings,
    provider: &P,
    statuses: &Arc<RwLock<HashMap<Address, SignerStatus>>>,
    wallet: &EthereumWallet,
    funding_signer_address: Address,
    metrics: &FunderMetrics,
) -> anyhow::Result<bool> {
    let addresses = statuses.read().keys().cloned().collect::<Vec<_>>();
    let balances = provider.get_balances(addresses.clone()).await?;
    let mut to_fund = balances
        .into_iter()
        .filter_map(|(address, balance)| {
            if balance < settings.fund_below_balance {
                Some((address, settings.fund_to_balance - balance))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    // sort by amount, descending
    to_fund.sort_by_key(|(_, amount)| cmp::Reverse(*amount));

    let mut total = to_fund.iter().map(|(_, amount)| amount).sum::<U256>();
    let total_to_fund = to_fund.len();
    let funding_balance =
        get_update_funder_balance(provider, metrics, funding_signer_address).await?;

    if total > funding_balance {
        tracing::warn!("Not enough funding balance. Funding balance: {funding_balance}, total to fund: {total}. Partial funding will be attempted.");
        while total > funding_balance && !to_fund.is_empty() {
            let (_, amount) = to_fund.pop().unwrap();
            total -= amount;
        }
        if to_fund.is_empty() {
            anyhow::bail!("Not enough funding balance for any funding. Funding balance: {funding_balance}, total to fund: {total}");
        } else {
            tracing::warn!(
                "Partially funding {} of {} addresses",
                to_fund.len(),
                total_to_fund
            );
        }
    }

    let num_calls = to_fund.len() as u64;
    let calls = to_fund
        .into_iter()
        .map(|(address, amount)| multicall3::create_call_value_only(address, amount))
        .collect::<Vec<_>>();
    let call = multicall3::Multicall3::aggregate3ValueCall { calls };

    let (nonce, base_fee, priority_fee) = tokio::try_join!(
        provider.get_transaction_count(funding_signer_address),
        provider.get_pending_base_fee(),
        provider.get_max_priority_fee()
    )?;

    let priority_fee = priority_fee * settings.priority_fee_multiplier as u128;
    let max_fee_per_gas = base_fee * settings.base_fee_multiplier as u128 + priority_fee;
    let gas_limit = GAS_BASE + GAS_PER_CALL * num_calls;

    let tx = TransactionRequest::default()
        .with_call(&call)
        .with_value(total)
        .with_chain_id(settings.chain_id)
        .with_nonce(nonce)
        .with_from(funding_signer_address)
        .with_to(settings.multicall3_address)
        .with_max_fee_per_gas(max_fee_per_gas)
        .with_max_priority_fee_per_gas(priority_fee)
        .with_gas_limit(gas_limit)
        .build(&wallet)
        .await?;

    let mut raw_tx = vec![];
    tx.encode_2718(&mut raw_tx);
    let tx_bytes: Bytes = raw_tx.into();

    // wait for the funding to complete, if doesn't mine after max retries
    let tx_hash = provider
        .request::<_, B256>("eth_sendRawTransaction", (tx_bytes,))
        .await?;

    let mut found_tx = None;
    for _ in 0..settings.poll_max_retries {
        tokio::time::sleep(settings.poll_interval).await;

        let maybe_tx = provider.get_transaction_receipt(tx_hash).await?;
        let Some(tx) = maybe_tx else {
            tracing::debug!("Transaction not found, retrying");
            continue;
        };
        found_tx = Some(tx);
        break;
    }

    match found_tx {
        Some(tx) => {
            tracing::info!("Funding transaction {tx_hash} mined. Receipt: {tx:?}");
        }
        None => {
            anyhow::bail!("Funding transaction {tx_hash} not mined after max retries");
        }
    }

    metrics.funded_addresses.increment(num_calls);
    let _ = get_update_funder_balance(provider, metrics, funding_signer_address).await;
    let new_balances = provider.get_balances(addresses.clone()).await?;
    Ok(FundingSignerManager::update_signer_statuses(
        statuses,
        new_balances,
        Some(settings.fund_below_balance),
    ))
}

async fn get_update_funder_balance<P: EvmProvider>(
    provider: &P,
    metrics: &FunderMetrics,
    funding_signer_address: Address,
) -> anyhow::Result<U256> {
    match provider.get_balance(funding_signer_address, None).await {
        Ok(balance) => {
            utils::set_balance_gauge(
                &metrics.funding_account_balance,
                funding_signer_address,
                balance,
            );
            Ok(balance)
        }
        Err(err) => {
            anyhow::bail!("Error getting balance for funding account: {err}");
        }
    }
}

#[derive(Metrics)]
#[metrics(scope = "funder")]
struct FunderMetrics {
    #[metric(describe = "the number of funding attempts")]
    funding_attempts: Counter,
    #[metric(describe = "tne mumber of funding errors")]
    funding_errors: Counter,
    #[metric(describe = "the number of addresses that were funded")]
    funded_addresses: Counter,
    #[metric(describe = "the balance of the funding account")]
    funding_account_balance: Gauge,
}
