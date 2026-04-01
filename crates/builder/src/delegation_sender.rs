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

use std::{sync::Arc, time::Duration};

use alloy_network::TransactionBuilder7702;
use alloy_primitives::B256;
use anyhow::Context;
use rundler_provider::{EvmProvider, FeeEstimator, TransactionRequest};
use rundler_signer::SignerManager;
use rundler_types::{GasFees, authorization::Eip7702Auth, pool::NewHead};
use tokio::sync::broadcast;
use tracing::{info, warn};

/// Gas limit for a type-4 EIP-7702 delegation transaction.
/// Base intrinsic (21k) + per-auth cost (25k) + buffer.
const DELEGATION_GAS_LIMIT: u64 = 100_000;

/// Settings for the delegation sender.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    /// Number of blocks to wait before considering a tx stuck and bumping fees.
    pub max_blocks_to_wait_for_mine: u64,
    /// Maximum number of fee bumps before giving up entirely.
    pub max_fee_bumps: u64,
    /// Percentage to increase fees on each bump (e.g. 10 = 10 %).
    pub fee_bump_percent: u32,
    /// How long to wait for a signer to become available, in milliseconds.
    pub signer_wait_timeout_ms: u64,
}

/// Submits and tracks a single bundler-sponsored EIP-7702 delegation transaction.
///
/// Acquires a signer, submits the type-4 tx, then watches the shared head-event
/// stream to detect mining. If the tx does not mine within `max_blocks_to_wait_for_mine`
/// blocks it is replaced with bumped fees; after `max_fee_bumps` failed attempts the
/// call returns an error.
#[derive(Clone)]
pub struct DelegationSender<E, F> {
    signer_manager: Arc<dyn SignerManager>,
    provider: E,
    fee_estimator: F,
    settings: Settings,
}

impl<E, F> DelegationSender<E, F>
where
    E: EvmProvider,
    F: FeeEstimator,
{
    pub(crate) fn new(
        signer_manager: Arc<dyn SignerManager>,
        provider: E,
        fee_estimator: F,
        settings: Settings,
    ) -> Self {
        Self {
            signer_manager,
            provider,
            fee_estimator,
            settings,
        }
    }

    /// Submit a delegation and wait for it to be mined.
    ///
    /// `heads_rx` must be a fresh subscriber to the shared new-heads broadcast
    /// channel so that this call receives every block from submission onwards.
    pub(crate) async fn send(
        &self,
        auth: Eip7702Auth,
        heads_rx: broadcast::Receiver<Arc<NewHead>>,
    ) -> anyhow::Result<B256> {
        let signer = self.acquire_signer().await?;
        let result = self.run(&signer, auth, heads_rx).await;
        self.signer_manager.return_lease(signer);
        result
    }

    // --- private helpers ---

    async fn acquire_signer(&self) -> anyhow::Result<rundler_signer::SignerLease> {
        const RETRY_INTERVAL_MS: u64 = 500;
        let max_attempts = (self.settings.signer_wait_timeout_ms / RETRY_INTERVAL_MS).max(1);

        for attempt in 0..max_attempts {
            if let Some(s) = self.signer_manager.lease_signer() {
                return Ok(s);
            }
            if attempt == 0 {
                tracing::debug!(
                    "no signer immediately available for delegation, \
                     waiting for a bundle sender idle period"
                );
            }
            tokio::time::sleep(Duration::from_millis(RETRY_INTERVAL_MS)).await;
        }

        anyhow::bail!(
            "no signer available for sponsored delegation after {}ms; all signers are busy",
            self.settings.signer_wait_timeout_ms,
        )
    }

    async fn run(
        &self,
        signer: &rundler_signer::SignerLease,
        auth: Eip7702Auth,
        mut heads_rx: broadcast::Receiver<Arc<NewHead>>,
    ) -> anyhow::Result<B256> {
        let eoa = auth
            .recover_authority()
            .context("failed to recover EOA from authorization")?;

        // Nonce the tx will use. Held constant across fee-bump retries so each
        // replacement supersedes the previous pending tx rather than queuing behind it.
        let nonce = self
            .provider
            .get_transaction_count(signer.address())
            .await
            .context("failed to get signer nonce")?;

        let (initial_fees, _) = self
            .fee_estimator
            .latest_bundle_fees()
            .await
            .context("failed to get bundle fees")?;

        let mut current_fees = initial_fees;

        for attempt in 0..=self.settings.max_fee_bumps {
            if attempt > 0 {
                current_fees = current_fees.increase_by_percent(self.settings.fee_bump_percent);
                info!(
                    "bumping delegation fees (attempt {attempt}): \
                     max_fee={}, priority_fee={}",
                    current_fees.max_fee_per_gas, current_fees.max_priority_fee_per_gas,
                );
            }

            let tx_hash = self.submit_tx(signer, &auth, nonce, current_fees).await?;
            info!("delegation tx submitted (attempt {attempt}): {tx_hash} for eoa {eoa}");

            // `until_block` is set lazily on the first head event so the timeout
            // is relative to the block that arrives after submission rather than
            // requiring an extra RPC call.
            let mut until_block: Option<u64> = None;

            let timed_out = loop {
                let head = match heads_rx.recv().await {
                    Ok(h) => h,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("delegation sender heads receiver lagged by {n} blocks");
                        // We may have missed the mining event. Check the receipt
                        // before continuing to wait.
                        if self.receipt_exists(tx_hash).await {
                            info!("delegation tx {tx_hash} confirmed (after lag) for eoa {eoa}");
                            return Ok(tx_hash);
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        anyhow::bail!("new-heads broadcast channel closed unexpectedly");
                    }
                };

                let block_number = head.block_number;
                let until = *until_block
                    .get_or_insert(block_number + self.settings.max_blocks_to_wait_for_mine);

                if let Some(update) = head
                    .address_updates
                    .iter()
                    .find(|u| u.address == signer.address())
                {
                    // Happy path: pool reported our tx hash in this block's update.
                    if update.mined_tx_hashes.contains(&tx_hash) {
                        info!(
                            "delegation tx {tx_hash} mined at block {block_number} for eoa {eoa}"
                        );
                        return Ok(tx_hash);
                    }

                    // A tx at or above our nonce mined but it wasn't ours according
                    // to this block's update. Two possibilities:
                    //   1. We lagged earlier and our tx mined in a previous block.
                    //   2. Another tx consumed our nonce (replacement or external).
                    // Fetch the receipt to disambiguate before bailing.
                    if update.nonce.is_some_and(|n| n >= nonce) {
                        if self.receipt_exists(tx_hash).await {
                            info!("delegation tx {tx_hash} confirmed (via receipt) for eoa {eoa}");
                            return Ok(tx_hash);
                        }
                        anyhow::bail!(
                            "signer nonce {nonce} was consumed by another transaction \
                             while awaiting delegation for eoa {eoa}"
                        );
                    }
                }

                if block_number >= until {
                    break true;
                }
            };

            if timed_out {
                warn!(
                    "delegation tx {tx_hash} not mined after {} blocks (attempt {attempt})",
                    self.settings.max_blocks_to_wait_for_mine,
                );
                // One last receipt check: the tx may have mined in the window
                // just before the timeout fired without triggering an update.
                if self.receipt_exists(tx_hash).await {
                    info!("delegation tx {tx_hash} confirmed (receipt at timeout) for eoa {eoa}");
                    return Ok(tx_hash);
                }
            }
        }

        anyhow::bail!(
            "delegation tx for eoa {eoa} not mined after {} fee bump attempts",
            self.settings.max_fee_bumps,
        )
    }

    async fn submit_tx(
        &self,
        signer: &rundler_signer::SignerLease,
        auth: &Eip7702Auth,
        nonce: u64,
        fees: GasFees,
    ) -> anyhow::Result<B256> {
        // Send to the bundler's own signer address to avoid executing any fallback
        // code the EOA may have acquired from the delegation.
        let tx = TransactionRequest::default()
            .to(signer.address())
            .nonce(nonce)
            .gas_limit(DELEGATION_GAS_LIMIT)
            .max_fee_per_gas(fees.max_fee_per_gas)
            .max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_authorization_list(vec![auth.clone().into()]);

        let raw_tx = signer
            .sign_tx_raw(tx)
            .await
            .context("failed to sign delegation transaction")?;

        self.provider
            .send_raw_transaction(raw_tx)
            .await
            .context("failed to submit delegation transaction")
    }

    /// Returns `true` if a transaction receipt exists for `tx_hash`.
    async fn receipt_exists(&self, tx_hash: B256) -> bool {
        matches!(
            self.provider.get_transaction_receipt(tx_hash).await,
            Ok(Some(_))
        )
    }
}
