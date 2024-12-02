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

use alloy_primitives::{Address, B256};
use anyhow::{bail, Context};
use async_trait::async_trait;
use metrics::Gauge;
use metrics_derive::Metrics;
#[cfg(test)]
use mockall::automock;
use rundler_provider::{EvmProvider, TransactionRequest};
use rundler_sim::ExpectedStorage;
use rundler_types::GasFees;
use tracing::{info, warn};

use crate::sender::{TransactionSender, TxSenderError, TxStatus};

/// Keeps track of pending transactions in order to suggest nonces and
/// replacement fees and ensure that transactions do not get stalled. All sent
/// transactions should flow through here.
///
/// `check_for_update_now` and `send_transaction_and_wait` are intended to be
/// called by a single caller at a time, with no new transactions attempted
/// until it returns a `TrackerUpdate` to indicate whether a transaction has
/// succeeded (potentially not the most recent one) or whether circumstances
/// have changed so that it is worth making another attempt.
#[async_trait]
#[cfg_attr(test, automock)]
pub(crate) trait TransactionTracker: Send + Sync {
    /// Returns the current nonce and the required fees for the next transaction.
    fn get_nonce_and_required_fees(&self) -> TransactionTrackerResult<(u64, Option<GasFees>)>;

    /// Sends the provided transaction and typically returns its transaction
    /// hash, but if the transaction failed to send because another transaction
    /// with the same nonce mined first, then returns information about that
    /// transaction instead.
    async fn send_transaction(
        &mut self,
        tx: TransactionRequest,
        expected_stroage: &ExpectedStorage,
    ) -> TransactionTrackerResult<B256>;

    /// Cancel the abandoned transaction in the tracker.
    ///
    /// Returns: An option containing the hash of the transaction that was used to cancel. If the option
    /// is empty, then either no transaction was cancelled or the cancellation was a "soft-cancel."
    async fn cancel_transaction(
        &mut self,
        to: Address,
        estimated_fees: GasFees,
    ) -> TransactionTrackerResult<Option<B256>>;

    /// Checks:
    /// 1. One of our transactions mines (not necessarily the one just sent).
    /// 2. All our send transactions have dropped.
    /// 3. Our nonce has changed but none of our transactions mined. This means
    ///    that a transaction from our account other than one of the ones we are
    ///    tracking has mined. This should not normally happen.
    /// 4. Several new blocks have passed.
    async fn check_for_update(&mut self) -> TransactionTrackerResult<Option<TrackerUpdate>>;

    /// Resets the tracker to its initial state
    async fn reset(&mut self);

    /// Abandons the current transaction.
    /// The current transaction will still be tracked, but will no longer be considered during fee estimation
    fn abandon(&mut self);

    /// Un-abandons the current transaction
    fn unabandon(&mut self);
}

/// Errors that can occur while using a `TransactionTracker`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TransactionTrackerError {
    #[error("nonce too low")]
    NonceTooLow,
    #[error("transaction underpriced")]
    Underpriced,
    #[error("replacement transaction underpriced")]
    ReplacementUnderpriced,
    #[error("storage slot value condition not met")]
    ConditionNotMet,
    #[error("rejected")]
    Rejected,
    /// All other errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub(crate) type TransactionTrackerResult<T> = std::result::Result<T, TransactionTrackerError>;

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum TrackerUpdate {
    Mined {
        tx_hash: B256,
        nonce: u64,
        block_number: u64,
        attempt_number: u64,
        gas_limit: Option<u64>,
        gas_used: Option<u128>,
        gas_price: Option<u128>,
    },
    LatestTxDropped {
        nonce: u64,
    },
    NonceUsedForOtherTx {
        nonce: u64,
    },
}

#[derive(Debug)]
pub(crate) struct TransactionTrackerImpl<P, T> {
    provider: P,
    sender: T,
    settings: Settings,
    nonce: u64,
    transactions: Vec<PendingTransaction>,
    has_abandoned: bool,
    attempt_count: u64,
    metrics: TransactionTrackerMetrics,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Settings {
    pub(crate) replacement_fee_percent_increase: u32,
}

#[derive(Clone, Copy, Debug)]
struct PendingTransaction {
    tx_hash: B256,
    gas_fees: GasFees,
    attempt_number: u64,
}

impl<P, T> TransactionTrackerImpl<P, T>
where
    P: EvmProvider,
    T: TransactionSender,
{
    pub(crate) async fn new(
        provider: P,
        sender: T,
        settings: Settings,
        builder_index: u64,
    ) -> anyhow::Result<Self> {
        let nonce = provider
            .get_transaction_count(sender.address())
            .await
            .unwrap_or(0);
        Ok(Self {
            provider,
            sender,
            settings,
            nonce,
            transactions: vec![],
            has_abandoned: false,
            attempt_count: 0,
            metrics: TransactionTrackerMetrics::new_with_labels(&[(
                "builder_index",
                builder_index.to_string(),
            )]),
        })
    }

    fn set_nonce_and_clear_state(&mut self, nonce: u64) {
        self.nonce = nonce;
        self.transactions.clear();
        self.attempt_count = 0;
        self.has_abandoned = false;
        self.update_metrics();
    }

    async fn get_external_nonce(&self) -> anyhow::Result<u64> {
        self.provider
            .get_transaction_count(self.sender.address())
            .await
            .context("tracker should load current nonce from provider")
    }

    fn validate_transaction(&self, tx: &TransactionRequest) -> anyhow::Result<()> {
        let Some(nonce) = tx.nonce else {
            bail!("transaction given to tracker should have nonce set");
        };
        let gas_fees = GasFees {
            max_fee_per_gas: tx.max_fee_per_gas.unwrap_or(0),
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas.unwrap_or(0),
        };
        let (required_nonce, required_gas_fees) = self.get_nonce_and_required_fees()?;
        if nonce != required_nonce {
            bail!("tried to send transaction with nonce {nonce}, but should match tracker's nonce of {required_nonce}");
        }
        if let Some(required_gas_fees) = required_gas_fees {
            if gas_fees.max_fee_per_gas < required_gas_fees.max_fee_per_gas
                || gas_fees.max_priority_fee_per_gas < required_gas_fees.max_priority_fee_per_gas
            {
                bail!("new transaction's gas fees should be at least the required fees")
            }
        }
        Ok(())
    }

    fn update_metrics(&self) {
        self.metrics
            .num_pending_transactions
            .set(self.transactions.len() as f64);
        self.metrics.nonce.set(self.nonce as f64);
        self.metrics.attempt_count.set(self.attempt_count as f64);

        if let Some(tx) = self.transactions.last() {
            self.metrics
                .current_max_fee_per_gas
                .set(tx.gas_fees.max_fee_per_gas as f64);
            self.metrics
                .max_priority_fee_per_gas
                .set(tx.gas_fees.max_priority_fee_per_gas as f64);
        } else {
            let fee = GasFees::default();
            self.metrics
                .current_max_fee_per_gas
                .set(fee.max_fee_per_gas as f64);
            self.metrics
                .max_priority_fee_per_gas
                .set(fee.max_priority_fee_per_gas as f64);
        }
    }

    async fn get_mined_tx_gas_info(
        &self,
        tx_hash: B256,
    ) -> anyhow::Result<(Option<u64>, Option<u128>, Option<u128>)> {
        let (tx, tx_receipt) = tokio::try_join!(
            self.provider.get_transaction_by_hash(tx_hash),
            self.provider.get_transaction_receipt(tx_hash),
        )?;
        let gas_limit = tx.map(|t| t.gas).or_else(|| {
            warn!("failed to fetch transaction data for tx: {}", tx_hash);
            None
        });
        let (gas_used, gas_price) = match tx_receipt {
            Some(r) => (Some(r.gas_used), Some(r.effective_gas_price)),
            None => {
                warn!("failed to fetch transaction receipt for tx: {}", tx_hash);
                (None, None)
            }
        };
        Ok((gas_limit, gas_used, gas_price))
    }
}

#[async_trait]
impl<P, T> TransactionTracker for TransactionTrackerImpl<P, T>
where
    P: EvmProvider,
    T: TransactionSender,
{
    fn get_nonce_and_required_fees(&self) -> TransactionTrackerResult<(u64, Option<GasFees>)> {
        let gas_fees = if self.has_abandoned {
            None
        } else {
            self.transactions.last().map(|tx| {
                tx.gas_fees
                    .increase_by_percent(self.settings.replacement_fee_percent_increase)
            })
        };
        Ok((self.nonce, gas_fees))
    }

    async fn send_transaction(
        &mut self,
        tx: TransactionRequest,
        expected_storage: &ExpectedStorage,
    ) -> TransactionTrackerResult<B256> {
        self.validate_transaction(&tx)?;
        let gas_fees = GasFees {
            max_fee_per_gas: tx.max_fee_per_gas.unwrap_or(0),
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas.unwrap_or(0),
        };
        info!(
            "Sending transaction with nonce: {:?} gas fees: {:?} gas limit: {:?}",
            self.nonce,
            gas_fees,
            tx.gas.unwrap_or(0),
        );
        let sent_tx = self.sender.send_transaction(tx, expected_storage).await;

        match sent_tx {
            Ok(sent_tx) => {
                info!(
                    "Sent transaction {:?} nonce: {:?}",
                    sent_tx.tx_hash, sent_tx.nonce
                );
                self.transactions.push(PendingTransaction {
                    tx_hash: sent_tx.tx_hash,
                    gas_fees,
                    attempt_number: self.attempt_count,
                });
                self.has_abandoned = false;
                self.attempt_count += 1;
                self.update_metrics();
                Ok(sent_tx.tx_hash)
            }
            Err(e) if matches!(e, TxSenderError::ReplacementUnderpriced) => {
                // Only can get into this state if there is an unknown pending transaction causing replacement
                // underpriced errors, or if the last transaction was abandoned.
                warn!(
                    "Replacement underpriced: nonce: {:?}, fees: {:?}",
                    self.nonce, gas_fees
                );

                // Store this transaction as pending if last is empty or if it has higher gas fees than last
                // so that we can continue to increase fees.
                if self.transactions.last().map_or(true, |t| {
                    gas_fees.max_fee_per_gas > t.gas_fees.max_fee_per_gas
                        && gas_fees.max_priority_fee_per_gas > t.gas_fees.max_priority_fee_per_gas
                }) {
                    self.transactions.push(PendingTransaction {
                        tx_hash: B256::ZERO,
                        gas_fees,
                        attempt_number: self.attempt_count,
                    });
                };

                self.has_abandoned = false;
                self.attempt_count += 1;
                self.update_metrics();
                Err(e.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn cancel_transaction(
        &mut self,
        to: Address,
        estimated_fees: GasFees,
    ) -> TransactionTrackerResult<Option<B256>> {
        let (tx_hash, gas_fees) = match self.transactions.last() {
            Some(tx) => {
                let increased_fees = tx
                    .gas_fees
                    .increase_by_percent(self.settings.replacement_fee_percent_increase);
                let gas_fees = GasFees {
                    max_fee_per_gas: increased_fees
                        .max_fee_per_gas
                        .max(estimated_fees.max_fee_per_gas),
                    max_priority_fee_per_gas: increased_fees
                        .max_priority_fee_per_gas
                        .max(estimated_fees.max_priority_fee_per_gas),
                };
                (tx.tx_hash, gas_fees)
            }
            None => (B256::ZERO, estimated_fees),
        };

        let cancel_res = self
            .sender
            .cancel_transaction(tx_hash, self.nonce, to, gas_fees)
            .await;

        match cancel_res {
            Ok(cancel_info) => {
                if cancel_info.soft_cancelled {
                    // If the transaction was soft-cancelled. Reset internal state.
                    self.reset().await;
                    return Ok(None);
                }

                info!(
                    "Sent cancellation tx {:?} fees: {:?}",
                    cancel_info.tx_hash, gas_fees
                );

                self.transactions.push(PendingTransaction {
                    tx_hash: cancel_info.tx_hash,
                    gas_fees,
                    attempt_number: self.attempt_count,
                });

                self.attempt_count += 1;
                self.update_metrics();
                Ok(Some(cancel_info.tx_hash))
            }
            Err(TxSenderError::ReplacementUnderpriced) => {
                warn!(
                    "Cancellation tx replacement underpriced: nonce: {:?} fees: {:?}",
                    self.nonce, gas_fees
                );

                // Store this transaction as pending if last is empty or if it has higher gas fees than last
                // so that we can continue to increase fees.
                if self.transactions.last().map_or(true, |t| {
                    gas_fees.max_fee_per_gas > t.gas_fees.max_fee_per_gas
                        && gas_fees.max_priority_fee_per_gas > t.gas_fees.max_priority_fee_per_gas
                }) {
                    self.transactions.push(PendingTransaction {
                        tx_hash: B256::ZERO,
                        gas_fees,
                        attempt_number: self.attempt_count,
                    });
                };

                Err(TransactionTrackerError::ReplacementUnderpriced)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn check_for_update(&mut self) -> TransactionTrackerResult<Option<TrackerUpdate>> {
        let external_nonce = self.get_external_nonce().await?;
        if self.nonce < external_nonce {
            // The nonce has changed. Check to see which of our transactions has
            // mined, if any.
            info!(
                "Nonce has changed from {:?} to {:?}",
                self.nonce, external_nonce
            );

            let mut out = TrackerUpdate::NonceUsedForOtherTx { nonce: self.nonce };
            for tx in self.transactions.iter().rev() {
                let status = self
                    .sender
                    .get_transaction_status(tx.tx_hash)
                    .await
                    .context("tracker should check transaction status when the nonce changes")?;
                info!("Status of tx {:?}: {:?}", tx.tx_hash, status);
                if let TxStatus::Mined { block_number } = status {
                    let (gas_limit, gas_used, gas_price) =
                        self.get_mined_tx_gas_info(tx.tx_hash).await?;
                    out = TrackerUpdate::Mined {
                        tx_hash: tx.tx_hash,
                        nonce: self.nonce,
                        block_number,
                        attempt_number: tx.attempt_number,
                        gas_limit,
                        gas_used,
                        gas_price,
                    };
                    break;
                }
            }
            self.set_nonce_and_clear_state(external_nonce);
            return Ok(Some(out));
        }

        let Some(&last_tx) = self.transactions.last() else {
            // If there are no pending transactions, there's no update either.
            return Ok(None);
        };

        if last_tx.tx_hash == B256::ZERO {
            // If the last transaction was a replacement that failed to send, we
            // don't need to check for updates.
            return Ok(None);
        }

        let status = self
            .sender
            .get_transaction_status(last_tx.tx_hash)
            .await
            .context("tracker should check for transaction status")?;
        Ok(match status {
            TxStatus::Pending => None,
            TxStatus::Mined { block_number } => {
                let nonce = self.nonce;
                self.set_nonce_and_clear_state(nonce + 1);
                let (gas_limit, gas_used, gas_price) =
                    self.get_mined_tx_gas_info(last_tx.tx_hash).await?;
                Some(TrackerUpdate::Mined {
                    tx_hash: last_tx.tx_hash,
                    nonce,
                    block_number,
                    attempt_number: last_tx.attempt_number,
                    gas_limit,
                    gas_used,
                    gas_price,
                })
            }
            TxStatus::Dropped => Some(TrackerUpdate::LatestTxDropped { nonce: self.nonce }),
        })
    }

    async fn reset(&mut self) {
        let nonce = self.get_external_nonce().await.unwrap_or(self.nonce);
        self.set_nonce_and_clear_state(nonce);
    }

    fn abandon(&mut self) {
        self.has_abandoned = true;
        self.attempt_count = 0;
        // remember the transaction in case we need to cancel it
    }

    fn unabandon(&mut self) {
        self.has_abandoned = false;
    }
}

impl From<TxSenderError> for TransactionTrackerError {
    fn from(value: TxSenderError) -> Self {
        match value {
            TxSenderError::NonceTooLow => TransactionTrackerError::NonceTooLow,
            TxSenderError::Underpriced => TransactionTrackerError::Underpriced,
            TxSenderError::ReplacementUnderpriced => {
                TransactionTrackerError::ReplacementUnderpriced
            }
            TxSenderError::ConditionNotMet => TransactionTrackerError::ConditionNotMet,
            TxSenderError::Rejected => TransactionTrackerError::Rejected,
            TxSenderError::SoftCancelFailed => {
                TransactionTrackerError::Other(anyhow::anyhow!("soft cancel failed"))
            }
            TxSenderError::Other(e) => TransactionTrackerError::Other(e),
        }
    }
}

#[derive(Metrics)]
#[metrics(scope = "builder_tracker_")]
struct TransactionTrackerMetrics {
    #[metric(describe = "the number of pending transactions.")]
    num_pending_transactions: Gauge,
    #[metric(describe = "the current account‘s nonce.")]
    nonce: Gauge,
    #[metric(describe = "the number of pending transactions.")]
    attempt_count: Gauge,
    #[metric(describe = "the maximum fee per gas of current transaction.")]
    current_max_fee_per_gas: Gauge,
    #[metric(describe = "the maximum priority fee per gas of current transaction.")]
    max_priority_fee_per_gas: Gauge,
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use mockall::Sequence;
    use rundler_provider::{
        MockEvmProvider, Transaction, TransactionReceipt, TransactionReceiptEnvelope,
        TransactionReceiptWithBloom,
    };

    use super::*;
    use crate::sender::{MockTransactionSender, SentTxInfo};

    fn create_base_config() -> (MockTransactionSender, MockEvmProvider) {
        let sender = MockTransactionSender::new();
        let provider = MockEvmProvider::new();

        (sender, provider)
    }

    async fn create_tracker(
        sender: MockTransactionSender,
        provider: MockEvmProvider,
    ) -> TransactionTrackerImpl<MockEvmProvider, MockTransactionSender> {
        let settings = Settings {
            replacement_fee_percent_increase: 5,
        };

        let tracker: TransactionTrackerImpl<MockEvmProvider, MockTransactionSender> =
            TransactionTrackerImpl::new(provider, sender, settings, 0)
                .await
                .unwrap();

        tracker
    }

    #[tokio::test]
    async fn test_nonce_and_fees() {
        let (mut sender, mut provider) = create_base_config();
        sender.expect_address().return_const(Address::ZERO);
        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: 0,
                    tx_hash: B256::ZERO,
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(0));

        let mut tracker = create_tracker(sender, provider).await;

        let tx = TransactionRequest::default()
            .nonce(0)
            .gas_limit(10000)
            .max_fee_per_gas(10000);
        let exp = ExpectedStorage::default();

        // send dummy transaction
        let _sent = tracker.send_transaction(tx, &exp).await;
        let nonce_and_fees = tracker.get_nonce_and_required_fees().unwrap();

        assert_eq!(
            (
                0,
                Some(GasFees {
                    max_fee_per_gas: 10500,
                    max_priority_fee_per_gas: 0,
                })
            ),
            nonce_and_fees
        );
    }

    #[tokio::test]
    async fn test_nonce_and_fees_abandoned() {
        let (mut sender, mut provider) = create_base_config();
        sender.expect_address().return_const(Address::ZERO);

        sender
            .expect_get_transaction_status()
            .returning(move |_a| Box::pin(async { Ok(TxStatus::Pending) }));

        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: 0,
                    tx_hash: B256::ZERO,
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(0));

        let mut tracker = create_tracker(sender, provider).await;

        let tx = TransactionRequest::default()
            .nonce(0)
            .gas_limit(10000)
            .max_fee_per_gas(10000);
        let exp = ExpectedStorage::default();

        // send dummy transaction
        let _sent = tracker.send_transaction(tx, &exp).await;
        let _tracker_update = tracker.check_for_update().await.unwrap();

        tracker.abandon();

        let nonce_and_fees = tracker.get_nonce_and_required_fees().unwrap();

        assert_eq!((0, None), nonce_and_fees);
    }

    #[tokio::test]
    async fn test_send_transaction_without_nonce() {
        let (mut sender, mut provider) = create_base_config();
        sender.expect_address().return_const(Address::ZERO);
        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: 0,
                    tx_hash: B256::ZERO,
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(2));

        let mut tracker = create_tracker(sender, provider).await;

        let tx = TransactionRequest::default();
        let exp = ExpectedStorage::default();
        let sent_transaction = tracker.send_transaction(tx, &exp).await;

        assert!(sent_transaction.is_err());
    }

    #[tokio::test]
    async fn test_send_transaction_with_invalid_nonce() {
        let (mut sender, mut provider) = create_base_config();

        sender.expect_address().return_const(Address::ZERO);
        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: 0,
                    tx_hash: B256::ZERO,
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(2));

        let mut tracker = create_tracker(sender, provider).await;

        let tx = TransactionRequest::default().nonce(0);
        let exp = ExpectedStorage::default();
        let sent_transaction = tracker.send_transaction(tx, &exp).await;

        assert!(sent_transaction.is_err());
    }

    #[tokio::test]
    async fn test_send_transaction() {
        let (mut sender, mut provider) = create_base_config();
        sender.expect_address().return_const(Address::ZERO);
        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: 0,
                    tx_hash: B256::ZERO,
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(0));

        let mut tracker = create_tracker(sender, provider).await;

        let tx = TransactionRequest::default().nonce(0);
        let exp = ExpectedStorage::default();
        tracker.send_transaction(tx, &exp).await.unwrap();
    }

    #[tokio::test]
    async fn test_check_for_update_nonce_used() {
        let (mut sender, mut provider) = create_base_config();
        sender.expect_address().return_const(Address::ZERO);

        let mut provider_seq = Sequence::new();
        for transaction_count in 0..=1 {
            provider
                .expect_get_transaction_count()
                .returning(move |_a| Ok(transaction_count))
                .times(1)
                .in_sequence(&mut provider_seq);
        }

        let mut tracker = create_tracker(sender, provider).await;

        let tracker_update = tracker.check_for_update().await.unwrap().unwrap();

        assert!(matches!(
            tracker_update,
            TrackerUpdate::NonceUsedForOtherTx { .. }
        ));
    }

    #[tokio::test]
    async fn test_check_for_update_mined() {
        let (mut sender, mut provider) = create_base_config();
        sender.expect_address().return_const(Address::ZERO);
        sender
            .expect_get_transaction_status()
            .returning(move |_a| Box::pin(async { Ok(TxStatus::Mined { block_number: 1 }) }));

        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: 0,
                    tx_hash: B256::random(),
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(0));

        provider
            .expect_get_transaction_by_hash()
            .returning(|_: B256| {
                Ok(Some(Transaction {
                    gas: 0,
                    ..Default::default()
                }))
            });

        provider
            .expect_get_transaction_receipt()
            .returning(|_: B256| {
                Ok(Some(TransactionReceipt {
                    inner: TransactionReceiptEnvelope::Legacy(
                        TransactionReceiptWithBloom::default(),
                    ),
                    transaction_hash: B256::ZERO,
                    transaction_index: None,
                    block_hash: None,
                    block_number: None,
                    gas_used: 0,
                    effective_gas_price: 0,
                    blob_gas_used: None,
                    blob_gas_price: None,
                    from: Address::ZERO,
                    to: None,
                    contract_address: None,
                    authorization_list: None,
                }))
            });

        let mut tracker = create_tracker(sender, provider).await;

        let tx = TransactionRequest::default().nonce(0);
        let exp = ExpectedStorage::default();

        // send dummy transaction
        let _sent = tracker.send_transaction(tx, &exp).await;
        let tracker_update = tracker.check_for_update().await.unwrap().unwrap();

        assert!(matches!(tracker_update, TrackerUpdate::Mined { .. }));
    }
}
