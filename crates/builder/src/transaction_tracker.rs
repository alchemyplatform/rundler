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

use std::sync::Arc;

use anyhow::{bail, Context};
use async_trait::async_trait;
use ethers::types::{transaction::eip2718::TypedTransaction, Address, H256, U256};
#[cfg(test)]
use mockall::automock;
use rundler_provider::Provider;
use rundler_sim::ExpectedStorage;
use rundler_types::GasFees;
use tracing::{debug, info, warn};

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
pub(crate) trait TransactionTracker: Send + Sync + 'static {
    /// Returns the current nonce and the required fees for the next transaction.
    fn get_nonce_and_required_fees(&self) -> TransactionTrackerResult<(U256, Option<GasFees>)>;

    /// Sends the provided transaction and typically returns its transaction
    /// hash, but if the transaction failed to send because another transaction
    /// with the same nonce mined first, then returns information about that
    /// transaction instead.
    async fn send_transaction(
        &mut self,
        tx: TypedTransaction,
        expected_stroage: &ExpectedStorage,
    ) -> TransactionTrackerResult<H256>;

    /// Cancel the abandoned transaction in the tracker.
    ///
    /// Returns: An option containing the hash of the transaction that was used to cancel. If the option
    /// is empty, then either no transaction was cancelled or the cancellation was a "soft-cancel."
    async fn cancel_transaction(
        &mut self,
        to: Address,
        estimated_fees: GasFees,
    ) -> TransactionTrackerResult<Option<H256>>;

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
    #[error("replacement transaction underpriced")]
    ReplacementUnderpriced,
    #[error("storage slot value condition not met")]
    ConditionNotMet,
    /// All other errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub(crate) type TransactionTrackerResult<T> = std::result::Result<T, TransactionTrackerError>;

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum TrackerUpdate {
    Mined {
        tx_hash: H256,
        nonce: U256,
        block_number: u64,
        attempt_number: u64,
        gas_limit: Option<U256>,
        gas_used: Option<U256>,
        gas_price: Option<U256>,
    },
    LatestTxDropped {
        nonce: U256,
    },
    NonceUsedForOtherTx {
        nonce: U256,
    },
}

#[derive(Debug)]
pub(crate) struct TransactionTrackerImpl<P, T>
where
    P: Provider,
    T: TransactionSender,
{
    provider: Arc<P>,
    sender: T,
    settings: Settings,
    builder_index: u64,
    nonce: U256,
    transactions: Vec<PendingTransaction>,
    has_abandoned: bool,
    attempt_count: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Settings {
    pub(crate) replacement_fee_percent_increase: u64,
}

#[derive(Clone, Copy, Debug)]
struct PendingTransaction {
    tx_hash: H256,
    gas_fees: GasFees,
    attempt_number: u64,
}

impl<P, T> TransactionTrackerImpl<P, T>
where
    P: Provider,
    T: TransactionSender,
{
    pub(crate) async fn new(
        provider: Arc<P>,
        sender: T,
        settings: Settings,
        builder_index: u64,
    ) -> anyhow::Result<Self> {
        let nonce = provider
            .get_transaction_count(sender.address())
            .await
            .unwrap_or(U256::zero());
        Ok(Self {
            provider,
            sender,
            settings,
            builder_index,
            nonce,
            transactions: vec![],
            has_abandoned: false,
            attempt_count: 0,
        })
    }

    fn set_nonce_and_clear_state(&mut self, nonce: U256) {
        self.nonce = nonce;
        self.transactions.clear();
        self.attempt_count = 0;
        self.has_abandoned = false;
        self.update_metrics();
    }

    async fn get_external_nonce(&self) -> anyhow::Result<U256> {
        self.provider
            .get_transaction_count(self.sender.address())
            .await
            .context("tracker should load current nonce from provider")
    }

    fn validate_transaction(&self, tx: &TypedTransaction) -> anyhow::Result<()> {
        let Some(&nonce) = tx.nonce() else {
            bail!("transaction given to tracker should have nonce set");
        };
        let gas_fees = GasFees::from(tx);
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
        TransactionTrackerMetrics::set_num_pending_transactions(
            self.builder_index,
            self.transactions.len(),
        );
        TransactionTrackerMetrics::set_nonce(self.builder_index, self.nonce);
        TransactionTrackerMetrics::set_attempt_count(self.builder_index, self.attempt_count);
        if let Some(tx) = self.transactions.last() {
            TransactionTrackerMetrics::set_current_fees(self.builder_index, Some(tx.gas_fees));
        } else {
            TransactionTrackerMetrics::set_current_fees(self.builder_index, None);
        }
    }

    async fn get_mined_tx_gas_info(
        &self,
        tx_hash: H256,
    ) -> anyhow::Result<(Option<U256>, Option<U256>, Option<U256>)> {
        let (tx, tx_receipt) = tokio::try_join!(
            self.provider.get_transaction(tx_hash),
            self.provider.get_transaction_receipt(tx_hash),
        )?;
        let gas_limit = tx.map(|t| t.gas).or_else(|| {
            warn!("failed to fetch transaction data for tx: {}", tx_hash);
            None
        });
        let (gas_used, gas_price) = match tx_receipt {
            Some(r) => (r.gas_used, r.effective_gas_price),
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
    P: Provider,
    T: TransactionSender,
{
    fn get_nonce_and_required_fees(&self) -> TransactionTrackerResult<(U256, Option<GasFees>)> {
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
        tx: TypedTransaction,
        expected_storage: &ExpectedStorage,
    ) -> TransactionTrackerResult<H256> {
        self.validate_transaction(&tx)?;
        let gas_fees = GasFees::from(&tx);
        info!(
            "Sending transaction with nonce: {:?} gas fees: {:?} gas limit: {:?}",
            self.nonce,
            gas_fees,
            tx.gas()
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
                info!("Replacement underpriced: nonce: {:?}", self.nonce);

                // Store this transaction as pending if last is empty or if it has higher gas fees than last
                // so that we can continue to increase fees.
                if self.transactions.last().map_or(true, |t| {
                    gas_fees.max_fee_per_gas > t.gas_fees.max_fee_per_gas
                        && gas_fees.max_priority_fee_per_gas > t.gas_fees.max_priority_fee_per_gas
                }) {
                    self.transactions.push(PendingTransaction {
                        tx_hash: H256::zero(),
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
    ) -> TransactionTrackerResult<Option<H256>> {
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
            None => (H256::zero(), estimated_fees),
        };

        let cancel_info = self
            .sender
            .cancel_transaction(tx_hash, self.nonce, to, gas_fees)
            .await?;

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

    async fn check_for_update(&mut self) -> TransactionTrackerResult<Option<TrackerUpdate>> {
        let external_nonce = self.get_external_nonce().await?;
        if self.nonce < external_nonce {
            // The nonce has changed. Check to see which of our transactions has
            // mined, if any.
            debug!(
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

        if last_tx.tx_hash == H256::zero() {
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
            TxSenderError::ReplacementUnderpriced => {
                TransactionTrackerError::ReplacementUnderpriced
            }
            TxSenderError::ConditionNotMet => TransactionTrackerError::ConditionNotMet,
            TxSenderError::SoftCancelFailed => {
                TransactionTrackerError::Other(anyhow::anyhow!("soft cancel failed"))
            }
            TxSenderError::Other(e) => TransactionTrackerError::Other(e),
        }
    }
}

struct TransactionTrackerMetrics {}

impl TransactionTrackerMetrics {
    fn set_num_pending_transactions(builder_index: u64, num_pending_transactions: usize) {
        metrics::gauge!("builder_tracker_num_pending_transactions", "builder_index" => builder_index.to_string())
            .set(num_pending_transactions as f64);
    }

    fn set_nonce(builder_index: u64, nonce: U256) {
        metrics::gauge!("builder_tracker_nonce", "builder_index" => builder_index.to_string())
            .set(nonce.as_u64() as f64);
    }

    fn set_attempt_count(builder_index: u64, attempt_count: u64) {
        metrics::gauge!("builder_tracker_attempt_count", "builder_index" => builder_index.to_string()).set(attempt_count as f64);
    }

    fn set_current_fees(builder_index: u64, current_fees: Option<GasFees>) {
        let fees = current_fees.unwrap_or_default();

        metrics::gauge!("builder_tracker_current_max_fee_per_gas", "builder_index" => builder_index.to_string())
            .set(fees.max_fee_per_gas.as_u64() as f64);
        metrics::gauge!("builder_tracker_current_max_priority_fee_per_gas", "builder_index" => builder_index.to_string())
            .set(fees.max_priority_fee_per_gas.as_u64() as f64);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethers::types::{Address, Eip1559TransactionRequest, Transaction, TransactionReceipt};
    use mockall::Sequence;
    use rundler_provider::MockProvider;

    use super::*;
    use crate::sender::{MockTransactionSender, SentTxInfo};

    fn create_base_config() -> (MockTransactionSender, MockProvider) {
        let sender = MockTransactionSender::new();
        let provider = MockProvider::new();

        (sender, provider)
    }

    async fn create_tracker(
        sender: MockTransactionSender,
        provider: MockProvider,
    ) -> TransactionTrackerImpl<MockProvider, MockTransactionSender> {
        let settings = Settings {
            replacement_fee_percent_increase: 5,
        };

        let tracker: TransactionTrackerImpl<MockProvider, MockTransactionSender> =
            TransactionTrackerImpl::new(Arc::new(provider), sender, settings, 0)
                .await
                .unwrap();

        tracker
    }

    #[tokio::test]
    async fn test_nonce_and_fees() {
        let (mut sender, mut provider) = create_base_config();
        sender.expect_address().return_const(Address::zero());
        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: U256::from(0),
                    tx_hash: H256::zero(),
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(U256::from(0)));

        let mut tracker = create_tracker(sender, provider).await;

        let tx = Eip1559TransactionRequest::new()
            .nonce(0)
            .gas(10000)
            .max_fee_per_gas(10000);
        let exp = ExpectedStorage::default();

        // send dummy transaction
        let _sent = tracker.send_transaction(tx.into(), &exp).await;
        let nonce_and_fees = tracker.get_nonce_and_required_fees().unwrap();

        assert_eq!(
            (
                U256::from(0),
                Some(GasFees {
                    max_fee_per_gas: U256::from(10500),
                    max_priority_fee_per_gas: U256::zero(),
                })
            ),
            nonce_and_fees
        );
    }

    #[tokio::test]
    async fn test_nonce_and_fees_abandoned() {
        let (mut sender, mut provider) = create_base_config();
        sender.expect_address().return_const(Address::zero());

        sender
            .expect_get_transaction_status()
            .returning(move |_a| Box::pin(async { Ok(TxStatus::Pending) }));

        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: U256::from(0),
                    tx_hash: H256::zero(),
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(U256::from(0)));

        let mut tracker = create_tracker(sender, provider).await;

        let tx = Eip1559TransactionRequest::new()
            .nonce(0)
            .gas(10000)
            .max_fee_per_gas(10000);
        let exp = ExpectedStorage::default();

        // send dummy transaction
        let _sent = tracker.send_transaction(tx.into(), &exp).await;
        let _tracker_update = tracker.check_for_update().await.unwrap();

        tracker.abandon();

        let nonce_and_fees = tracker.get_nonce_and_required_fees().unwrap();

        assert_eq!((U256::from(0), None), nonce_and_fees);
    }

    #[tokio::test]
    async fn test_send_transaction_without_nonce() {
        let (mut sender, mut provider) = create_base_config();
        sender.expect_address().return_const(Address::zero());
        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: U256::from(0),
                    tx_hash: H256::zero(),
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(U256::from(2)));

        let mut tracker = create_tracker(sender, provider).await;

        let tx = Eip1559TransactionRequest::new();
        let exp = ExpectedStorage::default();
        let sent_transaction = tracker.send_transaction(tx.into(), &exp).await;

        assert!(sent_transaction.is_err());
    }

    #[tokio::test]
    async fn test_send_transaction_with_invalid_nonce() {
        let (mut sender, mut provider) = create_base_config();

        sender.expect_address().return_const(Address::zero());
        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: U256::from(0),
                    tx_hash: H256::zero(),
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(U256::from(2)));

        let mut tracker = create_tracker(sender, provider).await;

        let tx = Eip1559TransactionRequest::new().nonce(0);
        let exp = ExpectedStorage::default();
        let sent_transaction = tracker.send_transaction(tx.into(), &exp).await;

        assert!(sent_transaction.is_err());
    }

    #[tokio::test]
    async fn test_send_transaction() {
        let (mut sender, mut provider) = create_base_config();
        sender.expect_address().return_const(Address::zero());
        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: U256::from(0),
                    tx_hash: H256::zero(),
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(U256::from(0)));

        let mut tracker = create_tracker(sender, provider).await;

        let tx = Eip1559TransactionRequest::new().nonce(0);
        let exp = ExpectedStorage::default();
        tracker.send_transaction(tx.into(), &exp).await.unwrap();
    }

    // TODO(#295): fix dropped status
    // #[tokio::test]
    // async fn test_wait_for_update_dropped() {
    //     let (mut sender, mut provider) = create_base_config();
    //     sender.expect_address().return_const(Address::zero());

    //     sender
    //         .expect_get_transaction_status()
    //         .returning(move |_a| Box::pin(async { Ok(TxStatus::Dropped) }));

    //     sender.expect_send_transaction().returning(move |_a, _b| {
    //         Box::pin(async {
    //             Ok(SentTxInfo {
    //                 nonce: U256::from(0),
    //                 tx_hash: H256::zero(),
    //             })
    //         })
    //     });

    //     provider
    //         .expect_get_transaction_count()
    //         .returning(move |_a| Ok(U256::from(0)));

    //     provider.expect_get_block_number().returning(move || Ok(1));

    //     let tracker = create_tracker(sender, provider).await;

    //     let tx = Eip1559TransactionRequest::new().nonce(0);
    //     let exp = ExpectedStorage::default();
    //     let _sent_transaction = tracker.send_transaction(tx.into(), &exp).await.unwrap();
    //     let tracker_update = tracker.wait_for_update().await.unwrap();

    //     assert!(matches!(
    //         tracker_update,
    //         TrackerUpdate::LatestTxDropped { .. }
    //     ));
    // }

    #[tokio::test]
    async fn test_check_for_update_nonce_used() {
        let (mut sender, mut provider) = create_base_config();
        sender.expect_address().return_const(Address::zero());

        let mut provider_seq = Sequence::new();
        for transaction_count in 0..=1 {
            provider
                .expect_get_transaction_count()
                .returning(move |_a| Ok(U256::from(transaction_count)))
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
        sender.expect_address().return_const(Address::zero());
        sender
            .expect_get_transaction_status()
            .returning(move |_a| Box::pin(async { Ok(TxStatus::Mined { block_number: 1 }) }));

        sender.expect_send_transaction().returning(move |_a, _b| {
            Box::pin(async {
                Ok(SentTxInfo {
                    nonce: U256::from(0),
                    tx_hash: H256::random(),
                })
            })
        });

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(U256::from(0)));

        provider.expect_get_transaction().returning(|_: H256| {
            Ok(Some(Transaction {
                gas: U256::from(0),
                ..Default::default()
            }))
        });

        provider
            .expect_get_transaction_receipt()
            .returning(|_: H256| {
                Ok(Some(TransactionReceipt {
                    gas_used: Some(U256::from(0)),
                    ..Default::default()
                }))
            });

        let mut tracker = create_tracker(sender, provider).await;

        let tx = Eip1559TransactionRequest::new().nonce(0);
        let exp = ExpectedStorage::default();

        // send dummy transaction
        let _sent = tracker.send_transaction(tx.into(), &exp).await;
        let tracker_update = tracker.check_for_update().await.unwrap().unwrap();

        assert!(matches!(tracker_update, TrackerUpdate::Mined { .. }));
    }
}
