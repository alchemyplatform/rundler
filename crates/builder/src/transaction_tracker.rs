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

use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256, I256, U256};
use anyhow::bail;
use async_trait::async_trait;
use metrics::{Gauge, Histogram};
use metrics_derive::Metrics;
#[cfg(test)]
use mockall::automock;
use rundler_provider::{EvmProvider, ReceiptResponse, TransactionRequest};
use rundler_signer::SignerLease;
use rundler_types::{pool::AddressUpdate, ExpectedStorage, GasFees};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::sender::{TransactionSender, TxSenderError};

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
    /// Returns the current nonce, balance, and the required fees for the next transaction.
    fn get_state(&self) -> TransactionTrackerResult<TrackerState>;

    /// Returns the number of pending transactions.
    fn num_pending_transactions(&self) -> usize;

    /// Sends the provided transaction and typically returns its transaction
    /// hash, but if the transaction failed to send because another transaction
    /// with the same nonce mined first, then returns information about that
    /// transaction instead.
    async fn send_transaction(
        &mut self,
        tx: TransactionRequest,
        expected_storage: &ExpectedStorage,
        block_number: u64,
    ) -> TransactionTrackerResult<B256>;

    /// Cancel the abandoned transaction in the tracker.
    ///
    /// Returns: An option containing the hash of the transaction that was used to cancel. If the option
    /// is empty, then either no transaction was cancelled or the cancellation was a "soft-cancel."
    async fn cancel_transaction(
        &mut self,
        estimated_fees: GasFees,
    ) -> TransactionTrackerResult<Option<B256>>;

    /// Checks:
    /// 1. One of our transactions mines (not necessarily the one just sent).
    /// 2. All our send transactions have dropped.
    /// 3. Our nonce has changed but none of our transactions mined. This means
    ///    that a transaction from our account other than one of the ones we are
    ///    tracking has mined. This should not normally happen.
    /// 4. Several new blocks have passed.
    async fn process_update(
        &mut self,
        update: &AddressUpdate,
    ) -> TransactionTrackerResult<Option<TrackerUpdate>>;

    /// Resets the tracker to its initial state
    async fn reset(&mut self);

    /// Abandons the current transaction.
    /// The current transaction will still be tracked, but will no longer be considered during fee estimation
    fn abandon(&mut self);

    /// Un-abandons the current transaction
    fn unabandon(&mut self);

    /// Returns the address of the account being tracked
    fn address(&self) -> Address;
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
    #[error("insufficient funds")]
    InsufficientFunds,
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
        gas_used: Option<u64>,
        gas_price: Option<u128>,
        is_success: bool,
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
    signer: SignerLease,
    settings: Settings,
    nonce: u64,
    balance: U256,
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
    // If none, this indicates that the transaction was not successfully sent
    // We still track these to ensure that we handle fee increases correctly
    tx_hash: Option<B256>,
    gas_fees: GasFees,
    attempt_number: u64,
    sent_at_block: Option<u64>,
    sent_at_time: Option<Instant>,
}

impl<P, T> TransactionTrackerImpl<P, T>
where
    P: EvmProvider,
    T: TransactionSender,
{
    pub(crate) async fn new(
        provider: P,
        sender: T,
        signer: SignerLease,
        settings: Settings,
        builder_tag: String,
    ) -> anyhow::Result<Self> {
        let mut this = Self {
            provider,
            sender,
            signer,
            settings,
            nonce: 0,
            balance: U256::ZERO,
            transactions: vec![],
            has_abandoned: false,
            attempt_count: 0,
            metrics: TransactionTrackerMetrics::new_with_labels(&[("builder_tag", builder_tag)]),
        };

        this.reset().await;

        Ok(this)
    }

    fn set_nonce_and_clear_state(&mut self, nonce: u64) {
        self.nonce = nonce;
        self.transactions.clear();
        self.attempt_count = 0;
        self.has_abandoned = false;
        self.update_metrics();
    }

    fn validate_transaction(&self, tx: &TransactionRequest) -> anyhow::Result<()> {
        let Some(nonce) = tx.nonce else {
            bail!("transaction given to tracker should have nonce set");
        };
        let gas_fees = GasFees {
            max_fee_per_gas: tx.max_fee_per_gas.unwrap_or(0),
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas.unwrap_or(0),
        };
        let TrackerState {
            nonce: required_nonce,
            required_fees,
            ..
        } = self.get_state()?;
        if nonce != required_nonce {
            bail!("tried to send transaction with nonce {nonce}, but should match tracker's nonce of {required_nonce}");
        }
        if let Some(required_fees) = required_fees {
            if gas_fees.max_fee_per_gas < required_fees.max_fee_per_gas
                || gas_fees.max_priority_fee_per_gas < required_fees.max_priority_fee_per_gas
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

    async fn get_mined_tx_info(&self, tx_hash: B256) -> anyhow::Result<Option<MinedTxInfo>> {
        let (tx, tx_receipt) = tokio::try_join!(
            self.provider.get_transaction_by_hash(tx_hash),
            self.provider.get_transaction_receipt(tx_hash),
        )?;
        let gas_limit = tx.map(|t| t.inner.gas_limit()).or_else(|| {
            warn!("failed to find transaction data for tx: {}", tx_hash);
            None
        });
        match tx_receipt {
            Some(r) => Ok(Some(MinedTxInfo {
                block_number: r.block_number.unwrap_or(0),
                gas_limit,
                gas_used: Some(r.inner.gas_used()),
                gas_price: Some(r.effective_gas_price),
                is_success: r.inner.status(),
            })),
            None => {
                warn!("failed to find transaction receipt for tx: {}", tx_hash);
                Ok(None)
            }
        }
    }
}

#[derive(Debug, Default)]
struct MinedTxInfo {
    block_number: u64,
    gas_limit: Option<u64>,
    gas_used: Option<u64>,
    gas_price: Option<u128>,
    is_success: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrackerState {
    pub(crate) nonce: u64,
    pub(crate) balance: U256,
    pub(crate) required_fees: Option<GasFees>,
}

#[async_trait]
impl<P, T> TransactionTracker for TransactionTrackerImpl<P, T>
where
    P: EvmProvider,
    T: TransactionSender,
{
    fn address(&self) -> Address {
        self.signer.address()
    }

    fn get_state(&self) -> TransactionTrackerResult<TrackerState> {
        let gas_fees = if self.has_abandoned {
            None
        } else {
            self.transactions.last().map(|tx| {
                tx.gas_fees
                    .increase_by_percent(self.settings.replacement_fee_percent_increase)
            })
        };
        Ok(TrackerState {
            nonce: self.nonce,
            balance: self.balance,
            required_fees: gas_fees,
        })
    }

    fn num_pending_transactions(&self) -> usize {
        self.transactions
            .iter()
            .filter(|t| t.tx_hash.is_some())
            .count()
    }

    async fn send_transaction(
        &mut self,
        tx: TransactionRequest,
        expected_storage: &ExpectedStorage,
        block_number: u64,
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

        let Some(tx_nonce) = tx.nonce else {
            return Err(TransactionTrackerError::Other(anyhow::anyhow!(
                "transaction given to tracker should have nonce set"
            )));
        };

        let sent_at_time = Instant::now();
        let tx_hash = self
            .sender
            .send_transaction(tx, expected_storage, &self.signer)
            .await;

        self.update_metrics();

        match tx_hash {
            Ok(tx_hash) => {
                info!("Sent transaction {:?} nonce: {:?}", tx_hash, tx_nonce);
                self.transactions.push(PendingTransaction {
                    tx_hash: Some(tx_hash),
                    gas_fees,
                    attempt_number: self.attempt_count,
                    sent_at_block: Some(block_number),
                    sent_at_time: Some(sent_at_time),
                });
                self.has_abandoned = false;
                self.attempt_count += 1;
                self.update_metrics();
                Ok(tx_hash)
            }
            Err(e)
                if matches!(
                    e,
                    TxSenderError::ReplacementUnderpriced | TxSenderError::Underpriced
                ) =>
            {
                warn!(
                    "Underpriced: nonce: {:?}, fees: {:?}, error: {:?}",
                    self.nonce, gas_fees, e
                );

                // Store this transaction as pending if last is empty or if it has higher gas fees than last
                // so that we can continue to increase fees.
                if self.transactions.last().map_or(true, |t| {
                    gas_fees.max_fee_per_gas > t.gas_fees.max_fee_per_gas
                        && gas_fees.max_priority_fee_per_gas > t.gas_fees.max_priority_fee_per_gas
                }) {
                    self.transactions.push(PendingTransaction {
                        tx_hash: None,
                        gas_fees,
                        attempt_number: self.attempt_count,
                        sent_at_block: None,
                        sent_at_time: None,
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
        estimated_fees: GasFees,
    ) -> TransactionTrackerResult<Option<B256>> {
        // find the last pending txn with a tx_hash
        let pending_tx = self.transactions.iter().rev().find(|t| t.tx_hash.is_some());
        let (tx_hash, gas_fees) = match pending_tx {
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
                (tx.tx_hash.unwrap(), gas_fees)
            }
            None => (B256::ZERO, estimated_fees),
        };

        let cancel_res = self
            .sender
            .cancel_transaction(tx_hash, self.nonce, gas_fees, &self.signer)
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
                    tx_hash: Some(cancel_info.tx_hash),
                    gas_fees,
                    attempt_number: self.attempt_count,
                    sent_at_block: None,
                    sent_at_time: None,
                });

                self.attempt_count += 1;
                self.update_metrics();
                Ok(Some(cancel_info.tx_hash))
            }
            Err(TxSenderError::ReplacementUnderpriced | TxSenderError::Underpriced) => {
                warn!(
                    "Cancellation tx underpriced: nonce: {:?} fees: {:?} error: {:?}",
                    self.nonce, gas_fees, cancel_res
                );

                // Store this transaction as pending if last is empty or if it has higher gas fees than last
                // so that we can continue to increase fees.
                if self.transactions.last().map_or(true, |t| {
                    gas_fees.max_fee_per_gas > t.gas_fees.max_fee_per_gas
                        && gas_fees.max_priority_fee_per_gas > t.gas_fees.max_priority_fee_per_gas
                }) {
                    self.transactions.push(PendingTransaction {
                        tx_hash: None,
                        gas_fees,
                        attempt_number: self.attempt_count,
                        sent_at_block: None,
                        sent_at_time: None,
                    });
                };

                Err(TransactionTrackerError::ReplacementUnderpriced)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn process_update(
        &mut self,
        update: &AddressUpdate,
    ) -> TransactionTrackerResult<Option<TrackerUpdate>> {
        // unlikely that the balance will fail to convert to I256, so just don't crash if it does
        // this is only used for logging
        let balance_change = I256::try_from(update.balance).unwrap_or(I256::ZERO)
            - I256::try_from(self.balance).unwrap_or(I256::ZERO);

        self.balance = update.balance;

        let Some(update_nonce) = update.nonce else {
            return Ok(None);
        };
        if self.nonce > update_nonce {
            return Ok(None);
        }
        let new_nonce = update_nonce + 1;

        // The nonce has changed. Check to see which of our transactions has
        // mined, if any.
        info!(
            "Tracker update: nonce has changed from {:?} to {:?}, balance change: {:?}gwei, transactions mined: {:?}",
            self.nonce,
            new_nonce,
            alloy_primitives::utils::format_units(balance_change, "gwei").unwrap_or("0".to_string()),
            update.mined_tx_hashes
        );

        let mut out = TrackerUpdate::NonceUsedForOtherTx { nonce: self.nonce };
        for tx in self.transactions.iter().rev() {
            let Some(pending_tx_hash) = tx.tx_hash else {
                continue;
            };

            if update.mined_tx_hashes.contains(&pending_tx_hash) {
                let Some(mined_tx_info) = self.get_mined_tx_info(pending_tx_hash).await? else {
                    continue;
                };
                out = TrackerUpdate::Mined {
                    tx_hash: pending_tx_hash,
                    nonce: self.nonce,
                    block_number: mined_tx_info.block_number,
                    attempt_number: tx.attempt_number,
                    gas_limit: mined_tx_info.gas_limit,
                    gas_used: mined_tx_info.gas_used,
                    gas_price: mined_tx_info.gas_price,
                    is_success: mined_tx_info.is_success,
                };

                if let Some(sent_at_time) = tx.sent_at_time {
                    let elapsed = Instant::now().duration_since(sent_at_time);
                    self.metrics
                        .txn_time_to_mine_ms
                        .record(elapsed.as_millis() as f64);
                }
                if let Some(sent_at_block) = tx.sent_at_block {
                    self.metrics
                        .txn_blocks_to_mine
                        .record((mined_tx_info.block_number.saturating_sub(sent_at_block)) as f64);
                }
            }
        }
        self.set_nonce_and_clear_state(new_nonce);
        return Ok(Some(out));
    }

    async fn reset(&mut self) {
        let nonce_fut = self.provider.get_transaction_count(self.signer.address());
        let balance_fut = self.provider.get_balance(self.signer.address(), None);
        let (nonce, balance) =
            tokio::try_join!(nonce_fut, balance_fut).unwrap_or((self.nonce, self.balance));

        self.set_nonce_and_clear_state(nonce);
        self.balance = balance;

        // reset metrics when tracker reset.
        self.metrics.num_pending_transactions.set(0);
        self.metrics.current_max_fee_per_gas.set(0);
        self.metrics.max_priority_fee_per_gas.set(0);
    }

    fn abandon(&mut self) {
        self.has_abandoned = true;
        self.attempt_count = 0;
        // set fees to 0 when abandoning
        self.metrics.current_max_fee_per_gas.set(0);
        self.metrics.max_priority_fee_per_gas.set(0);
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
            TxSenderError::InsufficientFunds => TransactionTrackerError::InsufficientFunds,
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
    #[metric(describe = "the blocks it takes for a transaction to mine.")]
    txn_blocks_to_mine: Histogram,
    #[metric(describe = "the time it takes for a transaction to mine in ms.")]
    txn_time_to_mine_ms: Histogram,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_consensus::{transaction::Recovered, Signed, TxEip1559};
    use alloy_network::TxSigner;
    use alloy_primitives::{Address, Signature, U256};
    use alloy_rpc_types_eth::{
        Transaction as AlloyTransaction, TransactionReceipt as AlloyTransactionReceipt,
    };
    use rundler_provider::{
        AnyReceiptEnvelope, AnyTxEnvelope, MockEvmProvider, ReceiptWithBloom, Transaction,
        WithOtherFields,
    };

    use super::*;
    use crate::sender::MockTransactionSender;

    struct MockTxSigner {}

    #[async_trait::async_trait]
    impl TxSigner<Signature> for MockTxSigner {
        fn address(&self) -> Address {
            Address::ZERO
        }
        async fn sign_transaction(
            &self,
            _tx: &mut dyn alloy_consensus::SignableTransaction<Signature>,
        ) -> alloy_signer::Result<Signature> {
            Ok(Signature::test_signature())
        }
    }

    fn create_base_config(
        initial_nonce: u64,
    ) -> (MockTransactionSender, MockEvmProvider, MockTxSigner) {
        let sender = MockTransactionSender::new();

        let mut provider = MockEvmProvider::new();
        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(initial_nonce));
        provider
            .expect_get_balance()
            .returning(move |_a, _b| Ok(U256::ZERO));

        let signer = MockTxSigner {};

        (sender, provider, signer)
    }

    async fn create_tracker(
        sender: MockTransactionSender,
        provider: MockEvmProvider,
        signer: MockTxSigner,
    ) -> TransactionTrackerImpl<MockEvmProvider, MockTransactionSender> {
        let settings = Settings {
            replacement_fee_percent_increase: 5,
        };

        let lease = SignerLease::new(Arc::new(signer), 1);

        let tracker: TransactionTrackerImpl<MockEvmProvider, MockTransactionSender> =
            TransactionTrackerImpl::new(provider, sender, lease, settings, "test".to_string())
                .await
                .unwrap();

        tracker
    }

    #[tokio::test]
    async fn test_nonce_and_fees() {
        let (mut sender, provider, signer) = create_base_config(0);
        sender
            .expect_send_transaction()
            .returning(move |_a, _b, _c| Box::pin(async { Ok(B256::ZERO) }));

        let mut tracker = create_tracker(sender, provider, signer).await;

        let tx = TransactionRequest::default()
            .nonce(0)
            .gas_limit(10000)
            .max_fee_per_gas(10000);
        let exp = ExpectedStorage::default();

        // send dummy transaction
        let _sent = tracker.send_transaction(tx, &exp, 0).await;
        let state = tracker.get_state().unwrap();

        assert_eq!(
            TrackerState {
                nonce: 0,
                balance: U256::ZERO,
                required_fees: Some(GasFees {
                    max_fee_per_gas: 10500,
                    max_priority_fee_per_gas: 0,
                }),
            },
            state
        );
    }

    #[tokio::test]
    async fn test_nonce_and_fees_abandoned() {
        let (mut sender, provider, signer) = create_base_config(0);
        sender
            .expect_send_transaction()
            .returning(move |_a, _b, _c| Box::pin(async { Ok(B256::ZERO) }));

        let mut tracker = create_tracker(sender, provider, signer).await;

        let tx = TransactionRequest::default()
            .nonce(0)
            .gas_limit(10000)
            .max_fee_per_gas(10000);
        let exp = ExpectedStorage::default();

        // send dummy transaction
        let _sent = tracker.send_transaction(tx, &exp, 0).await;

        tracker.abandon();

        let state = tracker.get_state().unwrap();

        assert_eq!(
            TrackerState {
                nonce: 0,
                balance: U256::ZERO,
                required_fees: None,
            },
            state
        );
    }

    #[tokio::test]
    async fn test_send_transaction_without_nonce() {
        let (mut sender, provider, signer) = create_base_config(2);
        sender
            .expect_send_transaction()
            .returning(move |_a, _b, _c| Box::pin(async { Ok(B256::ZERO) }));

        let mut tracker = create_tracker(sender, provider, signer).await;

        let tx = TransactionRequest::default();
        let exp = ExpectedStorage::default();
        let sent_transaction = tracker.send_transaction(tx, &exp, 0).await;

        assert!(sent_transaction.is_err());
    }

    #[tokio::test]
    async fn test_send_transaction_with_invalid_nonce() {
        let (mut sender, provider, signer) = create_base_config(2);

        sender
            .expect_send_transaction()
            .returning(move |_a, _b, _c| Box::pin(async { Ok(B256::ZERO) }));

        let mut tracker = create_tracker(sender, provider, signer).await;

        let tx = TransactionRequest::default().nonce(0);
        let exp = ExpectedStorage::default();
        let sent_transaction = tracker.send_transaction(tx, &exp, 0).await;

        assert!(sent_transaction.is_err());
    }

    #[tokio::test]
    async fn test_send_transaction() {
        let (mut sender, provider, signer) = create_base_config(0);
        sender
            .expect_send_transaction()
            .returning(move |_a, _b, _c| Box::pin(async { Ok(B256::ZERO) }));

        let mut tracker = create_tracker(sender, provider, signer).await;

        let tx = TransactionRequest::default().nonce(0);
        let exp = ExpectedStorage::default();
        tracker.send_transaction(tx, &exp, 0).await.unwrap();
    }

    #[tokio::test]
    async fn test_check_for_update_nonce_used() {
        let (sender, provider, signer) = create_base_config(0);

        let mut tracker = create_tracker(sender, provider, signer).await;
        let update = AddressUpdate {
            address: Address::ZERO,
            nonce: Some(1),
            mined_tx_hashes: vec![],
            balance: U256::ZERO,
        };

        let tracker_update = tracker.process_update(&update).await.unwrap().unwrap();

        assert!(matches!(
            tracker_update,
            TrackerUpdate::NonceUsedForOtherTx { .. }
        ));
    }

    #[tokio::test]
    async fn test_underpriced_txn() {
        let (mut sender, provider, signer) = create_base_config(0);
        sender
            .expect_send_transaction()
            .returning(move |_a, _b, _c| Box::pin(async { Err(TxSenderError::Underpriced) }));

        let mut tracker = create_tracker(sender, provider, signer).await;

        let tx = TransactionRequest::default()
            .nonce(0)
            .max_fee_per_gas(10000);
        let exp = ExpectedStorage::default();
        let sent_transaction = tracker.send_transaction(tx, &exp, 0).await;

        assert!(matches!(
            sent_transaction,
            Err(TransactionTrackerError::Underpriced)
        ));
        assert_eq!(tracker.num_pending_transactions(), 0);
        assert_eq!(
            tracker.get_state().unwrap().required_fees,
            Some(GasFees {
                max_fee_per_gas: 10500,
                max_priority_fee_per_gas: 0,
            })
        );
    }

    #[tokio::test]
    async fn test_replacement_underpriced_txn() {
        let (mut sender, provider, signer) = create_base_config(0);
        sender
            .expect_send_transaction()
            .returning(move |_a, _b, _c| {
                Box::pin(async { Err(TxSenderError::ReplacementUnderpriced) })
            });

        let mut tracker = create_tracker(sender, provider, signer).await;

        let tx = TransactionRequest::default()
            .nonce(0)
            .max_fee_per_gas(10000);
        let exp = ExpectedStorage::default();
        let sent_transaction = tracker.send_transaction(tx, &exp, 0).await;

        assert!(matches!(
            sent_transaction,
            Err(TransactionTrackerError::ReplacementUnderpriced)
        ));
        assert_eq!(tracker.num_pending_transactions(), 0);
        assert_eq!(
            tracker.get_state().unwrap().required_fees,
            Some(GasFees {
                max_fee_per_gas: 10500,
                max_priority_fee_per_gas: 0,
            })
        );
    }

    fn sign_transaction(hash: B256) -> Transaction {
        let txn = TxEip1559 {
            gas_limit: 0,
            ..Default::default()
        };
        let inner = Signed::new_unchecked(txn, Signature::test_signature(), hash).into();
        let inner = AnyTxEnvelope::Ethereum(inner);

        WithOtherFields::new(AlloyTransaction {
            inner: Recovered::new_unchecked(inner, Address::ZERO),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            effective_gas_price: None,
        })
        .into()
    }
    #[tokio::test]
    async fn test_process_update_mined() {
        let (mut sender, mut provider, signer) = create_base_config(0);

        let tx_hash = B256::random();

        sender
            .expect_send_transaction()
            .returning(move |_a, _b, _c| Box::pin(async move { Ok(tx_hash) }));

        provider
            .expect_get_transaction_by_hash()
            .returning(|hash: B256| Ok(Some(sign_transaction(hash))));

        provider
            .expect_get_transaction_receipt()
            .returning(|_: B256| {
                Ok(Some(WithOtherFields::new(AlloyTransactionReceipt {
                    inner: AnyReceiptEnvelope {
                        inner: ReceiptWithBloom::default(),
                        r#type: 0,
                    },
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
                })))
            });

        let mut tracker = create_tracker(sender, provider, signer).await;

        let tx = TransactionRequest::default().nonce(0);
        let exp = ExpectedStorage::default();

        // send dummy transaction
        let _sent = tracker.send_transaction(tx, &exp, 0).await;
        let update = AddressUpdate {
            address: Address::ZERO,
            nonce: Some(1),
            mined_tx_hashes: vec![tx_hash],
            balance: U256::from(1000),
        };

        let tracker_update = tracker.process_update(&update).await.unwrap().unwrap();

        assert!(matches!(tracker_update, TrackerUpdate::Mined { .. }));

        let state = tracker.get_state().unwrap();
        assert_eq!(
            state,
            TrackerState {
                nonce: 2,
                balance: U256::from(1000),
                required_fees: None,
            }
        );
    }
}
