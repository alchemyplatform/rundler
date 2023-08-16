use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context};
use ethers::types::{transaction::eip2718::TypedTransaction, H256, U256};
use tokio::time;
use tonic::async_trait;
use tracing::info;

use crate::{
    builder::sender::{TransactionSender, TxStatus},
    common::{
        gas::GasFees,
        types::{ExpectedStorage, ProviderLike},
    },
};

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
pub trait TransactionTracker: Send + Sync + 'static {
    fn get_nonce_and_required_fees(&self) -> anyhow::Result<(U256, Option<GasFees>)>;

    /// Sends the provided transaction and typically returns its transaction
    /// hash, but if the transaction failed to send because another transaction
    /// with the same nonce mined first, then returns information about that
    /// transaction instead.
    async fn send_transaction(
        &self,
        tx: TypedTransaction,
        expected_stroage: &ExpectedStorage,
    ) -> anyhow::Result<SendResult>;

    /// Waits until one of the following occurs:
    ///
    /// 1. One of our transactions mines (not necessarily the one just sent).
    /// 2. All our send transactions have dropped.
    /// 3. Our nonce has changed but none of our transactions mined. This means
    ///    that a transaction from our account other than one of the ones we are
    ///    tracking has mined. This should not normally happen.
    /// 4. Several new blocks have passed.
    async fn wait_for_update(&self) -> anyhow::Result<TrackerUpdate>;

    /// Like `wait_for_update`, except it returns immediately if there is no
    /// update rather than waiting for several new blocks.
    async fn check_for_update_now(&self) -> anyhow::Result<Option<TrackerUpdate>>;
}

pub enum SendResult {
    TxHash(H256),
    TrackerUpdate(TrackerUpdate),
}

#[derive(Debug)]
pub enum TrackerUpdate {
    Mined {
        tx_hash: H256,
        nonce: U256,
        gas_fees: GasFees,
        block_number: u64,
        attempt_number: u64,
    },
    StillPendingAfterWait,
    LatestTxDropped {
        nonce: U256,
    },
    NonceUsedForOtherTx {
        nonce: U256,
    },
}

#[derive(Debug)]
pub struct TransactionTrackerImpl<P, T>(tokio::sync::Mutex<TransactionTrackerImplInner<P, T>>)
where
    P: ProviderLike,
    T: TransactionSender;

#[derive(Debug)]
struct TransactionTrackerImplInner<P, T>
where
    P: ProviderLike,
    T: TransactionSender,
{
    provider: Arc<P>,
    sender: T,
    settings: Settings,
    nonce: U256,
    transactions: Vec<PendingTransaction>,
    has_dropped: bool,
    attempt_count: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub poll_interval: Duration,
    pub max_blocks_to_wait_for_mine: u64,
    pub replacement_fee_percent_increase: u64,
}

#[derive(Clone, Copy, Debug)]
struct PendingTransaction {
    tx_hash: H256,
    gas_fees: GasFees,
    attempt_number: u64,
}

#[async_trait]
impl<P, T> TransactionTracker for TransactionTrackerImpl<P, T>
where
    P: ProviderLike,
    T: TransactionSender,
{
    fn get_nonce_and_required_fees(&self) -> anyhow::Result<(U256, Option<GasFees>)> {
        Ok(self.inner()?.get_nonce_and_required_fees())
    }

    async fn send_transaction(
        &self,
        tx: TypedTransaction,
        expected_storage: &ExpectedStorage,
    ) -> anyhow::Result<SendResult> {
        self.inner()?.send_transaction(tx, expected_storage).await
    }

    async fn wait_for_update(&self) -> anyhow::Result<TrackerUpdate> {
        self.inner()?.wait_for_update().await
    }

    async fn check_for_update_now(&self) -> anyhow::Result<Option<TrackerUpdate>> {
        self.inner()?.check_for_update_now().await
    }
}

impl<P, T> TransactionTrackerImpl<P, T>
where
    P: ProviderLike,
    T: TransactionSender,
{
    pub async fn new(provider: Arc<P>, sender: T, settings: Settings) -> anyhow::Result<Self> {
        let inner = TransactionTrackerImplInner::new(provider, sender, settings).await?;
        Ok(Self(tokio::sync::Mutex::new(inner)))
    }

    fn inner(
        &self,
    ) -> anyhow::Result<tokio::sync::MutexGuard<'_, TransactionTrackerImplInner<P, T>>> {
        self.0
            .try_lock()
            .context("tracker should not be called while waiting for a transaction")
    }
}

impl<P, T> TransactionTrackerImplInner<P, T>
where
    P: ProviderLike,
    T: TransactionSender,
{
    async fn new(provider: Arc<P>, sender: T, settings: Settings) -> anyhow::Result<Self> {
        let nonce = provider
            .get_transaction_count(sender.address())
            .await
            .context("tracker should load initial nonce on construction")?;
        Ok(Self {
            provider,
            sender,
            settings,
            nonce,
            transactions: vec![],
            has_dropped: false,
            attempt_count: 0,
        })
    }

    fn get_nonce_and_required_fees(&self) -> (U256, Option<GasFees>) {
        let gas_fees = if self.has_dropped {
            None
        } else {
            self.transactions.last().map(|tx| {
                tx.gas_fees
                    .increase_by_percent(self.settings.replacement_fee_percent_increase)
            })
        };
        (self.nonce, gas_fees)
    }

    async fn send_transaction(
        &mut self,
        tx: TypedTransaction,
        expected_storage: &ExpectedStorage,
    ) -> anyhow::Result<SendResult> {
        self.validate_transaction(&tx)?;
        let gas_fees = GasFees::from(&tx);
        let send_result = self.sender.send_transaction(tx, expected_storage).await;
        let sent_tx = match send_result {
            Ok(sent_tx) => sent_tx,
            Err(error) => {
                let tracker_update = self.handle_send_error(error).await?;
                return Ok(SendResult::TrackerUpdate(tracker_update));
            }
        };
        info!("Sent transaction {:?}", sent_tx.tx_hash);
        self.transactions.push(PendingTransaction {
            tx_hash: sent_tx.tx_hash,
            gas_fees,
            attempt_number: self.attempt_count,
        });
        self.has_dropped = false;
        self.attempt_count += 1;
        Ok(SendResult::TxHash(sent_tx.tx_hash))
    }

    /// When we fail to send a transaction, it may be because another
    /// transaction has mined before it could be sent, invalidating the nonce.
    /// Thus, do one last check for an update before returning the error.
    async fn handle_send_error(&mut self, error: anyhow::Error) -> anyhow::Result<TrackerUpdate> {
        let update = self.check_for_update_now().await?;
        let Some(update) = update else {
            return Err(error);
        };
        match &update {
            TrackerUpdate::Mined { .. } | TrackerUpdate::NonceUsedForOtherTx { .. } => Ok(update),
            TrackerUpdate::StillPendingAfterWait | TrackerUpdate::LatestTxDropped { .. } => {
                Err(error)
            }
        }
    }

    async fn wait_for_update(&mut self) -> anyhow::Result<TrackerUpdate> {
        let start_block_number = self
            .provider
            .get_block_number()
            .await
            .context("tracker should get starting block when waiting for update")?;
        let end_block_number = start_block_number + self.settings.max_blocks_to_wait_for_mine;
        loop {
            let update = self.check_for_update_now().await?;
            if let Some(update) = update {
                return Ok(update);
            }
            let current_block_number = self
                .provider
                .get_block_number()
                .await
                .context("tracker should get current block when polling for updates")?;
            if end_block_number <= current_block_number {
                return Ok(TrackerUpdate::StillPendingAfterWait);
            }
            time::sleep(self.settings.poll_interval).await;
        }
    }

    async fn check_for_update_now(&mut self) -> anyhow::Result<Option<TrackerUpdate>> {
        let external_nonce = self.get_external_nonce().await?;
        if self.nonce < external_nonce {
            // The nonce has changed. Check to see which of our transactions has
            // mined, if any.
            let mut out = TrackerUpdate::NonceUsedForOtherTx { nonce: self.nonce };
            for tx in self.transactions.iter().rev() {
                let status = self
                    .sender
                    .get_transaction_status(tx.tx_hash)
                    .await
                    .context("tracker should check transaction status when the nonce changes")?;
                if let TxStatus::Mined { block_number } = status {
                    out = TrackerUpdate::Mined {
                        tx_hash: tx.tx_hash,
                        nonce: self.nonce,
                        gas_fees: tx.gas_fees,
                        block_number,
                        attempt_number: tx.attempt_number,
                    };
                    break;
                }
            }
            self.set_nonce_and_clear_state(external_nonce);
            return Ok(Some(out));
        }
        // The nonce has not changed. Check to see if the latest transaction has
        // dropped.
        if self.has_dropped {
            // has_dropped being true means that no new transactions have been
            // added since the last time we checked, hence no update.
            return Ok(None);
        }
        let Some(&last_tx) = self.transactions.last() else {
            // If there are no pending transactions, there's no update either.
            return Ok(None);
        };
        let status = self
            .sender
            .get_transaction_status(last_tx.tx_hash)
            .await
            .context("tracker should check for dropped transactions")?;
        Ok(match status {
            TxStatus::Pending => None,
            TxStatus::Mined { block_number } => {
                let nonce = self.nonce;
                self.set_nonce_and_clear_state(nonce + 1);
                Some(TrackerUpdate::Mined {
                    tx_hash: last_tx.tx_hash,
                    nonce,
                    gas_fees: last_tx.gas_fees,
                    block_number,
                    attempt_number: last_tx.attempt_number,
                })
            }
            TxStatus::Dropped => {
                self.has_dropped = true;
                Some(TrackerUpdate::LatestTxDropped { nonce: self.nonce })
            }
        })
    }

    fn set_nonce_and_clear_state(&mut self, nonce: U256) {
        self.nonce = nonce;
        self.transactions.clear();
        self.has_dropped = false;
        self.attempt_count = 0;
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
        let (required_nonce, required_gas_fees) = self.get_nonce_and_required_fees();
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
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use ethers::types::{Address, Eip1559TransactionRequest};

    use super::*;
    use crate::{
        builder::sender::{MockTransactionSender, SentTxInfo},
        common::types::MockProviderLike,
    };

    fn create_base_config() -> (MockTransactionSender, MockProviderLike, Settings) {
        let sender = MockTransactionSender::new();
        let provider = MockProviderLike::new();

        let settings = Settings {
            poll_interval: Duration::from_secs(5),
            max_blocks_to_wait_for_mine: 5,
            replacement_fee_percent_increase: 5,
        };

        (sender, provider, settings)
    }

    #[tokio::test]
    async fn test_happy_path_nonce_and_fees() {
        let (mut sender, mut provider, settings) = create_base_config();
        sender.expect_address().return_const(Address::zero());

        provider
            .expect_get_transaction_count()
            .returning(move |_a| Ok(U256::from(0)));

        let mock: TransactionTrackerImpl<MockProviderLike, MockTransactionSender> =
            TransactionTrackerImpl::new(Arc::new(provider), sender, settings)
                .await
                .unwrap();

        let nonce_and_fees = mock.get_nonce_and_required_fees().unwrap();

        assert_eq!((U256::from(0), None), nonce_and_fees);
    }

    #[tokio::test]
    async fn test_send_transaction_without_nonse() {
        let (mut sender, mut provider, settings) = create_base_config();
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

        let mock: TransactionTrackerImpl<MockProviderLike, MockTransactionSender> =
            TransactionTrackerImpl::new(Arc::new(provider), sender, settings)
                .await
                .unwrap();

        let tx = Eip1559TransactionRequest::new();
        let exp = ExpectedStorage::default();
        let sent_transaction = mock.send_transaction(tx.into(), &exp).await;
        assert_eq!(sent_transaction.is_err(), true);
    }

    #[tokio::test]
    async fn test_wait_for_update() {
        let (mut sender, mut provider, settings) = create_base_config();
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

        let mock: TransactionTrackerImpl<MockProviderLike, MockTransactionSender> =
            TransactionTrackerImpl::new(Arc::new(provider), sender, settings)
                .await
                .unwrap();

        let tx = Eip1559TransactionRequest::new();
        let exp = ExpectedStorage::default();
        let sent_transaction = mock.send_transaction(tx.into(), &exp).await;
        assert_eq!(sent_transaction.is_err(), true);
    }
}
