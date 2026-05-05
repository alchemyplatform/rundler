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

use std::{
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    time::Duration,
};

use alloy_primitives::B256;
use rundler_provider::TransactionRequest;
use rundler_signer::SignerLease;
use rundler_types::{ExpectedStorage, GasFees, Timestamp};

use super::{CancelTxInfo, Result, TransactionSender, TxSenderError};

#[derive(Debug, PartialEq, Eq)]
enum ActiveSender {
    Primary,
    Fallback,
}

/// A transaction sender that transparently fails over to a fallback sender when
/// the primary returns [`TxSenderError::SenderUnavailable`].
///
/// Recovery is passive: after `recovery_interval` has elapsed the next send
/// attempt re-tries the primary. On success the primary is reinstated; on
/// another `SenderUnavailable` the timer resets.
///
/// Cancellations are always routed to whichever sender originally submitted
/// the transaction (tracked by tx hash). If the primary is down at cancel time
/// the cancel attempt may itself fail, but the bundle sender will handle that
/// and re-submit via the fallback on the next cycle.
pub(crate) struct FallbackTransactionSender {
    primary: Box<dyn TransactionSender>,
    fallback: Box<dyn TransactionSender>,
    /// True when the fallback sender is active.
    using_fallback: AtomicBool,
    /// Unix epoch seconds when the primary was first detected as unavailable.
    /// Zero means the primary is currently healthy.
    degraded_since_secs: AtomicU64,
    recovery_interval: Duration,
    /// Tracks whether the most recent transaction was submitted via the fallback,
    /// so cancellations can be routed to the correct sender.
    last_tx_used_fallback: AtomicBool,
    /// Consecutive SenderUnavailable responses from the primary before we commit to failover.
    consecutive_failures: AtomicU32,
    /// How many consecutive failures are required before activating the fallback.
    failure_threshold: u32,
}

impl FallbackTransactionSender {
    pub(crate) fn new(
        primary: Box<dyn TransactionSender>,
        fallback: Box<dyn TransactionSender>,
        recovery_interval: Duration,
        failure_threshold: u32,
    ) -> Self {
        Self {
            primary,
            fallback,
            using_fallback: AtomicBool::new(false),
            degraded_since_secs: AtomicU64::new(0),
            recovery_interval,
            last_tx_used_fallback: AtomicBool::new(false),
            consecutive_failures: AtomicU32::new(0),
            failure_threshold,
        }
    }

    fn current_sender(&self) -> ActiveSender {
        if !self.using_fallback.load(Ordering::Acquire) {
            return ActiveSender::Primary;
        }
        let degraded_since_secs = self.degraded_since_secs.load(Ordering::Acquire);
        let elapsed_secs = Timestamp::now()
            .seconds_since_epoch()
            .saturating_sub(degraded_since_secs);
        if degraded_since_secs != 0 && elapsed_secs >= self.recovery_interval.as_secs() {
            tracing::info!(
                recovery_interval_secs = self.recovery_interval.as_secs(),
                "Recovery interval elapsed, attempting to restore primary sender"
            );
            self.using_fallback.store(false, Ordering::Release);
            self.degraded_since_secs.store(0, Ordering::Release);
            return ActiveSender::Primary;
        }
        ActiveSender::Fallback
    }

    fn activate_fallback(&self) {
        if self
            .using_fallback
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.degraded_since_secs
                .store(Timestamp::now().seconds_since_epoch(), Ordering::Release);
            tracing::warn!("Primary sender unavailable, activating fallback sender");
        }
    }
}

#[async_trait::async_trait]
impl TransactionSender for FallbackTransactionSender {
    async fn send_transaction(
        &self,
        tx: TransactionRequest,
        expected_storage: &ExpectedStorage,
        signer: &SignerLease,
    ) -> Result<B256> {
        if matches!(self.current_sender(), ActiveSender::Fallback) {
            let hash = self
                .fallback
                .send_transaction(tx, expected_storage, signer)
                .await?;
            self.last_tx_used_fallback.store(true, Ordering::Release);
            return Ok(hash);
        }

        match self
            .primary
            .send_transaction(tx.clone(), expected_storage, signer)
            .await
        {
            Ok(hash) => {
                self.consecutive_failures.store(0, Ordering::Release);
                self.last_tx_used_fallback.store(false, Ordering::Release);
                Ok(hash)
            }
            Err(TxSenderError::SenderUnavailable(e)) => {
                let failures = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
                if failures >= self.failure_threshold {
                    self.activate_fallback();
                    self.consecutive_failures.store(0, Ordering::Release);
                    let hash = self
                        .fallback
                        .send_transaction(tx, expected_storage, signer)
                        .await?;
                    self.last_tx_used_fallback.store(true, Ordering::Release);
                    Ok(hash)
                } else {
                    tracing::warn!(
                        failures,
                        threshold = self.failure_threshold,
                        error = %e,
                        "Primary sender unavailable, will activate fallback after threshold"
                    );
                    Err(TxSenderError::SenderUnavailable(e))
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn cancel_transaction(
        &self,
        tx_hash: B256,
        nonce: u64,
        gas_fees: GasFees,
        signer: &SignerLease,
    ) -> Result<CancelTxInfo> {
        if self.last_tx_used_fallback.load(Ordering::Acquire) {
            self.fallback
                .cancel_transaction(tx_hash, nonce, gas_fees, signer)
                .await
        } else {
            self.primary
                .cancel_transaction(tx_hash, nonce, gas_fees, signer)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use alloy_network::TxSigner;
    use alloy_primitives::{Address, B256};
    use alloy_signer::Signature;
    use rundler_provider::TransactionRequest;
    use rundler_signer::SignerLease;
    use rundler_types::{ExpectedStorage, GasFees};

    use super::*;
    use crate::sender::{CancelTxInfo, TransactionSender, TxSenderError};

    struct NoopSigner;

    #[async_trait::async_trait]
    impl TxSigner<Signature> for NoopSigner {
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

    fn test_signer() -> SignerLease {
        SignerLease::new(Arc::new(NoopSigner), 1)
    }

    struct AlwaysOkSender {
        hash: B256,
    }

    #[async_trait::async_trait]
    impl TransactionSender for AlwaysOkSender {
        async fn send_transaction(
            &self,
            _tx: TransactionRequest,
            _expected_storage: &ExpectedStorage,
            _signer: &SignerLease,
        ) -> super::Result<B256> {
            Ok(self.hash)
        }

        async fn cancel_transaction(
            &self,
            _tx_hash: B256,
            _nonce: u64,
            _gas_fees: GasFees,
            _signer: &SignerLease,
        ) -> super::Result<CancelTxInfo> {
            Ok(CancelTxInfo {
                tx_hash: B256::ZERO,
                soft_cancelled: false,
            })
        }
    }

    struct FailNTimesSender {
        fails_remaining: AtomicUsize,
        hash: B256,
    }

    #[async_trait::async_trait]
    impl TransactionSender for FailNTimesSender {
        async fn send_transaction(
            &self,
            _tx: TransactionRequest,
            _expected_storage: &ExpectedStorage,
            _signer: &SignerLease,
        ) -> super::Result<B256> {
            if self.fails_remaining.load(Ordering::SeqCst) > 0 {
                self.fails_remaining.fetch_sub(1, Ordering::SeqCst);
                Err(TxSenderError::SenderUnavailable(anyhow::anyhow!(
                    "mock failure"
                )))
            } else {
                Ok(self.hash)
            }
        }

        async fn cancel_transaction(
            &self,
            _tx_hash: B256,
            _nonce: u64,
            _gas_fees: GasFees,
            _signer: &SignerLease,
        ) -> super::Result<CancelTxInfo> {
            Ok(CancelTxInfo {
                tx_hash: B256::ZERO,
                soft_cancelled: false,
            })
        }
    }

    fn make_sender(
        primary: impl TransactionSender + 'static,
        fallback: impl TransactionSender + 'static,
        recovery_secs: u64,
        failure_threshold: u32,
    ) -> FallbackTransactionSender {
        FallbackTransactionSender::new(
            Box::new(primary),
            Box::new(fallback),
            Duration::from_secs(recovery_secs),
            failure_threshold,
        )
    }

    #[tokio::test]
    async fn uses_primary_when_available() {
        let sender = make_sender(
            AlwaysOkSender {
                hash: B256::repeat_byte(0x01),
            },
            AlwaysOkSender {
                hash: B256::repeat_byte(0x02),
            },
            60,
            3,
        );
        assert!(matches!(sender.current_sender(), ActiveSender::Primary));
    }

    #[tokio::test]
    async fn switches_to_fallback_on_unavailable() {
        let sender = make_sender(
            FailNTimesSender {
                fails_remaining: AtomicUsize::new(1),
                hash: B256::repeat_byte(0x01),
            },
            AlwaysOkSender {
                hash: B256::repeat_byte(0x02),
            },
            60,
            3,
        );
        sender.activate_fallback();
        assert!(matches!(sender.current_sender(), ActiveSender::Fallback));
    }

    #[tokio::test]
    async fn recovery_after_interval() {
        let sender = make_sender(
            AlwaysOkSender {
                hash: B256::repeat_byte(0x01),
            },
            AlwaysOkSender {
                hash: B256::repeat_byte(0x02),
            },
            1,
            3,
        );
        sender.activate_fallback();
        assert!(matches!(sender.current_sender(), ActiveSender::Fallback));
        std::thread::sleep(Duration::from_secs(2));
        assert!(matches!(sender.current_sender(), ActiveSender::Primary));
    }

    #[tokio::test]
    async fn activates_fallback_after_threshold() {
        let primary_hash = B256::repeat_byte(0x01);
        let fallback_hash = B256::repeat_byte(0x02);
        let signer = test_signer();

        // threshold=2: first failure returns error, second triggers failover
        let sender = make_sender(
            FailNTimesSender {
                fails_remaining: AtomicUsize::new(2),
                hash: primary_hash,
            },
            AlwaysOkSender {
                hash: fallback_hash,
            },
            60,
            2,
        );

        // First failure — below threshold, error propagated.
        assert!(
            sender
                .send_transaction(
                    TransactionRequest::default(),
                    &ExpectedStorage::default(),
                    &signer
                )
                .await
                .is_err()
        );
        assert!(!sender.last_tx_used_fallback.load(Ordering::Acquire));

        // Second failure — threshold reached, falls over and returns fallback hash.
        let hash = sender
            .send_transaction(
                TransactionRequest::default(),
                &ExpectedStorage::default(),
                &signer,
            )
            .await
            .unwrap();
        assert_eq!(hash, fallback_hash);
        assert!(sender.last_tx_used_fallback.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn cancel_routes_to_primary_when_healthy() {
        let primary_hash = B256::repeat_byte(0x01);
        let fallback_hash = B256::repeat_byte(0x02);
        let signer = test_signer();

        let sender = make_sender(
            AlwaysOkSender { hash: primary_hash },
            AlwaysOkSender {
                hash: fallback_hash,
            },
            60,
            3,
        );

        let hash = sender
            .send_transaction(
                TransactionRequest::default(),
                &ExpectedStorage::default(),
                &signer,
            )
            .await
            .unwrap();
        assert_eq!(hash, primary_hash);
        assert!(!sender.last_tx_used_fallback.load(Ordering::Acquire));
    }
}
