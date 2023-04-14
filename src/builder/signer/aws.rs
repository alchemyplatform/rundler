use std::time::Duration;

use anyhow::Context;
use ethers::{
    abi::Address,
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712},
        Signature,
    },
};
use ethers_signers::{AwsSigner, AwsSignerError, Signer};
use rslock::{LockGuard, LockManager};
use rusoto_core::Region;
use rusoto_kms::KmsClient;
use tokio::{sync::oneshot, time::sleep};
use tonic::async_trait;

use crate::common::handle::SpawnGuard;

/// A KMS signer handle that will release the key_id when dropped.
#[derive(Debug)]
pub struct KmsSigner {
    signer: AwsSigner,
    _kms_guard: SpawnGuard,
}

impl KmsSigner {
    pub async fn connect(
        chain_id: u64,
        region: Region,
        key_ids: Vec<String>,
        redis_uri: String,
        ttl_millis: u64,
    ) -> anyhow::Result<Self> {
        let (tx, rx) = oneshot::channel::<String>();
        let kms_guard = SpawnGuard::spawn_with_guard(Self::lock_manager_loop(
            redis_uri, key_ids, ttl_millis, tx,
        ));
        let key_id = rx.await.context("should lock key_id")?;
        let client = KmsClient::new(region);
        let signer = AwsSigner::new(client, key_id, chain_id)
            .await
            .context("should create signer")?;

        Ok(Self {
            signer,
            _kms_guard: kms_guard,
        })
    }

    async fn lock_manager_loop(
        redis_url: String,
        key_ids: Vec<String>,
        ttl_millis: u64,
        locked_tx: oneshot::Sender<String>,
    ) {
        let lm = LockManager::new(vec![redis_url]);

        let mut lock = None;
        let mut kid = None;
        for key_id in key_ids.iter() {
            match lm.lock(key_id.as_bytes(), ttl_millis as usize).await {
                Ok(l) => {
                    lock = Some(l);
                    kid = Some(key_id.clone());
                    tracing::info!("locked key_id {key_id}");
                    break;
                }
                Err(e) => {
                    tracing::warn!("could not lock key_id {key_id}: {e:?}");
                    continue;
                }
            }
        }
        if lock.is_none() {
            return;
        }
        let _ = locked_tx.send(kid.unwrap());

        let lg = LockGuard {
            lock: lock.unwrap(),
        };
        loop {
            sleep(Duration::from_millis(ttl_millis / 10)).await;
            match lm.extend(&lg.lock, ttl_millis as usize).await {
                Ok(_) => {
                    tracing::debug!("extended lock");
                }
                Err(e) => {
                    tracing::error!("could not extend lock: {e:?}");
                }
            }
        }
    }
}

#[async_trait]
impl Signer for KmsSigner {
    type Error = AwsSignerError;

    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error> {
        self.signer.sign_message(message).await
    }

    async fn sign_transaction(&self, tx: &TypedTransaction) -> Result<Signature, Self::Error> {
        self.signer.sign_transaction(tx).await
    }

    async fn sign_typed_data<T: Eip712 + Send + Sync>(
        &self,
        payload: &T,
    ) -> Result<Signature, Self::Error> {
        self.signer.sign_typed_data(payload).await
    }

    fn address(&self) -> Address {
        self.signer.address()
    }

    /// Gets the wallet's chain id
    fn chain_id(&self) -> u64 {
        self.signer.chain_id()
    }

    /// Sets the wallet's chain_id, used in conjunction with EIP-155 signing
    fn with_chain_id<T: Into<u64>>(self, chain_id: T) -> Self {
        Self {
            signer: self.signer.with_chain_id(chain_id),
            _kms_guard: self._kms_guard,
        }
    }
}
