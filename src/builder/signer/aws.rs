use std::{sync::Arc, time::Duration};

use anyhow::Context;
use ethers::{
    prelude::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, Provider},
    types::{Eip1559TransactionRequest, TransactionReceipt},
};
use ethers_signers::{AwsSigner, Signer};
use rslock::{LockGuard, LockManager};
use rusoto_core::Region;
use rusoto_kms::KmsClient;
use tokio::{sync::oneshot, time::sleep};
use tonic::async_trait;

use super::{monitor_account_balance, SignerLike};
use crate::common::handle::SpawnGuard;

/// A KMS signer handle that will release the key_id when dropped.
#[derive(Debug)]
pub struct KmsSigner<C: JsonRpcClient> {
    signer: SignerMiddleware<Arc<Provider<C>>, AwsSigner>,
    _kms_guard: SpawnGuard,
    _monitor_guard: SpawnGuard,
}

#[async_trait]
impl<C: JsonRpcClient + 'static> SignerLike for KmsSigner<C> {
    async fn send_transaction(
        &self,
        tx: Eip1559TransactionRequest,
    ) -> anyhow::Result<TransactionReceipt> {
        Middleware::send_transaction(&self.signer, tx, None)
            .await
            .context("should send tx")?
            .await
            .context("should get receipt")?
            .context("receipt should be some")
    }
}

impl<C: JsonRpcClient + 'static> KmsSigner<C> {
    pub async fn connect(
        provider: Arc<Provider<C>>,
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
        let monitor_guard = SpawnGuard::spawn_with_guard(monitor_account_balance(
            signer.address(),
            provider.clone(),
        ));

        Ok(Self {
            signer: SignerMiddleware::new(provider, signer),
            _kms_guard: kms_guard,
            _monitor_guard: monitor_guard,
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
