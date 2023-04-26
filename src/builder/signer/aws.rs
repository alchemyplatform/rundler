use std::{sync::Arc, time::Duration};

use anyhow::Context;
use ethers::providers::Middleware;
use ethers_signers::{AwsSigner, Signer};
use rslock::{LockGuard, LockManager};
use rusoto_core::Region;
use rusoto_kms::KmsClient;
use tokio::{sync::oneshot, time::sleep};

use super::monitor_account_balance;
use crate::common::handle::SpawnGuard;

/// A KMS signer handle that will release the key_id when dropped.
#[derive(Debug)]
pub struct KmsSigner {
    pub signer: AwsSigner,
    _kms_guard: SpawnGuard,
    _monitor_guard: SpawnGuard,
}

impl KmsSigner {
    pub async fn connect<M: Middleware + 'static>(
        provider: Arc<M>,
        chain_id: u64,
        region: Region,
        key_ids: Vec<String>,
        redis_uri: String,
        ttl_millis: u64,
    ) -> anyhow::Result<Self> {
        let (tx, rx) = oneshot::channel::<String>();
        let kms_guard = SpawnGuard::spawn_with_guard(Self::lock_manager_loop(
            redis_uri, key_ids, chain_id, ttl_millis, tx,
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
            signer,
            _kms_guard: kms_guard,
            _monitor_guard: monitor_guard,
        })
    }

    async fn lock_manager_loop(
        redis_url: String,
        key_ids: Vec<String>,
        chain_id: u64,
        ttl_millis: u64,
        locked_tx: oneshot::Sender<String>,
    ) {
        let lm = LockManager::new(vec![redis_url]);

        let mut lock = None;
        let mut kid = None;
        let lock_context = key_ids
            .into_iter()
            .map(|id| (format!("{chain_id}:{id}"), id))
            .collect::<Vec<_>>();

        for (lock_id, key_id) in lock_context.iter() {
            match lm.lock(lock_id.as_bytes(), ttl_millis as usize).await {
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
