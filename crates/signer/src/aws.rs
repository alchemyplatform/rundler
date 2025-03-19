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

use std::time::Duration;

use alloy_consensus::SignableTransaction;
use alloy_network::{EthereumWallet, TxSigner};
use alloy_primitives::{Address, PrimitiveSignature};
use alloy_signer_aws::AwsSigner;
use anyhow::Context;
use aws_config::BehaviorVersion;
use rslock::{Lock, LockGuard, LockManager};
use rundler_task::TaskSpawner;
use tokio::{sync::oneshot, time::sleep};

use crate::Result;

pub(crate) async fn create_wallet_from_key_ids(
    key_ids: Vec<String>,
    chain_id: u64,
) -> Result<EthereumWallet> {
    let mut wallet = EthereumWallet::default();
    let config = aws_config::load_defaults(BehaviorVersion::v2025_01_17()).await;
    let client = aws_sdk_kms::Client::new(&config);

    for key_id in key_ids {
        let signer = AwsSigner::new(client.clone(), key_id.to_string(), Some(chain_id))
            .await
            .context("should create aws kms signer")?;
        wallet.register_signer(signer);
    }

    Ok(wallet)
}

pub(crate) async fn create_signer_from_key_id(key_id: String, chain_id: u64) -> Result<AwsSigner> {
    let config = aws_config::load_defaults(BehaviorVersion::v2025_01_17()).await;
    let client = aws_sdk_kms::Client::new(&config);
    Ok(
        AwsSigner::new(client.clone(), key_id.to_string(), Some(chain_id))
            .await
            .context("should create aws kms signer")?,
    )
}

pub(crate) struct LockingKmsSigner {
    inner: AwsSigner,
    key_id: String,
}

#[async_trait::async_trait]
impl TxSigner<PrimitiveSignature> for LockingKmsSigner {
    fn address(&self) -> Address {
        TxSigner::address(&self.inner)
    }

    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<PrimitiveSignature>,
    ) -> alloy_signer::Result<PrimitiveSignature> {
        self.inner.sign_transaction(tx).await
    }
}

impl LockingKmsSigner {
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) async fn connect<T: TaskSpawner>(
        task_spawner: &T,
        chain_id: u64,
        key_ids: Vec<String>,
        redis_uri: String,
        ttl_millis: u64,
    ) -> Result<Self> {
        let config = aws_config::load_defaults(BehaviorVersion::v2025_01_17()).await;
        let client = aws_sdk_kms::Client::new(&config);

        let key_id = if key_ids.len() > 1 {
            let (tx, rx) = oneshot::channel::<String>();
            task_spawner.spawn_critical(
                "kms lock manager loop",
                Box::pin(Self::lock_manager_loop(
                    redis_uri, key_ids, chain_id, ttl_millis, tx,
                )),
            );
            rx.await.context("should lock key_id")?
        } else {
            key_ids
                .first()
                .expect("There should be at least one kms key")
                .to_owned()
        };

        let signer = AwsSigner::new(client, key_id.clone(), Some(chain_id))
            .await
            .context("should create signer")?;

        tracing::info!(
            "Connected to KMS key {key_id}. Address: {}",
            signer.address()
        );

        Ok(Self {
            inner: signer,
            key_id,
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
        let mut locked_id = None;
        let lock_context = key_ids
            .into_iter()
            .map(|id| (format!("{chain_id}:{id}"), id))
            .collect::<Vec<_>>();

        for (lock_id, key_id) in lock_context.iter() {
            if let Some(l) = try_lock(&lm, lock_id, ttl_millis).await {
                lock = Some(l);
                kid = Some(key_id.clone());
                locked_id = Some(lock_id.clone());
                break;
            }
        }
        if lock.is_none() {
            return;
        }

        let lock_id = locked_id.unwrap();
        let _ = locked_tx.send(kid.unwrap());
        let mut lg_opt = Some(LockGuard {
            lock: lock.unwrap(),
        });

        loop {
            sleep(Duration::from_millis(ttl_millis / 10)).await;

            if let Some(lg) = &lg_opt {
                match lm.extend(&lg.lock, Duration::from_millis(ttl_millis)).await {
                    Ok(_) => {
                        tracing::debug!("extended lock");
                    }
                    Err(e) => {
                        tracing::error!("could not extend lock: {e:?}");
                        lg_opt.take();
                    }
                }
            } else if let Some(l) = try_lock(&lm, &lock_id, ttl_millis).await {
                lg_opt = Some(LockGuard { lock: l });
            } else {
                tracing::error!("could not re-lock key_id {lock_id}");
            }
        }
    }
}

async fn try_lock(lm: &LockManager, lock_id: &str, ttl_millis: u64) -> Option<Lock> {
    match lm
        .lock(lock_id.as_bytes(), Duration::from_millis(ttl_millis))
        .await
    {
        Ok(l) => Some(l),
        Err(e) => {
            tracing::warn!("could not lock key_id {lock_id}: {e:?}");
            None
        }
    }
}
