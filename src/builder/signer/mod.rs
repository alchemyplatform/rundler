use std::sync::Arc;

use anyhow::Context;
use ethers::{
    abi::Address,
    prelude::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, Provider},
    types::{Eip1559TransactionRequest, TransactionReceipt},
};
use ethers_signers::{LocalWallet, Signer};

mod aws;
pub use aws::*;
#[cfg(test)]
use mockall::automock;
use tokio::task::AbortHandle;
use tonic::async_trait;

/// A trait for sending transactions
#[cfg_attr(test, automock)]
#[async_trait]
pub trait SignerLike: Send + Sync {
    async fn send_transaction(
        &self,
        tx: Eip1559TransactionRequest,
    ) -> anyhow::Result<TransactionReceipt>;
}

/// Generic implementation of SignerLike for SignerMiddleware
#[async_trait]
impl<M, S> SignerLike for SignerMiddleware<M, S>
where
    M: Middleware + 'static,
    S: Signer + 'static,
{
    async fn send_transaction(
        &self,
        tx: Eip1559TransactionRequest,
    ) -> anyhow::Result<TransactionReceipt> {
        Middleware::send_transaction(&self, tx, None)
            .await
            .context("should send tx")?
            .await
            .context("should get receipt")?
            .context("receipt should be some")
    }
}

/// A local signer handle
#[derive(Debug)]
pub struct LocalSigner<C: JsonRpcClient> {
    signer: SignerMiddleware<Arc<Provider<C>>, LocalWallet>,
    monitor_abort_handle: AbortHandle,
}

impl<C: JsonRpcClient> Drop for LocalSigner<C> {
    fn drop(&mut self) {
        self.monitor_abort_handle.abort();
    }
}

#[async_trait]
impl<C: JsonRpcClient + 'static> SignerLike for LocalSigner<C> {
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

impl<C: JsonRpcClient + 'static> LocalSigner<C> {
    pub async fn connect(
        provider: Arc<Provider<C>>,
        chain_id: u64,
        private_key: String,
    ) -> anyhow::Result<Self> {
        let signer = private_key
            .parse::<LocalWallet>()
            .context("should create signer")?;
        let monitor_abort_handle = tokio::spawn(super::signer::monitor_account_balance(
            signer.address(),
            provider.clone(),
        ))
        .abort_handle();

        Ok(Self {
            signer: SignerMiddleware::new(provider, signer.with_chain_id(chain_id)),
            monitor_abort_handle,
        })
    }
}

pub async fn monitor_account_balance<C: JsonRpcClient>(addr: Address, provider: Arc<Provider<C>>) {
    loop {
        let balance = provider.get_balance(addr, None).await.unwrap();
        let eth_balance = balance.as_u64() as f64 / 1e18;
        tracing::info!("account {addr:?} balance: {}", eth_balance);
        metrics::gauge!("bundle_builder_account_balance", eth_balance, "addr" => addr.to_string());
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}
