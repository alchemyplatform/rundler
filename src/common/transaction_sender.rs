use std::sync::Arc;

use anyhow::Context;
use ethers::{
    middleware::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, PendingTransaction, Provider},
    types::{transaction::eip2718::TypedTransaction, TransactionReceipt, H256},
};
use ethers_signers::Signer;
#[cfg(test)]
use mockall::automock;
use serde_json::json;
use tonic::async_trait;

use crate::common::types::ExpectedStorage;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait TransactionSender: Send + Sync + 'static {
    async fn send_transaction(
        &self,
        tx: TypedTransaction,
        expected_storage: &ExpectedStorage,
    ) -> anyhow::Result<H256>;

    async fn wait_until_mined(&self, tx_hash: H256) -> anyhow::Result<Option<TransactionReceipt>>;
}

#[derive(Debug)]
pub struct TransactionSenderImpl<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    // The `SignerMiddleware` specifically needs to wrap a `Provider`, and not
    // just any `Middleware`, because `.request()` is only on `Provider` and not
    // on `Middleware`.
    provider: SignerMiddleware<Arc<Provider<C>>, S>,
    use_conditional_endpoint: bool,
}

#[async_trait]
impl<C, S> TransactionSender for TransactionSenderImpl<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    async fn send_transaction(
        &self,
        mut tx: TypedTransaction,
        expected_storage: &ExpectedStorage,
    ) -> anyhow::Result<H256> {
        self.provider
            .fill_transaction(&mut tx, None)
            .await
            .context("should fill transaction before signing it")?;
        let signature = self
            .provider
            .signer()
            .sign_transaction(&tx)
            .await
            .context("should sign transaction before sending")?;
        let raw_tx = tx.rlp_signed(&signature);
        if self.use_conditional_endpoint {
            self.provider
                .provider()
                .request(
                    "eth_sendRawTransactionConditional",
                    (raw_tx, json!({ "knownAccounts": expected_storage })),
                )
                .await
                .context("should send conditional raw transaction to node")
        } else {
            self.provider
                .provider()
                .request("eth_sendRawTransaction", (raw_tx,))
                .await
                .context("should send raw transaction to node")
        }
    }

    async fn wait_until_mined(&self, tx_hash: H256) -> anyhow::Result<Option<TransactionReceipt>> {
        PendingTransaction::new(tx_hash, self.provider.inner())
            .await
            .context("should wait for transaction to be mined or dropped")
    }
}

impl<C, S> TransactionSenderImpl<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    pub fn new(provider: Arc<Provider<C>>, signer: S, use_conditional_endpoint: bool) -> Self {
        Self {
            provider: SignerMiddleware::new(provider, signer),
            use_conditional_endpoint,
        }
    }
}
