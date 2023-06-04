use std::sync::Arc;

use anyhow::Context;
use ethers::{
    middleware::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, PendingTransaction, Provider},
    types::{transaction::eip2718::TypedTransaction, Address, TransactionReceipt, H256, U256},
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
    ) -> anyhow::Result<SentTxInfo>;

    async fn wait_until_mined(&self, tx_hash: H256) -> anyhow::Result<Option<TransactionReceipt>>;

    fn address(&self) -> Address;
}

#[derive(Debug)]
pub struct SentTxInfo {
    pub nonce: U256,
    pub tx_hash: H256,
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
    ) -> anyhow::Result<SentTxInfo> {
        self.provider
            .fill_transaction(&mut tx, None)
            .await
            .context("should fill transaction before signing it")?;
        let nonce = *tx
            .nonce()
            .context("nonce should be set when transaction is filled")?;
        let signature = self
            .provider
            .signer()
            .sign_transaction(&tx)
            .await
            .context("should sign transaction before sending")?;
        let raw_tx = tx.rlp_signed(&signature);
        let tx_hash: H256 = if self.use_conditional_endpoint {
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
        }?;
        Ok(SentTxInfo { nonce, tx_hash })
    }

    async fn wait_until_mined(&self, tx_hash: H256) -> anyhow::Result<Option<TransactionReceipt>> {
        PendingTransaction::new(tx_hash, self.provider.inner())
            .await
            .context("should wait for transaction to be mined or dropped")
    }

    fn address(&self) -> Address {
        self.provider.address()
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
