use std::sync::Arc;

use anyhow::Context;
use ethers::{
    middleware::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, PendingTransaction, Provider},
    types::{transaction::eip2718::TypedTransaction, Address, TransactionReceipt, H256},
};
use ethers_signers::Signer;
use tonic::async_trait;

use crate::{
    builder::sender::{fill_and_sign, SentTxInfo, TransactionSender, TxStatus},
    common::types::ExpectedStorage,
};

#[derive(Debug)]
pub struct RawTransactionSender<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    // The `SignerMiddleware` specifically needs to wrap a `Provider`, and not
    // just any `Middleware`, because `.request()` is only on `Provider` and not
    // on `Middleware`.
    provider: SignerMiddleware<Arc<Provider<C>>, S>,
}

#[async_trait]
impl<C, S> TransactionSender for RawTransactionSender<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    async fn send_transaction(
        &self,
        tx: TypedTransaction,
        _expected_storage: &ExpectedStorage,
    ) -> anyhow::Result<SentTxInfo> {
        let (raw_tx, nonce) = fill_and_sign(&self.provider, tx).await?;

        let tx_hash = self
            .provider
            .provider()
            .request("eth_sendRawTransaction", (raw_tx,))
            .await
            .context("should send raw transaction to node")?;
        Ok(SentTxInfo { nonce, tx_hash })
    }

    async fn get_transaction_status(&self, tx_hash: H256) -> anyhow::Result<TxStatus> {
        let tx = self
            .provider
            .get_transaction(tx_hash)
            .await
            .context("provider should return transaction status")?;
        Ok(match tx {
            None => TxStatus::Dropped,
            Some(tx) => match tx.block_number {
                None => TxStatus::Pending,
                Some(block_number) => TxStatus::Mined {
                    block_number: block_number.as_u64(),
                },
            },
        })
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

impl<C, S> RawTransactionSender<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    pub fn new(provider: Arc<Provider<C>>, signer: S) -> Self {
        Self {
            provider: SignerMiddleware::new(provider, signer),
        }
    }
}
