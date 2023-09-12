mod conditional;
mod flashbots;
mod raw;

use std::sync::Arc;

use anyhow::Context;
pub use conditional::ConditionalTransactionSender;
use enum_dispatch::enum_dispatch;
use ethers::{
    prelude::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, Provider},
    types::{
        transaction::eip2718::TypedTransaction, Address, Bytes, TransactionReceipt, H256, U256,
    },
};
use ethers_signers::Signer;
pub use flashbots::FlashbotsTransactionSender;
#[cfg(test)]
use mockall::automock;
pub use raw::RawTransactionSender;
use tonic::async_trait;

use crate::common::types::ExpectedStorage;

#[derive(Debug)]
pub struct SentTxInfo {
    pub nonce: U256,
    pub tx_hash: H256,
}

#[derive(Debug)]
pub enum TxStatus {
    Pending,
    Mined { block_number: u64 },
    Dropped,
}

#[async_trait]
#[enum_dispatch(TransactionSenderEnum<_C,_S>)]
#[cfg_attr(test, automock)]
pub trait TransactionSender: Send + Sync + 'static {
    async fn send_transaction(
        &self,
        tx: TypedTransaction,
        expected_storage: &ExpectedStorage,
    ) -> anyhow::Result<SentTxInfo>;

    async fn get_transaction_status(&self, tx_hash: H256) -> anyhow::Result<TxStatus>;

    async fn wait_until_mined(&self, tx_hash: H256) -> anyhow::Result<Option<TransactionReceipt>>;

    fn address(&self) -> Address;
}

#[enum_dispatch]
pub enum TransactionSenderEnum<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    Raw(RawTransactionSender<C, S>),
    Conditional(ConditionalTransactionSender<C, S>),
    Flashbots(FlashbotsTransactionSender<C, S>),
}

async fn fill_and_sign<C, S>(
    provider: &SignerMiddleware<Arc<Provider<C>>, S>,
    mut tx: TypedTransaction,
) -> anyhow::Result<(Bytes, U256)>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    provider
        .fill_transaction(&mut tx, None)
        .await
        .context("should fill transaction before signing it")?;
    let nonce = *tx
        .nonce()
        .context("nonce should be set when transaction is filled")?;
    let signature = provider
        .signer()
        .sign_transaction(&tx)
        .await
        .context("should sign transaction before sending")?;
    Ok((tx.rlp_signed(&signature), nonce))
}

pub fn get_sender<C, S>(
    provider: Arc<Provider<C>>,
    signer: S,
    is_conditional: bool,
    url: &str,
) -> TransactionSenderEnum<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    if is_conditional {
        ConditionalTransactionSender::new(provider, signer).into()
    } else if url.contains("flashbots") {
        FlashbotsTransactionSender::new(provider, signer).into()
    } else {
        RawTransactionSender::new(provider, signer).into()
    }
}
