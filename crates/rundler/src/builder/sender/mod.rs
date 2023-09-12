mod bloxroute;
mod conditional;
mod flashbots;
mod raw;

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
pub(crate) use bloxroute::PolygonBloxrouteTransactionSender;
pub(crate) use conditional::ConditionalTransactionSender;
use enum_dispatch::enum_dispatch;
use ethers::{
    prelude::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, Provider},
    types::{
        transaction::eip2718::TypedTransaction, Address, Bytes, Chain, TransactionReceipt, H256,
        U256,
    },
};
use ethers_signers::Signer;
pub(crate) use flashbots::FlashbotsTransactionSender;
#[cfg(test)]
use mockall::automock;
pub(crate) use raw::RawTransactionSender;
use rundler_sim::ExpectedStorage;

#[derive(Debug)]
pub(crate) struct SentTxInfo {
    pub(crate) nonce: U256,
    pub(crate) tx_hash: H256,
}

#[derive(Debug)]
pub(crate) enum TxStatus {
    Pending,
    Mined { block_number: u64 },
    Dropped,
}

#[async_trait]
#[enum_dispatch(TransactionSenderEnum<_C,_S>)]
#[cfg_attr(test, automock)]
pub(crate) trait TransactionSender: Send + Sync + 'static {
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
pub(crate) enum TransactionSenderEnum<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    Raw(RawTransactionSender<C, S>),
    Conditional(ConditionalTransactionSender<C, S>),
    Flashbots(FlashbotsTransactionSender<C, S>),
    PolygonBloxroute(PolygonBloxrouteTransactionSender<C, S>),
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

pub(crate) fn get_sender<C, S>(
    provider: Arc<Provider<C>>,
    signer: S,
    is_conditional: bool,
    url: &str,
    chain_id: u64,
    poll_interval: Duration,
    bloxroute_auth_header: &Option<String>,
) -> anyhow::Result<TransactionSenderEnum<C, S>>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    let sender = if is_conditional {
        ConditionalTransactionSender::new(provider, signer).into()
    } else if url.contains("flashbots") {
        FlashbotsTransactionSender::new(provider, signer).into()
    } else if let Some(auth_header) = bloxroute_auth_header {
        assert!(
            chain_id == Chain::Polygon as u64,
            "Bloxroute sender is only supported on Polygon mainnet"
        );
        PolygonBloxrouteTransactionSender::new(provider, signer, poll_interval, auth_header)?.into()
    } else {
        RawTransactionSender::new(provider, signer).into()
    };

    Ok(sender)
}
