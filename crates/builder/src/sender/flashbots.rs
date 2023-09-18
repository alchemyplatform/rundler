// Adapted from https://github.com/onbjerg/ethers-flashbots and
// https://github.com/gakonst/ethers-rs/blob/master/ethers-providers/src/toolbox/pending_transaction.rs
use std::{
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};

use anyhow::{bail, Context};
use ethers::{
    middleware::SignerMiddleware,
    providers::{interval, JsonRpcClient, Middleware, Provider},
    types::{transaction::eip2718::TypedTransaction, Address, TransactionReceipt, H256, U256, U64},
};
use ethers_signers::Signer;
use futures_timer::Delay;
use futures_util::{Stream, StreamExt, TryFutureExt};
use pin_project::pin_project;
use rundler_sim::ExpectedStorage;
use serde::{de, Deserialize};
use serde_json::Value;
use tonic::async_trait;

use crate::sender::{fill_and_sign, SentTxInfo, TransactionSender, TxStatus};

#[derive(Debug)]
pub(crate) struct FlashbotsTransactionSender<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    provider: SignerMiddleware<Arc<Provider<C>>, S>,
    client: FlashbotsClient,
}

#[async_trait]
impl<C, S> TransactionSender for FlashbotsTransactionSender<C, S>
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
        let status = self.client.status(tx_hash).await?;
        Ok(match status.status {
            FlashbotsAPITransactionStatus::Pending => TxStatus::Pending,
            FlashbotsAPITransactionStatus::Included => {
                // Even if Flashbots says the transaction is included, we still
                // need to wait for the provider to see it. Until it does, we're
                // still pending.
                let tx = self
                    .provider
                    .get_transaction(tx_hash)
                    .await
                    .context("provider should look up transaction included by Flashbots")?;
                if let Some(tx) = tx {
                    if let Some(block_number) = tx.block_number {
                        return Ok(TxStatus::Mined {
                            block_number: block_number.as_u64(),
                        });
                    }
                }
                TxStatus::Pending
            }
            FlashbotsAPITransactionStatus::Failed | FlashbotsAPITransactionStatus::Unknown => {
                bail!(
                    "Transaction {tx_hash:?} failed in Flashbots with status {:?}",
                    status.status,
                );
            }
            FlashbotsAPITransactionStatus::Cancelled => TxStatus::Dropped,
        })
    }

    async fn wait_until_mined(&self, tx_hash: H256) -> anyhow::Result<Option<TransactionReceipt>> {
        PendingFlashbotsTransaction::new(tx_hash, self.provider.inner(), &self.client).await
    }

    fn address(&self) -> Address {
        self.provider.address()
    }
}

impl<C, S> FlashbotsTransactionSender<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    pub(crate) fn new(provider: Arc<Provider<C>>, signer: S) -> Self {
        Self {
            provider: SignerMiddleware::new(provider, signer),
            client: FlashbotsClient::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct FlashbotsAPITransaction {
    #[serde(deserialize_with = "deserialize_optional_address")]
    from: Option<Address>,
    #[serde(deserialize_with = "deserialize_optional_address")]
    to: Option<Address>,
    #[serde(deserialize_with = "deserialize_optional_u256")]
    gas_limit: Option<U256>,
    #[serde(deserialize_with = "deserialize_optional_u256")]
    max_fee_per_gas: Option<U256>,
    #[serde(deserialize_with = "deserialize_optional_u256")]
    max_priority_fee_per_gas: Option<U256>,
    #[serde(deserialize_with = "deserialize_optional_u256")]
    nonce: Option<U256>,
    #[serde(deserialize_with = "deserialize_optional_u256")]
    value: Option<U256>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum FlashbotsAPITransactionStatus {
    Pending,
    Included,
    Failed,
    Cancelled,
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct FlashbotsAPIResponse {
    status: FlashbotsAPITransactionStatus,
    hash: H256,
    #[serde(deserialize_with = "deserialize_u64")]
    max_block_number: U64,
    transaction: FlashbotsAPITransaction,
    seen_in_mempool: bool,
}

#[derive(Debug, Default)]
struct FlashbotsClient {}

impl FlashbotsClient {
    async fn status(&self, tx_hash: H256) -> anyhow::Result<FlashbotsAPIResponse> {
        let url = format!("https://protect.flashbots.net/tx/{:?}", tx_hash);
        let resp = reqwest::get(&url).await?;
        resp.json::<FlashbotsAPIResponse>()
            .await
            .context("should deserialize FlashbotsAPIResponse")
    }
}

type PinBoxFut<'a, T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;

enum PendingFlashbotsTxState<'a> {
    InitialDelay(Pin<Box<Delay>>),
    PausedGettingTx,
    GettingTx(PinBoxFut<'a, FlashbotsAPIResponse>),
    PausedGettingReceipt,
    GettingReceipt(PinBoxFut<'a, Option<TransactionReceipt>>),
    Completed,
}

#[pin_project]
struct PendingFlashbotsTransaction<'a, P> {
    tx_hash: H256,
    provider: &'a Provider<P>,
    client: &'a FlashbotsClient,
    state: PendingFlashbotsTxState<'a>,
    interval: Box<dyn Stream<Item = ()> + Send + Unpin>,
}

impl<'a, P: JsonRpcClient> PendingFlashbotsTransaction<'a, P> {
    fn new(tx_hash: H256, provider: &'a Provider<P>, client: &'a FlashbotsClient) -> Self {
        let delay = Box::pin(Delay::new(provider.get_interval()));

        Self {
            tx_hash,
            provider,
            client,
            state: PendingFlashbotsTxState::InitialDelay(delay),
            interval: Box::new(interval(provider.get_interval())),
        }
    }
}

impl<'a, P: JsonRpcClient> Future for PendingFlashbotsTransaction<'a, P> {
    type Output = anyhow::Result<Option<TransactionReceipt>>;

    fn poll(self: Pin<&mut Self>, ctx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.state {
            PendingFlashbotsTxState::InitialDelay(fut) => {
                futures_util::ready!(fut.as_mut().poll(ctx));
                let status_fut = Box::pin(this.client.status(*this.tx_hash));
                *this.state = PendingFlashbotsTxState::GettingTx(status_fut);
                ctx.waker().wake_by_ref();
                return Poll::Pending;
            }
            PendingFlashbotsTxState::PausedGettingTx => {
                let _ready = futures_util::ready!(this.interval.poll_next_unpin(ctx));
                let status_fut = Box::pin(this.client.status(*this.tx_hash));
                *this.state = PendingFlashbotsTxState::GettingTx(status_fut);
                ctx.waker().wake_by_ref();
                return Poll::Pending;
            }
            PendingFlashbotsTxState::GettingTx(fut) => {
                let status = futures_util::ready!(fut.as_mut().poll(ctx))?;
                tracing::debug!("Transaction:status {:?}:{:?}", *this.tx_hash, status.status);
                match status.status {
                    FlashbotsAPITransactionStatus::Pending => {
                        *this.state = PendingFlashbotsTxState::PausedGettingTx;
                        ctx.waker().wake_by_ref();
                    }
                    FlashbotsAPITransactionStatus::Included => {
                        let receipt_fut = Box::pin(
                            this.provider
                                .get_transaction_receipt(*this.tx_hash)
                                .map_err(|e| anyhow::anyhow!("failed to get receipt: {:?}", e)),
                        );
                        *this.state = PendingFlashbotsTxState::GettingReceipt(receipt_fut);
                        ctx.waker().wake_by_ref();
                    }
                    FlashbotsAPITransactionStatus::Cancelled => {
                        return Poll::Ready(Ok(None));
                    }
                    FlashbotsAPITransactionStatus::Failed
                    | FlashbotsAPITransactionStatus::Unknown => {
                        return Poll::Ready(Err(anyhow::anyhow!(
                            "transaction failed with status {:?}",
                            status.status
                        )));
                    }
                }
            }
            PendingFlashbotsTxState::PausedGettingReceipt => {
                let _ready = futures_util::ready!(this.interval.poll_next_unpin(ctx));
                let fut = Box::pin(
                    this.provider
                        .get_transaction_receipt(*this.tx_hash)
                        .map_err(|e| anyhow::anyhow!("failed to get receipt: {:?}", e)),
                );
                *this.state = PendingFlashbotsTxState::GettingReceipt(fut);
                ctx.waker().wake_by_ref();
            }
            PendingFlashbotsTxState::GettingReceipt(fut) => {
                if let Some(receipt) = futures_util::ready!(fut.as_mut().poll(ctx))? {
                    *this.state = PendingFlashbotsTxState::Completed;
                    return Poll::Ready(Ok(Some(receipt)));
                } else {
                    *this.state = PendingFlashbotsTxState::PausedGettingReceipt;
                    ctx.waker().wake_by_ref();
                }
            }
            PendingFlashbotsTxState::Completed => {
                panic!("polled pending flashbots transaction future after completion")
            }
        }

        Poll::Pending
    }
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<U64, D::Error>
where
    D: de::Deserializer<'de>,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::String(s) => {
            if s.as_str() == "0x" {
                U64::zero()
            } else if s.as_str().starts_with("0x") {
                U64::from_str_radix(s.as_str(), 16).map_err(de::Error::custom)?
            } else {
                U64::from_dec_str(s.as_str()).map_err(de::Error::custom)?
            }
        }
        Value::Number(num) => U64::from(
            num.as_u64()
                .ok_or_else(|| de::Error::custom("Invalid number"))?,
        ),
        _ => return Err(de::Error::custom("wrong type")),
    })
}

fn deserialize_optional_u256<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
where
    D: de::Deserializer<'de>,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::String(s) => {
            if s.is_empty() {
                None
            } else if s.as_str() == "0x" {
                Some(U256::zero())
            } else if s.as_str().starts_with("0x") {
                Some(U256::from_str_radix(s.as_str(), 16).map_err(de::Error::custom)?)
            } else {
                Some(U256::from_dec_str(s.as_str()).map_err(de::Error::custom)?)
            }
        }
        Value::Number(num) => Some(U256::from(
            num.as_u64()
                .ok_or_else(|| de::Error::custom("Invalid number"))?,
        )),
        Value::Null => None,
        _ => return Err(de::Error::custom("wrong type")),
    })
}

fn deserialize_optional_address<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
where
    D: de::Deserializer<'de>,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::String(s) => {
            if s.is_empty() || s.as_str() == "0x" {
                None
            } else {
                Some(Address::from_str(s.as_str()).map_err(de::Error::custom)?)
            }
        }
        Value::Null => None,
        _ => return Err(de::Error::custom("expected a hexadecimal string")),
    })
}
