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

// Adapted from https://github.com/onbjerg/ethers-flashbots and
// https://github.com/gakonst/ethers-rs/blob/master/ethers-providers/src/toolbox/pending_transaction.rs
use std::{
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};

use anyhow::{anyhow, Context};
use ethers::{
    middleware::SignerMiddleware,
    providers::{interval, JsonRpcClient, Middleware, Provider},
    types::{
        transaction::eip2718::TypedTransaction, Address, TransactionReceipt, TxHash, H256, U256,
        U64,
    },
    utils,
};
use ethers_signers::Signer;
use futures_timer::Delay;
use futures_util::{Stream, StreamExt, TryFutureExt};
use jsonrpsee::core::traits::ToRpcParams;
use pin_project::pin_project;
use reqwest::{
    header::{HeaderMap, CONTENT_TYPE},
    Client,
};
use serde::{de, Deserialize, Serialize};
use serde_json::{json, value::RawValue, Value};
use tonic::async_trait;

use super::{
    fill_and_sign, ExpectedStorage, Result, SentTxInfo, TransactionSender, TxSenderError, TxStatus,
};

#[derive(Serialize, Deserialize, Debug)]
struct Preferences {
    fast: bool,
    privacy: Option<Privacy>,
    validity: Option<Validity>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Privacy {
    hints: Option<Vec<String>>,
    builders: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Validity {
    refund: Option<Vec<Refund>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Refund {
    address: String,
    percent: u8,
}

#[derive(Debug)]
pub(crate) struct FlashbotsTransactionSender<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    provider: SignerMiddleware<Arc<Provider<C>>, S>,
    flashbots_client: FlashbotsClient,
    http_client: Client,
    builders: Vec<String>,
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
    ) -> Result<SentTxInfo> {
        let (raw_tx, nonce) = fill_and_sign(&self.provider, tx).await?;

        let preferences = Preferences {
            fast: false,
            privacy: Some(Privacy {
                hints: None,
                builders: Some(self.builders.clone()),
            }),
            validity: None,
        };

        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_sendPrivateRawTransaction",
            "params": [raw_tx, preferences],
            "id": 1
        });

        let flashbots_header = format!(
            "{}:{}",
            self.provider.signer().address(),
            self.provider
                .signer()
                .sign_message(utils::keccak256(body.to_string()))
                .await
                .unwrap()
        );

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert("X-Flashbots-Signature", flashbots_header.parse().unwrap());

        // Send the request
        let response = self
            .http_client
            .post("https://relay.flashbots.net")
            .headers(headers)
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| anyhow!("failed to send transaction to Flashbots: {:?}", e))?;

        let parsed_response = response
            .json::<FlashbotsResponse>()
            .await
            .map_err(|e| anyhow!("failed to deserialize Flashbots response: {:?}", e))?;

        Ok(SentTxInfo {
            nonce,
            tx_hash: parsed_response.tx_hash,
        })
    }

    async fn get_transaction_status(&self, tx_hash: H256) -> Result<TxStatus> {
        let status = self.flashbots_client.status(tx_hash).await?;
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
                return Err(TxSenderError::Other(anyhow!(
                    "Transaction {tx_hash:?} failed in Flashbots with status {:?}",
                    status.status,
                )));
            }
            FlashbotsAPITransactionStatus::Cancelled => TxStatus::Dropped,
        })
    }

    async fn wait_until_mined(&self, tx_hash: H256) -> Result<Option<TransactionReceipt>> {
        Ok(
            PendingFlashbotsTransaction::new(
                tx_hash,
                self.provider.inner(),
                &self.flashbots_client,
            )
            .await?,
        )
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
    pub(crate) fn new(
        provider: Arc<Provider<C>>,
        signer: S,
        builders: Vec<String>,
    ) -> Result<Self> {
        Ok(Self {
            provider: SignerMiddleware::new(provider, signer),
            flashbots_client: FlashbotsClient::new(),
            http_client: Client::new(),
            builders,
        })
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

#[derive(Debug)]
struct FlashbotsClient {}

impl FlashbotsClient {
    fn new() -> Self {
        Self {}
    }

    async fn status(&self, tx_hash: H256) -> anyhow::Result<FlashbotsAPIResponse> {
        let url = format!("https://protect.flashbots.net/tx/{:?}", tx_hash);
        let resp = reqwest::get(&url).await?;
        resp.json::<FlashbotsAPIResponse>()
            .await
            .context("should deserialize FlashbotsAPIResponse")
    }
}

#[derive(Serialize)]
struct FlashbotsRequest {
    transaction: String,
}

impl ToRpcParams for FlashbotsRequest {
    fn to_rpc_params(self) -> std::result::Result<Option<Box<RawValue>>, jsonrpsee::core::Error> {
        let s = String::from_utf8(serde_json::to_vec(&self)?).expect("Valid UTF8 format");
        RawValue::from_string(s)
            .map(Some)
            .map_err(jsonrpsee::core::Error::ParseError)
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct FlashbotsResponse {
    tx_hash: TxHash,
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

fn deserialize_u64<'de, D>(deserializer: D) -> std::result::Result<U64, D::Error>
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

fn deserialize_optional_u256<'de, D>(deserializer: D) -> std::result::Result<Option<U256>, D::Error>
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

fn deserialize_optional_address<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Address>, D::Error>
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
