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
use std::{str::FromStr, sync::Arc};

use anyhow::{anyhow, Context};
use ethers::{
    middleware::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, Provider},
    types::{transaction::eip2718::TypedTransaction, Address, Bytes, H256, U256, U64},
    utils,
};
use ethers_signers::Signer;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client, Response,
};
use rundler_types::GasFees;
use serde::{de, Deserialize, Serialize};
use serde_json::{json, Value};
use tonic::async_trait;

use super::{
    fill_and_sign, ExpectedStorage, Result, SentTxInfo, TransactionSender, TxSenderError, TxStatus,
};
use crate::sender::CancelTxInfo;

#[derive(Debug)]
pub(crate) struct FlashbotsTransactionSender<C, S, FS> {
    provider: SignerMiddleware<Arc<Provider<C>>, S>,
    flashbots_client: FlashbotsClient<FS>,
}

#[async_trait]
impl<C, S, FS> TransactionSender for FlashbotsTransactionSender<C, S, FS>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
    FS: Signer + 'static,
{
    async fn send_transaction(
        &self,
        tx: TypedTransaction,
        _expected_storage: &ExpectedStorage,
    ) -> Result<SentTxInfo> {
        let (raw_tx, nonce) = fill_and_sign(&self.provider, tx).await?;

        let tx_hash = self
            .flashbots_client
            .send_private_transaction(raw_tx)
            .await?;

        Ok(SentTxInfo { nonce, tx_hash })
    }

    async fn cancel_transaction(
        &self,
        tx_hash: H256,
        _nonce: U256,
        _to: Address,
        _gas_fees: GasFees,
    ) -> Result<CancelTxInfo> {
        let success = self
            .flashbots_client
            .cancel_private_transaction(tx_hash)
            .await?;

        if !success {
            return Err(TxSenderError::SoftCancelFailed);
        }

        Ok(CancelTxInfo {
            tx_hash: H256::zero(),
            soft_cancelled: true,
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
            FlashbotsAPITransactionStatus::Unknown => {
                return Err(TxSenderError::Other(anyhow!(
                    "Transaction {tx_hash:?} unknown in Flashbots API",
                )));
            }
            FlashbotsAPITransactionStatus::Failed | FlashbotsAPITransactionStatus::Cancelled => {
                TxStatus::Dropped
            }
        })
    }

    fn address(&self) -> Address {
        self.provider.address()
    }
}

impl<C, S, FS> FlashbotsTransactionSender<C, S, FS>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
    FS: Signer + 'static,
{
    pub(crate) fn new(
        provider: Arc<Provider<C>>,
        tx_signer: S,
        flashbots_signer: FS,
        builders: Vec<String>,
        relay_url: String,
        status_url: String,
    ) -> Result<Self> {
        Ok(Self {
            provider: SignerMiddleware::new(provider, tx_signer),
            flashbots_client: FlashbotsClient::new(
                flashbots_signer,
                builders,
                relay_url,
                status_url,
            ),
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Preferences {
    fast: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    privacy: Option<Privacy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validity: Option<Validity>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Privacy {
    #[serde(skip_serializing_if = "Option::is_none")]
    hints: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    builders: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Validity {
    #[serde(skip_serializing_if = "Option::is_none")]
    refund: Option<Vec<Refund>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Refund {
    address: String,
    percent: u8,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct FlashbotsSendPrivateTransactionRequest {
    tx: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_block_number: Option<U256>,
    preferences: Preferences,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct FlashbotsSendPrivateTransactionResponse {
    result: H256,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct FlashbotsCancelPrivateTransactionRequest {
    tx_hash: H256,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct FlashbotsCancelPrivateTransactionResponse {
    result: bool,
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
struct FlashbotsClient<S> {
    http_client: Client,
    signer: S,
    builders: Vec<String>,
    relay_url: String,
    status_url: String,
}

impl<S> FlashbotsClient<S> {
    fn new(signer: S, builders: Vec<String>, relay_url: String, status_url: String) -> Self {
        Self {
            http_client: Client::new(),
            signer,
            builders,
            relay_url,
            status_url,
        }
    }

    async fn status(&self, tx_hash: H256) -> anyhow::Result<FlashbotsAPIResponse> {
        let url = format!("{}{:?}", self.status_url, tx_hash);
        let resp = self.http_client.get(&url).send().await?;
        resp.json::<FlashbotsAPIResponse>()
            .await
            .context("should deserialize FlashbotsAPIResponse")
    }
}

impl<S> FlashbotsClient<S>
where
    S: Signer,
{
    async fn send_private_transaction(&self, raw_tx: Bytes) -> anyhow::Result<H256> {
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
            "method": "eth_sendPrivateTransaction",
            "params": [
                FlashbotsSendPrivateTransactionRequest {
                    tx: raw_tx,
                    max_block_number: None,
                    preferences,
                }],
            "id": 1
        });

        let response = self.sign_send_request(body).await?;

        let parsed_response = response
            .json::<FlashbotsSendPrivateTransactionResponse>()
            .await
            .map_err(|e| anyhow!("failed to deserialize Flashbots response: {:?}", e))?;

        Ok(parsed_response.result)
    }

    async fn cancel_private_transaction(&self, tx_hash: H256) -> anyhow::Result<bool> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_cancelPrivateTransaction",
            "params": [
                FlashbotsCancelPrivateTransactionRequest { tx_hash }
            ],
            "id": 1
        });

        let response = self.sign_send_request(body).await?;

        let parsed_response = response
            .json::<FlashbotsCancelPrivateTransactionResponse>()
            .await
            .map_err(|e| anyhow!("failed to deserialize Flashbots response: {:?}", e))?;

        Ok(parsed_response.result)
    }

    async fn sign_send_request(&self, body: Value) -> anyhow::Result<Response> {
        let signature = self
            .signer
            .sign_message(format!(
                "0x{:x}",
                H256::from(utils::keccak256(body.to_string()))
            ))
            .await
            .expect("Signature failed");
        let header_val =
            HeaderValue::from_str(&format!("{:?}:0x{}", self.signer.address(), signature))
                .expect("Header contains invalid characters");

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert("x-flashbots-signature", header_val);

        // Send the request
        self.http_client
            .post(&self.relay_url)
            .headers(headers)
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| anyhow!("failed to send request to Flashbots: {:?}", e))
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
