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
use std::str::FromStr;

use alloy_primitives::{Address, B256, Bytes, U64, U256, hex, utils};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, anyhow};
use reqwest::{
    Client, Response,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};
use rundler_provider::TransactionRequest;
use rundler_signer::SignerLease;
use rundler_types::GasFees;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, de};
use serde_json::{Value, json};

use super::{ExpectedStorage, Result, TransactionSender, TxSenderError};
use crate::sender::CancelTxInfo;

/// Errors from the Flashbots relay's raw HTTP JSON-RPC interface.
#[derive(Debug, thiserror::Error)]
enum FlashbotsError {
    /// The relay responded with a well-formed JSON-RPC error object - a
    /// verdict on this specific request, not evidence the relay is down.
    #[error("Flashbots RPC error {code}: {message}")]
    Rpc { code: i64, message: String },
    /// Network failure, non-2xx status with no JSON-RPC error body, or any
    /// other response that isn't a recognizable JSON-RPC envelope.
    #[error(transparent)]
    Transport(#[from] anyhow::Error),
}

impl From<FlashbotsError> for TxSenderError {
    fn from(value: FlashbotsError) -> Self {
        match value {
            FlashbotsError::Rpc { code, message } => {
                if let Some(known) = super::parse_known_call_execution_failed(&message, code) {
                    return known;
                }
                tracing::warn!(
                    rpc_error_code = code,
                    rpc_error_message = %message,
                    "Unrecognized Flashbots RPC error, treating as sender unavailable"
                );
                TxSenderError::SenderUnavailable(anyhow::anyhow!(
                    "unrecognized Flashbots RPC error {code}: {message}"
                ))
            }
            FlashbotsError::Transport(err) => {
                tracing::warn!(
                    error = %err,
                    "Flashbots request failed, treating as sender unavailable"
                );
                TxSenderError::SenderUnavailable(err)
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct FlashbotsTransactionSender {
    flashbots_client: FlashbotsClient,
}

#[async_trait::async_trait]
impl TransactionSender for FlashbotsTransactionSender {
    async fn send_transaction(
        &self,
        tx: TransactionRequest,
        _expected_storage: &ExpectedStorage,
        signer: &SignerLease,
    ) -> Result<B256> {
        let raw_tx = signer
            .sign_tx_raw(tx)
            .await
            .context("failed to sign transaction")?;

        let tx_hash = self
            .flashbots_client
            .send_private_transaction(raw_tx)
            .await?;

        Ok(tx_hash)
    }

    async fn cancel_transaction(
        &self,
        tx_hash: B256,
        _nonce: u64,
        _gas_fees: GasFees,
        _signer: &SignerLease,
    ) -> Result<CancelTxInfo> {
        let success = self
            .flashbots_client
            .cancel_private_transaction(tx_hash)
            .await?;

        if !success {
            return Err(TxSenderError::SoftCancelFailed);
        }

        Ok(CancelTxInfo {
            tx_hash: B256::ZERO,
            soft_cancelled: true,
        })
    }
}

impl FlashbotsTransactionSender {
    pub(crate) fn new(
        flashbots_auth_key: SecretString,
        builders: Vec<String>,
        relay_url: String,
    ) -> Result<Self> {
        Ok(Self {
            flashbots_client: FlashbotsClient::new(flashbots_auth_key, builders, relay_url),
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

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct FlashbotsCancelPrivateTransactionRequest {
    tx_hash: B256,
}

/// A JSON-RPC 2.0 response envelope that may carry either a `result` or an
/// `error` object, so a well-formed RPC-level rejection from the relay can be
/// told apart from a transport failure or a garbled response.
#[derive(Deserialize, Debug)]
struct JsonRpcEnvelope<T> {
    // Named default fns (rather than bare `#[serde(default)]`) avoid serde
    // deriving a spurious `T: Default` bound on the whole impl - Option<T> is
    // Default for any T, but serde's derive can't see that through a bare
    // `Default::default()` call.
    #[serde(default = "Option::default")]
    result: Option<T>,
    #[serde(default = "Option::default")]
    error: Option<JsonRpcErrorObject>,
}

#[derive(Deserialize, Debug)]
struct JsonRpcErrorObject {
    code: i64,
    message: String,
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
    hash: B256,
    #[serde(deserialize_with = "deserialize_u64")]
    max_block_number: U64,
    transaction: FlashbotsAPITransaction,
    seen_in_mempool: bool,
}

#[derive(Debug)]
struct FlashbotsClient {
    http_client: Client,
    signer: PrivateKeySigner,
    builders: Vec<String>,
    relay_url: String,
}

impl FlashbotsClient {
    fn new(auth_key: SecretString, builders: Vec<String>, relay_url: String) -> Self {
        Self {
            http_client: Client::new(),
            signer: auth_key
                .expose_secret()
                .parse()
                .expect("should parse auth key"),
            builders,
            relay_url,
        }
    }

    async fn send_private_transaction(
        &self,
        raw_tx: Bytes,
    ) -> std::result::Result<B256, FlashbotsError> {
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

        self.send_and_parse(body).await
    }

    async fn cancel_private_transaction(
        &self,
        tx_hash: B256,
    ) -> std::result::Result<bool, FlashbotsError> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_cancelPrivateTransaction",
            "params": [
                FlashbotsCancelPrivateTransactionRequest { tx_hash }
            ],
            "id": 1
        });

        self.send_and_parse(body).await
    }

    /// Sends a signed JSON-RPC request and parses the response as a
    /// [`JsonRpcEnvelope`], so a well-formed RPC-level rejection from the
    /// relay - which can arrive on a 200 or a non-2xx status - is classified
    /// via `FlashbotsError::Rpc` instead of being lumped in with genuine
    /// transport failures.
    async fn send_and_parse<T>(&self, body: Value) -> std::result::Result<T, FlashbotsError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response = self.sign_send_request(body).await?;
        let status = response.status();
        let text = response.text().await.map_err(|e| {
            FlashbotsError::Transport(anyhow!("failed to read Flashbots response body: {e:?}"))
        })?;

        let envelope: JsonRpcEnvelope<T> = serde_json::from_str(&text).map_err(|e| {
            FlashbotsError::Transport(anyhow!(
                "failed to parse Flashbots response (status {status}): {e:?}, body: {text}"
            ))
        })?;

        if let Some(error) = envelope.error {
            return Err(FlashbotsError::Rpc {
                code: error.code,
                message: error.message,
            });
        }

        envelope.result.ok_or_else(|| {
            FlashbotsError::Transport(anyhow!(
                "Flashbots response missing both result and error (status {status}): {text}"
            ))
        })
    }

    async fn sign_send_request(
        &self,
        body: Value,
    ) -> std::result::Result<Response, FlashbotsError> {
        let to_sign = format!("0x{:x}", utils::keccak256(body.to_string()));

        let signature = self
            .signer
            .sign_message_sync(to_sign.as_bytes())
            .expect("Signature failed");
        let header_val = HeaderValue::from_str(&format!(
            "{:?}:0x{}",
            self.signer.address(),
            hex::encode(signature.as_bytes())
        ))
        .expect("Header contains invalid characters");

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert("x-flashbots-signature", header_val);

        // Send the request. Deliberately not checking status here: a
        // well-formed JSON-RPC error can arrive on a non-2xx status just as
        // easily as on a 200, and send_and_parse needs the body either way
        // to tell an RPC-level rejection apart from a transport failure.
        self.http_client
            .post(&self.relay_url)
            .headers(headers)
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| {
                FlashbotsError::Transport(anyhow!("failed to send request to Flashbots: {e:?}"))
            })
    }
}

fn deserialize_u64<'de, D>(deserializer: D) -> std::result::Result<U64, D::Error>
where
    D: de::Deserializer<'de>,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::String(s) => {
            if s.as_str() == "0x" {
                U64::ZERO
            } else if s.as_str().starts_with("0x") {
                U64::from_str_radix(&s[2..], 16).map_err(de::Error::custom)?
            } else {
                U64::from_str(s.as_str()).map_err(de::Error::custom)?
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
                Some(U256::ZERO)
            } else if s.as_str().starts_with("0x") {
                Some(U256::from_str_radix(&s[2..], 16).map_err(de::Error::custom)?)
            } else {
                Some(U256::from_str(s.as_str()).map_err(de::Error::custom)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sender::RpcOutcomeClass;

    #[test]
    fn recognized_rpc_error_is_classified_not_sender_unavailable() {
        let error = FlashbotsError::Rpc {
            code: -32000,
            message: "nonce too low".to_string(),
        };
        let sender_error: TxSenderError = error.into();
        assert!(matches!(sender_error, TxSenderError::NonceTooLow));
        assert_eq!(sender_error.classify(), RpcOutcomeClass::Neutral);
    }

    #[test]
    fn unrecognized_rpc_error_falls_back_to_sender_unavailable() {
        let error = FlashbotsError::Rpc {
            code: -32099,
            message: "some new relay-specific rejection".to_string(),
        };
        let sender_error: TxSenderError = error.into();
        assert!(matches!(sender_error, TxSenderError::SenderUnavailable(_)));
        assert_eq!(sender_error.classify(), RpcOutcomeClass::NonTerminal);
    }

    #[test]
    fn transport_failure_is_sender_unavailable() {
        let error = FlashbotsError::Transport(anyhow!("connection reset"));
        let sender_error: TxSenderError = error.into();
        assert!(matches!(sender_error, TxSenderError::SenderUnavailable(_)));
        assert_eq!(sender_error.classify(), RpcOutcomeClass::NonTerminal);
    }

    #[test]
    fn envelope_parses_rpc_error_alongside_missing_result() {
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#;
        let envelope: JsonRpcEnvelope<B256> = serde_json::from_str(body).unwrap();
        assert!(envelope.result.is_none());
        let error = envelope.error.expect("should parse error object");
        assert_eq!(error.code, -32000);
        assert_eq!(error.message, "nonce too low");
    }

    #[test]
    fn envelope_parses_result_alongside_missing_error() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":"0x0000000000000000000000000000000000000000000000000000000000000001"}"#;
        let envelope: JsonRpcEnvelope<B256> = serde_json::from_str(body).unwrap();
        assert!(envelope.error.is_none());
        assert!(envelope.result.is_some());
    }
}
