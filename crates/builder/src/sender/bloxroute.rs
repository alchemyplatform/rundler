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

use alloy_primitives::{hex, Address, Bytes, B256};
use anyhow::Context;
use jsonrpsee::{
    core::{client::ClientT, traits::ToRpcParams},
    http_client::{transport::HttpBackend, HeaderMap, HeaderValue, HttpClient, HttpClientBuilder},
};
use rundler_provider::{EvmProvider, TransactionRequest};
use rundler_sim::ExpectedStorage;
use rundler_types::GasFees;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tonic::async_trait;

use super::{
    create_hard_cancel_tx, CancelTxInfo, Result, SentTxInfo, TransactionSender, TxSenderError,
    TxStatus,
};
use crate::signer::Signer;

pub(crate) struct PolygonBloxrouteTransactionSender<P, S> {
    provider: P,
    signer: S,
    client: PolygonBloxrouteClient,
}

#[async_trait]
impl<P, S> TransactionSender for PolygonBloxrouteTransactionSender<P, S>
where
    P: EvmProvider,
    S: Signer,
{
    async fn send_transaction(
        &self,
        tx: TransactionRequest,
        _expected_storage: &ExpectedStorage,
    ) -> Result<SentTxInfo> {
        let (raw_tx, nonce) = self.signer.fill_and_sign(tx).await?;
        let tx_hash = self.client.send_transaction(raw_tx).await?;
        Ok(SentTxInfo { nonce, tx_hash })
    }

    async fn cancel_transaction(
        &self,
        _tx_hash: B256,
        nonce: u64,
        to: Address,
        gas_fees: GasFees,
    ) -> Result<CancelTxInfo> {
        // Cannot cancel transactions on polygon bloxroute private, however, the transaction may have been
        // propagated to the public network, and can be cancelled via a public transaction.

        let tx = create_hard_cancel_tx(to, nonce, gas_fees);

        let (raw_tx, _) = self.signer.fill_and_sign(tx).await?;

        let tx_hash = self
            .provider
            .request("eth_sendRawTransaction", (raw_tx,))
            .await?;

        Ok(CancelTxInfo {
            tx_hash,
            soft_cancelled: false,
        })
    }

    async fn get_transaction_status(&self, tx_hash: B256) -> Result<TxStatus> {
        let tx = self
            .provider
            .get_transaction_by_hash(tx_hash)
            .await
            .context("provider should return transaction status")?;
        // BDN transactions will not always show up in the node's transaction pool
        // so we can't rely on this to determine if the transaction was dropped
        // Thus, always return pending.
        Ok(tx
            .and_then(|tx| tx.block_number)
            .map(|block_number| TxStatus::Mined { block_number })
            .unwrap_or(TxStatus::Pending))
    }

    fn address(&self) -> Address {
        self.signer.address()
    }
}

impl<P, S> PolygonBloxrouteTransactionSender<P, S>
where
    P: EvmProvider,
    S: Signer,
{
    pub(crate) fn new(provider: P, signer: S, auth_header: &str) -> Result<Self> {
        Ok(Self {
            provider,
            signer,
            client: PolygonBloxrouteClient::new(auth_header)?,
        })
    }
}

struct PolygonBloxrouteClient {
    client: HttpClient<HttpBackend>,
}

impl PolygonBloxrouteClient {
    fn new(auth_header: &str) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", HeaderValue::from_str(auth_header)?);
        let client = HttpClientBuilder::default()
            .set_headers(headers)
            .build("https://api.blxrbdn.com:443")?;
        Ok(Self { client })
    }

    async fn send_transaction(&self, raw_tx: Bytes) -> Result<B256> {
        let request = BloxrouteRequest {
            transaction: hex::encode(raw_tx),
        };
        let response: BloxrouteResponse =
            self.client.request("polygon_private_tx", request).await?;
        Ok(response.tx_hash)
    }
}

#[derive(Serialize)]

struct BloxrouteRequest {
    transaction: String,
}

impl ToRpcParams for BloxrouteRequest {
    fn to_rpc_params(self) -> std::result::Result<Option<Box<RawValue>>, serde_json::Error> {
        let s = String::from_utf8(serde_json::to_vec(&self)?).expect("Valid UTF8 format");
        RawValue::from_string(s).map(Some)
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BloxrouteResponse {
    tx_hash: B256,
}

impl From<jsonrpsee::core::ClientError> for TxSenderError {
    fn from(value: jsonrpsee::core::ClientError) -> Self {
        if let jsonrpsee::core::ClientError::Call(e) = &value {
            if let Some(e) = super::parse_known_call_execution_failed(e.message(), e.code() as i64)
            {
                return e;
            }
        }

        TxSenderError::Other(value.into())
    }
}
