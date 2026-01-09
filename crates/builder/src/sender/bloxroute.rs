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

use alloy_primitives::{B256, Bytes, hex};
use anyhow::Context;
use jsonrpsee::{
    core::{client::ClientT, traits::ToRpcParams},
    http_client::{HeaderMap, HeaderValue, HttpClient, HttpClientBuilder, transport::HttpBackend},
};
use rundler_provider::{EvmProvider, TransactionRequest};
use rundler_signer::SignerLease;
use rundler_types::{ExpectedStorage, GasFees};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tonic::async_trait;

use super::{CancelTxInfo, Result, TransactionSender, TxSenderError, create_hard_cancel_tx};

pub(crate) struct PolygonBloxrouteTransactionSender<P> {
    provider: P,
    client: PolygonBloxrouteClient,
}

#[async_trait]
impl<P> TransactionSender for PolygonBloxrouteTransactionSender<P>
where
    P: EvmProvider,
{
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
        let tx_hash = self.client.send_transaction(raw_tx).await?;
        Ok(tx_hash)
    }

    async fn cancel_transaction(
        &self,
        _tx_hash: B256,
        nonce: u64,
        gas_fees: GasFees,
        signer: &SignerLease,
    ) -> Result<CancelTxInfo> {
        // Cannot cancel transactions on polygon bloxroute private, however, the transaction may have been
        // propagated to the public network, and can be cancelled via a public transaction.

        let tx = create_hard_cancel_tx(signer.address(), nonce, gas_fees);

        let raw_tx = signer
            .sign_tx_raw(tx)
            .await
            .context("failed to sign transaction")?;

        let tx_hash = self.provider.send_raw_transaction(raw_tx).await?;

        Ok(CancelTxInfo {
            tx_hash,
            soft_cancelled: false,
        })
    }
}

impl<P> PolygonBloxrouteTransactionSender<P>
where
    P: EvmProvider,
{
    pub(crate) fn new(provider: P, auth_header: &SecretString) -> Result<Self> {
        Ok(Self {
            provider,
            client: PolygonBloxrouteClient::new(auth_header)?,
        })
    }
}

struct PolygonBloxrouteClient {
    client: HttpClient<HttpBackend>,
}

impl PolygonBloxrouteClient {
    fn new(auth_header: &SecretString) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(auth_header.expose_secret())?,
        );
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
        if let jsonrpsee::core::ClientError::Call(e) = &value
            && let Some(e) = super::parse_known_call_execution_failed(e.message(), e.code() as i64)
        {
            return e;
        }

        TxSenderError::Other(value.into())
    }
}
