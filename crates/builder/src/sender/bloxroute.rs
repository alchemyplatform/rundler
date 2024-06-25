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

use std::sync::Arc;

use anyhow::Context;
use ethers::{
    middleware::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, Provider},
    types::{transaction::eip2718::TypedTransaction, Address, Bytes, TxHash, H256, U256},
    utils::hex,
};
use ethers_signers::Signer;
use jsonrpsee::{
    core::{client::ClientT, traits::ToRpcParams},
    http_client::{transport::HttpBackend, HeaderMap, HeaderValue, HttpClient, HttpClientBuilder},
};
use rundler_sim::ExpectedStorage;
use rundler_types::GasFees;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tonic::async_trait;

use super::{
    create_hard_cancel_tx, fill_and_sign, CancelTxInfo, Result, SentTxInfo, TransactionSender,
    TxStatus,
};

pub(crate) struct PolygonBloxrouteTransactionSender<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    provider: SignerMiddleware<Arc<Provider<C>>, S>,
    client: PolygonBloxrouteClient,
}

#[async_trait]
impl<C, S> TransactionSender for PolygonBloxrouteTransactionSender<C, S>
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
        let tx_hash = self.client.send_transaction(raw_tx).await?;
        Ok(SentTxInfo { nonce, tx_hash })
    }

    async fn cancel_transaction(
        &self,
        _tx_hash: H256,
        nonce: U256,
        to: Address,
        gas_fees: GasFees,
    ) -> Result<CancelTxInfo> {
        let tx = create_hard_cancel_tx(self.provider.address(), to, nonce, gas_fees);

        let (raw_tx, _) = fill_and_sign(&self.provider, tx).await?;

        let tx_hash = self
            .provider
            .provider()
            .request("eth_sendRawTransaction", (raw_tx,))
            .await?;

        Ok(CancelTxInfo {
            tx_hash,
            soft_cancelled: false,
        })
    }

    async fn get_transaction_status(&self, tx_hash: H256) -> Result<TxStatus> {
        let tx = self
            .provider
            .get_transaction(tx_hash)
            .await
            .context("provider should return transaction status")?;
        // BDN transactions will not always show up in the node's transaction pool
        // so we can't rely on this to determine if the transaction was dropped
        // Thus, always return pending.
        Ok(tx
            .and_then(|tx| tx.block_number)
            .map(|block_number| TxStatus::Mined {
                block_number: block_number.as_u64(),
            })
            .unwrap_or(TxStatus::Pending))
    }

    fn address(&self) -> Address {
        self.provider.address()
    }
}

impl<C, S> PolygonBloxrouteTransactionSender<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    pub(crate) fn new(provider: Arc<Provider<C>>, signer: S, auth_header: &str) -> Result<Self> {
        Ok(Self {
            provider: SignerMiddleware::new(Arc::clone(&provider), signer),
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

    async fn send_transaction(&self, raw_tx: Bytes) -> Result<TxHash> {
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
    fn to_rpc_params(self) -> std::result::Result<Option<Box<RawValue>>, jsonrpsee::core::Error> {
        let s = String::from_utf8(serde_json::to_vec(&self)?).expect("Valid UTF8 format");
        RawValue::from_string(s)
            .map(Some)
            .map_err(jsonrpsee::core::Error::ParseError)
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BloxrouteResponse {
    tx_hash: TxHash,
}
