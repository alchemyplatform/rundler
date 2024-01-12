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

mod bloxroute;
mod conditional;
mod flashbots;
mod raw;
use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{bail, Context, Error};
use async_trait::async_trait;
pub(crate) use bloxroute::PolygonBloxrouteTransactionSender;
pub(crate) use conditional::ConditionalTransactionSender;
use enum_dispatch::enum_dispatch;
use ethers::{
    prelude::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, Provider, ProviderError},
    types::{
        transaction::eip2718::TypedTransaction, Address, Bytes, TransactionReceipt, H256, U256,
    },
};
use ethers_signers::Signer;
pub(crate) use flashbots::FlashbotsTransactionSender;
#[cfg(test)]
use mockall::automock;
pub(crate) use raw::RawTransactionSender;
use rundler_sim::ExpectedStorage;
use rundler_types::chain::ChainSpec;
use serde::Serialize;

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

/// Errors from transaction senders
#[derive(Debug, thiserror::Error)]
pub(crate) enum TxSenderError {
    /// Replacement transaction was underpriced
    #[error("replacement transaction underpriced")]
    ReplacementUnderpriced,
    /// All other errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub(crate) type Result<T> = std::result::Result<T, TxSenderError>;

#[async_trait]
#[enum_dispatch(TransactionSenderEnum<_C,_S>)]
#[cfg_attr(test, automock)]
pub(crate) trait TransactionSender: Send + Sync + 'static {
    async fn send_transaction(
        &self,
        tx: TypedTransaction,
        expected_storage: &ExpectedStorage,
    ) -> Result<SentTxInfo>;

    async fn get_transaction_status(&self, tx_hash: H256) -> Result<TxStatus>;

    async fn wait_until_mined(&self, tx_hash: H256) -> Result<Option<TransactionReceipt>>;

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

/// Transaction sender types
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionSenderType {
    /// Raw transaction sender
    Raw,
    /// Conditional transaction sender
    Conditional,
    /// Flashbots transaction sender
    ///
    /// Currently only supported on Eth mainnet
    Flashbots,
    /// Bloxroute transaction sender
    ///
    /// Currently only supported on Polygon mainnet
    PolygonBloxroute,
}

impl FromStr for TransactionSenderType {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "raw" => Ok(TransactionSenderType::Raw),
            "conditional" => Ok(TransactionSenderType::Conditional),
            "flashbots" => Ok(TransactionSenderType::Flashbots),
            "polygon_bloxroute" => Ok(TransactionSenderType::PolygonBloxroute),
            _ => bail!("Invalid sender input. Must be one of either 'raw', 'conditional', 'flashbots' or 'polygon_bloxroute'"),
        }
    }
}

impl TransactionSenderType {
    fn into_snake_case(self) -> String {
        match self {
            TransactionSenderType::Raw => "raw",
            TransactionSenderType::Conditional => "conditional",
            TransactionSenderType::Flashbots => "flashbots",
            TransactionSenderType::PolygonBloxroute => "polygon_bloxroute",
        }
        .to_string()
    }

    pub(crate) fn into_sender<C: JsonRpcClient + 'static, S: Signer + 'static>(
        self,
        chain_spec: &ChainSpec,
        client: Arc<Provider<C>>,
        signer: S,
        eth_poll_interval: Duration,
        bloxroute_header: &Option<String>,
    ) -> std::result::Result<TransactionSenderEnum<C, S>, SenderConstructorErrors> {
        let sender = match self {
            Self::Raw => TransactionSenderEnum::Raw(RawTransactionSender::new(client, signer)),
            Self::Conditional => TransactionSenderEnum::Conditional(
                ConditionalTransactionSender::new(client, signer),
            ),
            Self::Flashbots => {
                if !chain_spec.flashbots_enabled {
                    return Err(SenderConstructorErrors::InvalidChainForSender(
                        chain_spec.id,
                        self.into_snake_case(),
                    ));
                }
                TransactionSenderEnum::Flashbots(FlashbotsTransactionSender::new(client, signer)?)
            }
            Self::PolygonBloxroute => {
                if let Some(header) = bloxroute_header {
                    if !chain_spec.bloxroute_enabled {
                        return Err(SenderConstructorErrors::InvalidChainForSender(
                            chain_spec.id,
                            self.into_snake_case(),
                        ));
                    }

                    TransactionSenderEnum::PolygonBloxroute(PolygonBloxrouteTransactionSender::new(
                        client,
                        signer,
                        eth_poll_interval,
                        header,
                    )?)
                } else {
                    return Err(SenderConstructorErrors::BloxRouteMissingToken);
                }
            }
        };
        Ok(sender)
    }
}

/// Custom errors for the sender constructor
#[derive(Debug, thiserror::Error)]
pub(crate) enum SenderConstructorErrors {
    /// Error fallback
    #[error(transparent)]
    Internal(#[from] TxSenderError),
    /// Invalid Chain ID error for sender
    #[error("Chain ID: {0} cannot be used with the {1} sender")]
    InvalidChainForSender(u64, String),
    /// Bloxroute missing token error
    #[error("Missing token for Bloxroute API")]
    BloxRouteMissingToken,
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

impl From<ProviderError> for TxSenderError {
    fn from(value: ProviderError) -> Self {
        match &value {
            ProviderError::JsonRpcClientError(e) => {
                if let Some(e) = e.as_error_response() {
                    if e.message.contains("replacement transaction underpriced") {
                        return TxSenderError::ReplacementUnderpriced;
                    }
                }
                TxSenderError::Other(value.into())
            }
            _ => TxSenderError::Other(value.into()),
        }
    }
}

impl From<jsonrpsee::core::Error> for TxSenderError {
    fn from(value: jsonrpsee::core::Error) -> Self {
        match &value {
            jsonrpsee::core::Error::Call(e) => {
                if e.message().contains("replacement transaction underpriced") {
                    TxSenderError::ReplacementUnderpriced
                } else {
                    TxSenderError::Other(value.into())
                }
            }
            _ => TxSenderError::Other(value.into()),
        }
    }
}
