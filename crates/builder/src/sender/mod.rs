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
mod flashbots;
mod raw;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
pub(crate) use bloxroute::PolygonBloxrouteTransactionSender;
use enum_dispatch::enum_dispatch;
use ethers::{
    prelude::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, Provider, ProviderError},
    types::{
        transaction::eip2718::TypedTransaction, Address, Bytes, Eip1559TransactionRequest, H256,
        U256,
    },
};
use ethers_signers::{LocalWallet, Signer};
pub(crate) use flashbots::FlashbotsTransactionSender;
#[cfg(test)]
use mockall::automock;
pub(crate) use raw::RawTransactionSender;
use rundler_sim::ExpectedStorage;
use rundler_types::GasFees;

#[derive(Debug)]
pub(crate) struct SentTxInfo {
    pub(crate) nonce: U256,
    pub(crate) tx_hash: H256,
}

#[derive(Debug)]
pub(crate) struct CancelTxInfo {
    pub(crate) tx_hash: H256,
    // True if the transaction was soft-cancelled. Soft-cancellation is when the RPC endpoint
    // accepts the cancel without an onchain transaction.
    pub(crate) soft_cancelled: bool,
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
    /// Nonce too low
    #[error("nonce too low")]
    NonceTooLow,
    /// Conditional value not met
    #[error("storage slot value condition not met")]
    ConditionNotMet,
    /// Soft cancellation failed
    #[error("soft cancel failed")]
    SoftCancelFailed,
    /// All other errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub(crate) type Result<T> = std::result::Result<T, TxSenderError>;

#[async_trait]
#[enum_dispatch(TransactionSenderEnum<_C,_S,_FS>)]
#[cfg_attr(test, automock)]
pub(crate) trait TransactionSender: Send + Sync + 'static {
    async fn send_transaction(
        &self,
        tx: TypedTransaction,
        expected_storage: &ExpectedStorage,
    ) -> Result<SentTxInfo>;

    async fn cancel_transaction(
        &self,
        tx_hash: H256,
        nonce: U256,
        to: Address,
        gas_fees: GasFees,
    ) -> Result<CancelTxInfo>;

    async fn get_transaction_status(&self, tx_hash: H256) -> Result<TxStatus>;

    fn address(&self) -> Address;
}

#[enum_dispatch]
pub(crate) enum TransactionSenderEnum<C, S, FS>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
    FS: Signer + 'static,
{
    Raw(RawTransactionSender<C, S>),
    Flashbots(FlashbotsTransactionSender<C, S, FS>),
    PolygonBloxroute(PolygonBloxrouteTransactionSender<C, S>),
}

/// Transaction sender types
#[derive(Debug, Clone, strum::EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum TransactionSenderKind {
    /// Raw transaction sender
    Raw,
    /// Flashbots transaction sender
    Flashbots,
    /// Bloxroute transaction sender
    Bloxroute,
}

/// Transaction sender types
#[derive(Debug, Clone)]
pub enum TransactionSenderArgs {
    /// Raw transaction sender
    Raw(RawSenderArgs),
    /// Flashbots transaction sender
    Flashbots(FlashbotsSenderArgs),
    /// Bloxroute transaction sender
    Bloxroute(BloxrouteSenderArgs),
}

/// Raw sender arguments
#[derive(Debug, Clone)]
pub struct RawSenderArgs {
    /// Submit URL
    pub submit_url: String,
    /// Use submit for status
    pub use_submit_for_status: bool,
    /// If the "dropped" status is supported by the status provider
    pub dropped_status_supported: bool,
    /// If the sender should use the conditional endpoint
    pub use_conditional_rpc: bool,
}

/// Bloxroute sender arguments
#[derive(Debug, Clone)]
pub struct BloxrouteSenderArgs {
    /// The auth header to use
    pub header: String,
}

/// Flashbots sender arguments
#[derive(Debug, Clone)]
pub struct FlashbotsSenderArgs {
    /// Builder list
    pub builders: Vec<String>,
    /// Flashbots relay URL
    pub relay_url: String,
    /// Flashbots protect tx status URL (NOTE: must end in "/")
    pub status_url: String,
    /// Auth Key
    pub auth_key: String,
}

impl TransactionSenderArgs {
    pub(crate) fn into_sender<C: JsonRpcClient + 'static, S: Signer + 'static>(
        self,
        rpc_provider: Arc<Provider<C>>,
        submit_provider: Option<Arc<Provider<C>>>,
        signer: S,
    ) -> std::result::Result<TransactionSenderEnum<C, S, LocalWallet>, SenderConstructorErrors>
    {
        let sender = match self {
            Self::Raw(args) => {
                let (provider, submitter) = if let Some(submit_provider) = submit_provider {
                    if args.use_submit_for_status {
                        (Arc::clone(&submit_provider), submit_provider)
                    } else {
                        (rpc_provider, submit_provider)
                    }
                } else {
                    (Arc::clone(&rpc_provider), rpc_provider)
                };

                TransactionSenderEnum::Raw(RawTransactionSender::new(
                    provider,
                    submitter,
                    signer,
                    args.dropped_status_supported,
                    args.use_conditional_rpc,
                ))
            }
            Self::Flashbots(args) => {
                let flashbots_signer = args.auth_key.parse().context("should parse auth key")?;

                TransactionSenderEnum::Flashbots(FlashbotsTransactionSender::new(
                    rpc_provider,
                    signer,
                    flashbots_signer,
                    args.builders,
                    args.relay_url,
                    args.status_url,
                )?)
            }
            Self::Bloxroute(args) => TransactionSenderEnum::PolygonBloxroute(
                PolygonBloxrouteTransactionSender::new(rpc_provider, signer, &args.header)?,
            ),
        };
        Ok(sender)
    }
}

/// Custom errors for the sender constructor
#[derive(Debug, thiserror::Error)]
pub(crate) enum SenderConstructorErrors {
    /// Sender Error
    #[error(transparent)]
    Sender(#[from] TxSenderError),
    /// Fallback
    #[error(transparent)]
    Other(#[from] anyhow::Error),
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

fn create_hard_cancel_tx(
    from: Address,
    to: Address,
    nonce: U256,
    gas_fees: GasFees,
) -> TypedTransaction {
    Eip1559TransactionRequest::new()
        .from(from)
        .to(to)
        .nonce(nonce)
        .gas(U256::from(30_000))
        .max_fee_per_gas(gas_fees.max_fee_per_gas)
        .max_priority_fee_per_gas(gas_fees.max_priority_fee_per_gas)
        .data(Bytes::new())
        .into()
}

impl From<ProviderError> for TxSenderError {
    fn from(value: ProviderError) -> Self {
        match &value {
            ProviderError::JsonRpcClientError(e) => {
                if let Some(e) = e.as_error_response() {
                    if e.message.contains("replacement transaction underpriced") {
                        return TxSenderError::ReplacementUnderpriced;
                    } else if e.message.contains("nonce too low") {
                        return TxSenderError::NonceTooLow;
                    // Arbitrum conditional sender error message
                    // TODO push them to use a specific error code and to return the specific slot that is not met.
                    } else if e
                        .message
                        .to_lowercase()
                        .contains("storage slot value condition not met")
                    {
                        return TxSenderError::ConditionNotMet;
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
