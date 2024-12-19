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

use alloy_primitives::{Address, B256};
pub(crate) use bloxroute::PolygonBloxrouteTransactionSender;
use enum_dispatch::enum_dispatch;
pub(crate) use flashbots::FlashbotsTransactionSender;
#[cfg(test)]
use mockall::automock;
pub(crate) use raw::RawTransactionSender;
use rundler_provider::{EvmProvider, ProviderError, TransactionRequest};
use rundler_sim::ExpectedStorage;
use rundler_types::GasFees;

use crate::signer::Signer;

#[derive(Debug)]
pub(crate) struct SentTxInfo {
    pub(crate) nonce: u64,
    pub(crate) tx_hash: B256,
}

#[derive(Debug)]
pub(crate) struct CancelTxInfo {
    pub(crate) tx_hash: B256,
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
    /// Transaction was underpriced and dropped
    #[error("transaction underpriced")]
    Underpriced,
    /// Replacement transaction was underpriced
    #[error("replacement transaction underpriced")]
    ReplacementUnderpriced,
    /// Nonce too low
    #[error("nonce too low")]
    NonceTooLow,
    /// Conditional value not met
    #[error("storage slot value condition not met")]
    ConditionNotMet,
    /// Transaction was rejected
    ///
    /// This is a catch-all for when a transaction is rejected for any reason
    /// that can be solved with a retry.
    #[error("transaction rejected")]
    Rejected,
    /// Soft cancellation failed
    #[error("soft cancel failed")]
    SoftCancelFailed,
    /// All other errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub(crate) type Result<T> = std::result::Result<T, TxSenderError>;

#[async_trait::async_trait]
#[enum_dispatch(TransactionSenderEnum<_P,_S>)]
#[cfg_attr(test, automock)]
pub(crate) trait TransactionSender: Send + Sync {
    async fn send_transaction(
        &self,
        tx: TransactionRequest,
        expected_storage: &ExpectedStorage,
    ) -> Result<SentTxInfo>;

    async fn cancel_transaction(
        &self,
        tx_hash: B256,
        nonce: u64,
        to: Address,
        gas_fees: GasFees,
    ) -> Result<CancelTxInfo>;

    async fn get_transaction_status(&self, tx_hash: B256) -> Result<TxStatus>;

    fn address(&self) -> Address;
}

#[enum_dispatch]
pub(crate) enum TransactionSenderEnum<P: EvmProvider, S: Signer> {
    Raw(RawTransactionSender<P, S>),
    Flashbots(FlashbotsTransactionSender<P, S>),
    PolygonBloxroute(PolygonBloxrouteTransactionSender<P, S>),
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
    pub(crate) fn into_sender<S: Signer>(
        self,
        rpc_url: &str,
        signer: S,
        provider_client_timeout_seconds: u64,
    ) -> std::result::Result<TransactionSenderEnum<impl EvmProvider, S>, SenderConstructorErrors>
    {
        let provider =
            rundler_provider::new_alloy_evm_provider(rpc_url, provider_client_timeout_seconds)?;
        let sender = match self {
            Self::Raw(args) => {
                let submitter = rundler_provider::new_alloy_evm_provider(
                    &args.submit_url,
                    provider_client_timeout_seconds,
                )?;

                if args.use_submit_for_status {
                    TransactionSenderEnum::Raw(RawTransactionSender::new(
                        submitter.clone(),
                        submitter,
                        signer,
                        args.dropped_status_supported,
                        args.use_conditional_rpc,
                    ))
                } else {
                    TransactionSenderEnum::Raw(RawTransactionSender::new(
                        submitter,
                        provider,
                        signer,
                        args.dropped_status_supported,
                        args.use_conditional_rpc,
                    ))
                }
            }
            Self::Flashbots(args) => {
                TransactionSenderEnum::Flashbots(FlashbotsTransactionSender::new(
                    provider,
                    signer,
                    args.auth_key,
                    args.builders,
                    args.relay_url,
                    args.status_url,
                )?)
            }
            Self::Bloxroute(args) => TransactionSenderEnum::PolygonBloxroute(
                PolygonBloxrouteTransactionSender::new(provider, signer, &args.header)?,
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

fn create_hard_cancel_tx(to: Address, nonce: u64, gas_fees: GasFees) -> TransactionRequest {
    TransactionRequest::default()
        .to(to)
        .nonce(nonce)
        .gas_limit(30_000)
        .max_fee_per_gas(gas_fees.max_fee_per_gas)
        .max_priority_fee_per_gas(gas_fees.max_priority_fee_per_gas)
}

impl From<ProviderError> for TxSenderError {
    fn from(value: ProviderError) -> Self {
        match &value {
            ProviderError::RPC(e) => {
                if let Some(e) = e.as_error_resp() {
                    // Client impls use different error codes, just match on the message
                    if let Some(e) = parse_known_call_execution_failed(&e.message, e.code) {
                        e
                    } else {
                        TxSenderError::Other(value.into())
                    }
                } else {
                    TxSenderError::Other(value.into())
                }
            }
            _ => TxSenderError::Other(value.into()),
        }
    }
}

// Geth: https://github.com/ethereum/go-ethereum/blob/23800122b37695be50565f8221858a16ce1763db/core/txpool/errors.go#L31
// Reth: https://github.com/paradigmxyz/reth/blob/8e4a917ec1aa70b3779083454ff2d5ecf6b44168/crates/rpc/rpc-eth-types/src/error/mod.rs#L624
// Erigon: https://github.com/erigontech/erigon/blob/96fabf3fd1a4ddce26b845ffe2b6cfb50d5b4b2d/txnprovider/txpool/txpoolcfg/txpoolcfg.go#L124
fn parse_known_call_execution_failed(message: &str, code: i64) -> Option<TxSenderError> {
    // Check error codes before checking the message
    // The error code is -32003 or -32005 when condition is not met: https://eips.ethereum.org/EIPS/eip-7796
    if code == -32003 || code == -32005 {
        return Some(TxSenderError::ConditionNotMet);
    }
    // String match on the error message when an error code is not available
    // DEVELOPER NOTE: ensure to put the most specific matches first
    let lowercase_message = message.to_lowercase();
    // geth. Reth & erigon don't have similar
    if lowercase_message.contains("future transaction tries to replace pending") {
        return Some(TxSenderError::Rejected);
    }
    // geth & reth
    if lowercase_message.contains("replacement transaction underpriced") {
        return Some(TxSenderError::ReplacementUnderpriced);
    }
    // erigon
    if lowercase_message.contains("could not replace existing tx") {
        return Some(TxSenderError::ReplacementUnderpriced);
    }
    // geth, erigon, reth
    if lowercase_message.contains("nonce too low") {
        return Some(TxSenderError::NonceTooLow);
    }
    // geth
    if lowercase_message.contains("transaction underpriced") {
        return Some(TxSenderError::Underpriced);
    }
    // reth
    if lowercase_message.contains("txpool is full") {
        return Some(TxSenderError::Underpriced);
    }
    // erigon
    if lowercase_message.contains("underpriced") {
        return Some(TxSenderError::Underpriced);
    }
    // No known error matched
    None
}
