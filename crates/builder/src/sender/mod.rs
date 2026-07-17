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
mod fallback;
mod flashbots;
mod polygon_private;
mod raw;

#[cfg(test)]
use alloy_json_rpc::{ErrorPayload, RpcError};
use alloy_primitives::{Address, B256};
use anyhow::Context;
pub(crate) use bloxroute::PolygonBloxrouteTransactionSender;
use enum_dispatch::enum_dispatch;
pub(crate) use fallback::FallbackTransactionSender;
pub(crate) use flashbots::FlashbotsTransactionSender;
#[cfg(test)]
use mockall::automock;
pub(crate) use raw::RawTransactionSender;
use rundler_provider::{
    AlloyNetworkConfig, EvmProvider, ProviderError, TransactionRequest,
    transaction::{self, TransactionSubmissionError},
};
use rundler_signer::SignerLease;
use rundler_types::{ExpectedStorage, GasFees};
use secrecy::SecretString;

use crate::sender::polygon_private::PolygonPrivateSender;

#[derive(Debug)]
pub(crate) struct CancelTxInfo {
    pub(crate) tx_hash: B256,
    // True if the transaction was soft-cancelled. Soft-cancellation is when the RPC endpoint
    // accepts the cancel without an onchain transaction.
    pub(crate) soft_cancelled: bool,
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
    /// Insufficient funds for transaction
    #[error("insufficient funds for transaction")]
    InsufficientFunds,
    /// Transaction gas limit is below its intrinsic gas cost
    #[error("intrinsic gas too low")]
    IntrinsicGasTooLow,
    /// The provider rejected the transaction with an error response known to be
    /// terminal for this chain: retrying the identical transaction cannot succeed.
    ///
    /// Currently produced for `-32000: internal error` on chains with
    /// `ChainSpec::internal_rpc_error_is_terminal`.
    #[error("terminal RPC error {code}: {message}")]
    TerminalRpcError {
        /// RPC error code.
        code: i64,
        /// RPC error message.
        message: String,
    },
    /// Sender is unavailable due to an outage or transport error.
    ///
    /// When a fallback sender is configured this triggers failover.
    #[error("sender unavailable: {0}")]
    SenderUnavailable(anyhow::Error),
    /// The provider returned an RPC error response that Rundler does not recognize.
    ///
    /// The node judged the transaction but the meaning is unknown, so acceptance is
    /// ambiguous. When a fallback sender is configured this triggers failover.
    #[error("unrecognized RPC error {code}: {message}")]
    UnrecognizedRpc {
        /// RPC error code.
        code: i64,
        /// RPC error message.
        message: String,
    },
    /// All other errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Classification of a submission failure for poison user operation handling.
///
/// See `docs/designs/poison-user-operations.md`.
#[allow(dead_code)] // consumed once the bundle sender reports outcomes to the pool
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RpcOutcomeClass {
    /// Final rejection; retrying the identical transaction cannot succeed.
    Terminal,
    /// Transport failure, timeout, outage, or ambiguous rejection; acceptance unknown.
    NonTerminal,
    /// Known operational error with dedicated handling; evidence of neither user
    /// operation poison nor provider health.
    Neutral,
}

impl TxSenderError {
    /// Classifies this error for poison user operation handling.
    #[allow(dead_code)] // consumed once the bundle sender reports outcomes to the pool
    pub(crate) fn classify(&self) -> RpcOutcomeClass {
        match self {
            TxSenderError::IntrinsicGasTooLow | TxSenderError::TerminalRpcError { .. } => {
                RpcOutcomeClass::Terminal
            }
            TxSenderError::SenderUnavailable(_) | TxSenderError::UnrecognizedRpc { .. } => {
                RpcOutcomeClass::NonTerminal
            }
            TxSenderError::Underpriced
            | TxSenderError::ReplacementUnderpriced
            | TxSenderError::NonceTooLow
            | TxSenderError::ConditionNotMet
            | TxSenderError::Rejected
            | TxSenderError::SoftCancelFailed
            | TxSenderError::InsufficientFunds
            | TxSenderError::Other(_) => RpcOutcomeClass::Neutral,
        }
    }

    /// On chains where the node emits `-32000: internal error` as a terminal
    /// per-transaction rejection (`ChainSpec::internal_rpc_error_is_terminal`),
    /// promotes that response from ambiguous to terminal.
    pub(crate) fn promote_terminal_internal_error(self) -> Self {
        match self {
            TxSenderError::UnrecognizedRpc { code, message }
                if code == -32000 && message.trim().eq_ignore_ascii_case("internal error") =>
            {
                TxSenderError::TerminalRpcError { code, message }
            }
            other => other,
        }
    }
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
        signer: &SignerLease,
    ) -> Result<B256>;

    async fn cancel_transaction(
        &self,
        tx_hash: B256,
        nonce: u64,
        gas_fees: GasFees,
        signer: &SignerLease,
    ) -> Result<CancelTxInfo>;
}

#[enum_dispatch(TransactionSender)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum TransactionSenderEnum<P: EvmProvider> {
    Raw(RawTransactionSender<P>),
    Flashbots(FlashbotsTransactionSender),
    PolygonBloxroute(PolygonBloxrouteTransactionSender<P>),
    PolygonPrivate(PolygonPrivateSender<P>),
    Fallback(FallbackTransactionSender),
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
    /// Polygon private transaction sender
    PolygonPrivate,
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
    /// Polygon private transaction sender
    PolygonPrivate(PolygonPrivateArgs),
    /// Sender with automatic failover to a fallback sender
    Fallback(FallbackSenderArgs),
}

/// Raw sender arguments
#[derive(Debug, Clone)]
pub struct RawSenderArgs {
    /// Submit URL
    pub submit_url: String,
    /// If the sender should use the conditional endpoint
    pub use_conditional_rpc: bool,
    /// If the chain emits `-32000: internal error` as a terminal rejection
    pub internal_rpc_error_is_terminal: bool,
}

/// Bloxroute sender arguments
#[derive(Debug, Clone)]
pub struct BloxrouteSenderArgs {
    /// The auth header to use
    pub header: SecretString,
}

/// Polygon private sender arguments
#[derive(Debug, Clone)]
pub struct PolygonPrivateArgs {
    /// Submit URL
    pub submit_url: String,
}

/// Flashbots sender arguments
#[derive(Debug, Clone)]
pub struct FlashbotsSenderArgs {
    /// Builder list
    pub builders: Vec<String>,
    /// Flashbots relay URL
    pub relay_url: String,
    /// Auth Key
    pub auth_key: SecretString,
}

/// Fallback sender arguments
#[derive(Debug, Clone)]
pub struct FallbackSenderArgs {
    /// Primary sender
    pub primary: Box<TransactionSenderArgs>,
    /// Fallback sender used when the primary is unavailable
    pub fallback: Box<TransactionSenderArgs>,
    /// How long to wait on the fallback before re-attempting the primary
    pub recovery_interval: std::time::Duration,
    /// Consecutive SenderUnavailable responses required before activating the fallback
    pub failure_threshold: u32,
}

impl TransactionSenderArgs {
    pub(crate) fn into_sender(
        self,
        config: &AlloyNetworkConfig,
    ) -> std::result::Result<TransactionSenderEnum<impl EvmProvider + use<>>, SenderConstructorErrors>
    {
        let provider = rundler_provider::new_alloy_evm_provider(config)?;
        let sender = match self {
            Self::Raw(args) => {
                let config = AlloyNetworkConfig {
                    rpc_url: args
                        .submit_url
                        .parse()
                        .context("invalid builder submit URL")?,
                    ..config.clone()
                };
                let submitter = rundler_provider::new_alloy_evm_provider(&config)?;

                TransactionSenderEnum::Raw(RawTransactionSender::new(
                    submitter,
                    args.use_conditional_rpc,
                    args.internal_rpc_error_is_terminal,
                ))
            }
            Self::Flashbots(args) => TransactionSenderEnum::Flashbots(
                FlashbotsTransactionSender::new(args.auth_key, args.builders, args.relay_url)?,
            ),
            Self::Bloxroute(args) => TransactionSenderEnum::PolygonBloxroute(
                PolygonBloxrouteTransactionSender::new(provider, &args.header)?,
            ),
            Self::PolygonPrivate(args) => {
                let config = AlloyNetworkConfig {
                    rpc_url: args
                        .submit_url
                        .parse()
                        .context("invalid builder submit URL")?,
                    ..config.clone()
                };
                let submitter = rundler_provider::new_alloy_evm_provider(&config)?;

                TransactionSenderEnum::PolygonPrivate(PolygonPrivateSender::new(submitter))
            }
            Self::Fallback(args) => {
                let primary = args.primary.into_sender(config)?;
                let fallback = args.fallback.into_sender(config)?;
                TransactionSenderEnum::Fallback(FallbackTransactionSender::new(
                    Box::new(primary),
                    Box::new(fallback),
                    args.recovery_interval,
                    args.failure_threshold,
                ))
            }
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

/// Builds the `ProviderError` for a JSON-RPC error response, for tests.
#[cfg(test)]
pub(crate) fn rpc_error_response(code: i64, message: &str) -> ProviderError {
    ProviderError::RPC(RpcError::ErrorResp(ErrorPayload {
        code,
        message: message.to_string().into(),
        data: None,
    }))
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
                    if let Some(known) = parse_known_call_execution_failed(&e.message, e.code) {
                        return known;
                    }
                    tracing::warn!(
                        rpc_error_code = e.code,
                        rpc_error_message = %e.message,
                        "Unrecognized RPC error response from provider"
                    );
                    TxSenderError::UnrecognizedRpc {
                        code: e.code,
                        message: e.message.to_string(),
                    }
                } else {
                    tracing::warn!(
                        error = ?value,
                        "Non-error RPC response from provider, treating as sender unavailable"
                    );
                    TxSenderError::SenderUnavailable(anyhow::anyhow!("{value:?}"))
                }
            }
            _ => TxSenderError::Other(value.into()),
        }
    }
}

fn parse_known_call_execution_failed(message: &str, code: i64) -> Option<TxSenderError> {
    transaction::classify_submission_error(message, code).map(TxSenderError::from)
}

impl From<TransactionSubmissionError> for TxSenderError {
    fn from(error: TransactionSubmissionError) -> Self {
        match error {
            TransactionSubmissionError::Underpriced => Self::Underpriced,
            TransactionSubmissionError::ReplacementUnderpriced => Self::ReplacementUnderpriced,
            TransactionSubmissionError::NonceTooLow => Self::NonceTooLow,
            TransactionSubmissionError::ConditionNotMet => Self::ConditionNotMet,
            TransactionSubmissionError::Rejected => Self::Rejected,
            TransactionSubmissionError::InsufficientFunds => Self::InsufficientFunds,
            TransactionSubmissionError::IntrinsicGasTooLow => Self::IntrinsicGasTooLow,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_transport::TransportErrorKind;
    use rundler_provider::ProviderError;

    use super::{RpcOutcomeClass, TxSenderError};

    #[test]
    fn classifies_rpc_outcomes() {
        let cases = [
            (TxSenderError::IntrinsicGasTooLow, RpcOutcomeClass::Terminal),
            (
                TxSenderError::TerminalRpcError {
                    code: -32000,
                    message: "internal error".to_string(),
                },
                RpcOutcomeClass::Terminal,
            ),
            (
                TxSenderError::SenderUnavailable(anyhow::anyhow!("connection refused")),
                RpcOutcomeClass::NonTerminal,
            ),
            (
                TxSenderError::UnrecognizedRpc {
                    code: -32000,
                    message: "internal error".to_string(),
                },
                RpcOutcomeClass::NonTerminal,
            ),
            (TxSenderError::Underpriced, RpcOutcomeClass::Neutral),
            (TxSenderError::NonceTooLow, RpcOutcomeClass::Neutral),
            (
                TxSenderError::Other(anyhow::anyhow!("signing failed")),
                RpcOutcomeClass::Neutral,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.classify(), expected, "error: {error}");
        }
    }

    #[test]
    fn maps_unrecognized_rpc_response_to_unrecognized_rpc() {
        let error = TxSenderError::from(super::rpc_error_response(-32000, "internal error"));

        assert!(matches!(
            error,
            TxSenderError::UnrecognizedRpc { code: -32000, ref message } if message == "internal error"
        ));
    }

    #[test]
    fn maps_transport_failure_to_sender_unavailable() {
        let error = TxSenderError::from(ProviderError::RPC(TransportErrorKind::custom_str(
            "connection refused",
        )));

        assert!(matches!(error, TxSenderError::SenderUnavailable(_)));
    }

    #[test]
    fn promotes_internal_error_to_terminal() {
        let error = TxSenderError::UnrecognizedRpc {
            code: -32000,
            message: " Internal Error ".to_string(),
        }
        .promote_terminal_internal_error();

        assert!(matches!(
            error,
            TxSenderError::TerminalRpcError { code: -32000, .. }
        ));
    }

    #[test]
    fn does_not_promote_other_errors() {
        let cases = [
            TxSenderError::UnrecognizedRpc {
                code: -32603,
                message: "internal error".to_string(),
            },
            TxSenderError::UnrecognizedRpc {
                code: -32000,
                message: "internal error: tx pool full".to_string(),
            },
            TxSenderError::SenderUnavailable(anyhow::anyhow!("internal error")),
        ];

        for error in cases {
            assert!(!matches!(
                error.promote_terminal_internal_error(),
                TxSenderError::TerminalRpcError { .. }
            ));
        }
    }

    #[test]
    fn parses_cronos_invalid_sequence_as_nonce_too_low() {
        let error = super::parse_known_call_execution_failed(
            "invalid nonce; got 1232, expected 1233: invalid sequence: invalid sequence",
            -32000,
        );

        assert!(matches!(error, Some(TxSenderError::NonceTooLow)));
    }

    #[test]
    fn parses_cronos_invalid_sequence_case_insensitively() {
        let error = super::parse_known_call_execution_failed(
            "Invalid nonce; got 26, expected 27: invalid sequence: invalid sequence",
            -32000,
        );

        assert!(matches!(error, Some(TxSenderError::NonceTooLow)));
    }

    #[test]
    fn ignores_invalid_sequence_without_invalid_nonce() {
        let error =
            super::parse_known_call_execution_failed("invalid sequence: invalid sequence", -32000);

        assert!(error.is_none());
    }
}
