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

//! Transaction submission error classification.

/// A transaction submission error that Rundler knows how to handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionSubmissionError {
    /// A transaction was underpriced and dropped.
    Underpriced,
    /// A replacement transaction was underpriced.
    ReplacementUnderpriced,
    /// A transaction nonce was already used.
    NonceTooLow,
    /// A conditional transaction's storage condition was not met.
    ConditionNotMet,
    /// A transaction was rejected for a reason that can be solved with a retry.
    Rejected,
    /// The sender account has insufficient funds.
    InsufficientFunds,
}

/// Classifies a transaction submission RPC error that Rundler knows how to handle.
///
/// Client implementations use different error codes for the same condition, so known client
/// messages are matched before codes.
pub fn classify_submission_error(message: &str, code: i64) -> Option<TransactionSubmissionError> {
    // Geth: https://github.com/ethereum/go-ethereum/blob/23800122b37695be50565f8221858a16ce1763db/core/txpool/errors.go#L31
    // Reth: https://github.com/paradigmxyz/reth/blob/8e4a917ec1aa70b3779083454ff2d5ecf6b44168/crates/rpc/rpc-eth-types/src/error/mod.rs#L624
    // Erigon: https://github.com/erigontech/erigon/blob/96fabf3fd1a4ddce26b845ffe2b6cfb50d5b4b2d/txnprovider/txpool/txpoolcfg/txpoolcfg.go#L124

    // DEVELOPER NOTE: ensure to put the most specific matches first.
    let lowercase_message = message.to_lowercase();

    // Geth. Reth and Erigon don't have similar messages.
    if lowercase_message.contains("future transaction tries to replace pending") {
        return Some(TransactionSubmissionError::Rejected);
    }
    // Geth and Reth.
    if lowercase_message.contains("replacement transaction underpriced") {
        return Some(TransactionSubmissionError::ReplacementUnderpriced);
    }
    // Erigon.
    if lowercase_message.contains("could not replace existing tx") {
        return Some(TransactionSubmissionError::ReplacementUnderpriced);
    }
    // Monad.
    if lowercase_message.contains("an existing transaction had higher priority") {
        return Some(TransactionSubmissionError::ReplacementUnderpriced);
    }
    // Geth, Erigon, and Reth.
    if lowercase_message.contains("nonce too low") {
        return Some(TransactionSubmissionError::NonceTooLow);
    }
    // Cronos/Cosmos SDK: "invalid nonce; got 1232, expected 1233: invalid sequence".
    if lowercase_message.contains("invalid nonce; got") {
        return Some(TransactionSubmissionError::NonceTooLow);
    }
    // Geth.
    if lowercase_message.contains("transaction underpriced") {
        return Some(TransactionSubmissionError::Underpriced);
    }
    // Reth.
    if lowercase_message.contains("txpool is full") {
        return Some(TransactionSubmissionError::Underpriced);
    }
    // Erigon.
    if lowercase_message.contains("underpriced") {
        return Some(TransactionSubmissionError::Underpriced);
    }
    // Geth, Erigon, and Reth.
    if lowercase_message.contains("insufficient funds") {
        return Some(TransactionSubmissionError::InsufficientFunds);
    }
    // Arbitrum sequencer.
    if lowercase_message.contains("condition not met") {
        return Some(TransactionSubmissionError::ConditionNotMet);
    }
    // EIP-7796 uses -32003 or -32005 when a condition is not met.
    if code == -32003 || code == -32005 {
        return Some(TransactionSubmissionError::ConditionNotMet);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::TransactionSubmissionError;

    #[test]
    fn classifies_known_submission_errors() {
        let cases = [
            (
                "future transaction tries to replace pending",
                -32000,
                TransactionSubmissionError::Rejected,
            ),
            (
                "replacement transaction underpriced",
                -32000,
                TransactionSubmissionError::ReplacementUnderpriced,
            ),
            (
                "could not replace existing tx",
                -32000,
                TransactionSubmissionError::ReplacementUnderpriced,
            ),
            (
                "an existing transaction had higher priority",
                -32000,
                TransactionSubmissionError::ReplacementUnderpriced,
            ),
            (
                "nonce too low",
                -32000,
                TransactionSubmissionError::NonceTooLow,
            ),
            (
                "invalid nonce; got 1232, expected 1233: invalid sequence",
                -32000,
                TransactionSubmissionError::NonceTooLow,
            ),
            (
                "transaction underpriced",
                -32000,
                TransactionSubmissionError::Underpriced,
            ),
            (
                "txpool is full",
                -32000,
                TransactionSubmissionError::Underpriced,
            ),
            (
                "underpriced",
                -32000,
                TransactionSubmissionError::Underpriced,
            ),
            (
                "insufficient funds for gas * price + value",
                -32000,
                TransactionSubmissionError::InsufficientFunds,
            ),
            (
                "storage slot value condition not met",
                -32000,
                TransactionSubmissionError::ConditionNotMet,
            ),
            (
                "transaction rejected",
                -32003,
                TransactionSubmissionError::ConditionNotMet,
            ),
            (
                "transaction rejected",
                -32005,
                TransactionSubmissionError::ConditionNotMet,
            ),
        ];

        for (message, code, expected) in cases {
            assert_eq!(
                super::classify_submission_error(message, code),
                Some(expected),
                "message: {message}"
            );
        }
    }

    #[test]
    fn classifies_messages_case_insensitively() {
        assert_eq!(
            super::classify_submission_error(
                "Invalid nonce; got 26, expected 27: invalid sequence",
                -32000,
            ),
            Some(TransactionSubmissionError::NonceTooLow)
        );
    }

    #[test]
    fn ignores_unknown_submission_errors() {
        assert_eq!(
            super::classify_submission_error("internal error", -32000),
            None
        );
        assert_eq!(
            super::classify_submission_error("invalid sequence", -32000),
            None
        );
    }
}
