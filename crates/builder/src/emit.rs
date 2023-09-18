use std::{fmt::Display, sync::Arc};

use ethers::types::{transaction::eip2718::TypedTransaction, Address, H256};
use rundler_sim::SimulationError;
use rundler_types::{GasFees, ValidTimeRange};
use rundler_utils::strs;

/// Builder event
#[derive(Clone, Debug)]
pub enum BuilderEvent {
    /// A bundle was formed
    FormedBundle {
        /// Details of the transaction that was sent
        /// If `None`, means that the bundle contained no operations and so no
        /// transaction was created.
        tx_details: Option<BundleTxDetails>,
        /// Nonce of the transaction that was sent
        nonce: u64,
        /// Number of times fees were increased
        fee_increase_count: u64,
        /// Required fees for the transaction that was sent
        required_fees: Option<GasFees>,
    },
    /// A bundle transaction was mined
    TransactionMined {
        /// Transaction hash
        tx_hash: H256,
        /// Transaction nonce
        nonce: u64,
        /// Block number containing the transaction
        block_number: u64,
    },
    /// The latest transaction was dropped
    LatestTransactionDropped {
        /// Nonce of the dropped transaction
        nonce: u64,
    },
    /// A nonce was used by another transaction not tracked by this builder
    NonceUsedForOtherTransaction {
        /// The used nonce
        nonce: u64,
    },
    /// An operation was skipped in the bundle
    SkippedOp {
        /// Operation hash
        op_hash: H256,
        /// Reason for skipping
        reason: SkipReason,
    },
    /// An operation was rejected from the bundle and requested to be removed from the pool
    RejectedOp {
        /// Operation hash
        op_hash: H256,
        /// Reason for rejection
        reason: OpRejectionReason,
    },
}

/// Details of a bundle transaction
#[derive(Clone, Debug)]
pub struct BundleTxDetails {
    /// Transaction hash
    pub tx_hash: H256,
    /// The transaction
    pub tx: TypedTransaction,
    /// Operation hashes included in the bundle
    pub op_hashes: Arc<Vec<H256>>,
}

/// Reason for skipping an operation in a bundle
#[derive(Clone, Debug)]
pub enum SkipReason {
    /// Operation accessed another sender account included earlier in the bundle
    AccessedOtherSender { other_sender: Address },
    /// Current time is outside of the operation's valid time range
    InvalidTimeRange { valid_range: ValidTimeRange },
    /// Operation did not bid high enough gas fees for inclusion in the bundle
    InsufficientFees {
        required_fees: GasFees,
        actual_fees: GasFees,
    },
}

/// Reason for rejecting an operation from a bundle
#[derive(Clone, Debug)]
pub enum OpRejectionReason {
    /// Operation failed its 2nd validation simulation attempt
    FailedRevalidation { error: SimulationError },
    /// Operation reverted during bundle formation simulation with message
    FailedInBundle { message: Arc<String> },
}

impl Display for BuilderEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuilderEvent::FormedBundle {
                tx_details,
                nonce,
                fee_increase_count,
                required_fees,
            } => {
                let required_max_fee_per_gas =
                    strs::to_string_or(required_fees.map(|fees| fees.max_fee_per_gas), "(default)");
                let required_max_priority_fee_per_gas = strs::to_string_or(
                    required_fees.map(|fees| fees.max_priority_fee_per_gas),
                    "(default)",
                );
                match tx_details {
                    Some(tx_details) => {
                        let op_hashes = tx_details
                            .op_hashes
                            .iter()
                            .map(|hash| format!("{hash:?}"))
                            .collect::<Vec<_>>()
                            .join(", ");
                        write!(
                            f,
                            concat!(
                                "Bundle transaction sent!",
                                "    Transaction hash: {:?}",
                                "    Nonce: {}",
                                "    Fee increases: {}",
                                "    Required maxFeePerGas: {}",
                                "    Required maxPriorityFeePerGas: {}",
                                "    Op hashes: {}",
                            ),
                            tx_details.tx_hash,
                            nonce,
                            fee_increase_count,
                            required_max_fee_per_gas,
                            required_max_priority_fee_per_gas,
                            op_hashes,
                        )
                    }
                    None => write!(
                        f,
                        concat!(
                            "Bundle was empty.",
                            "    Nonce: {}",
                            "    Fee increases: {}",
                            "    Required maxFeePerGas: {}",
                            "    Required maxPriorityFeePerGas: {}",
                        ),
                        nonce,
                        fee_increase_count,
                        required_max_fee_per_gas,
                        required_max_priority_fee_per_gas
                    ),
                }
            }
            BuilderEvent::TransactionMined {
                tx_hash,
                nonce,
                block_number,
            } => write!(
                f,
                concat!(
                    "Transaction mined!",
                    "    Transaction hash: {:?}",
                    "    Nonce: {}",
                    "    Block number: {}",
                ),
                tx_hash, nonce, block_number,
            ),
            BuilderEvent::LatestTransactionDropped { nonce } => {
                write!(
                    f,
                    "Latest transaction dropped. Higher fees are needed.    Nonce: {nonce}"
                )
            }
            BuilderEvent::NonceUsedForOtherTransaction { nonce } => {
                write!(f, "Transaction failed because nonce was used by another transaction outside of this Rundler.    Nonce: {nonce}")
            }
            BuilderEvent::SkippedOp { op_hash, reason } => {
                write!(f, "Op skipped in bundle (but remains in pool).    Op hash: {op_hash:?}    Reason: {reason:?}")
            }
            BuilderEvent::RejectedOp { op_hash, reason } => {
                write!(f, "Op rejected from bundle and removed from pool.    Op hash: {op_hash:?}    Reason: {reason:?}")
            }
        }
    }
}
