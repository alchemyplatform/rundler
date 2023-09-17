use std::{fmt::Display, sync::Arc};

use ethers::types::{transaction::eip2718::TypedTransaction, Address, H256};
use rundler_sim::SimulationError;
use rundler_types::{GasFees, ValidTimeRange};

use crate::common::strs;

#[derive(Clone, Debug)]
pub enum BuilderEvent {
    FormedBundle {
        /// If `None`, means that the bundle contained no operations and so no
        /// transaction was created.
        tx_details: Option<BundleTxDetails>,
        nonce: u64,
        fee_increase_count: u64,
        required_fees: Option<GasFees>,
    },
    TransactionMined {
        tx_hash: H256,
        nonce: u64,
        block_number: u64,
    },
    LatestTransactionDropped {
        nonce: u64,
    },
    NonceUsedForOtherTransaction {
        nonce: u64,
    },
    SkippedOp {
        op_hash: H256,
        reason: SkipReason,
    },
    RejectedOp {
        op_hash: H256,
        reason: OpRejectionReason,
    },
}

#[derive(Clone, Debug)]
pub struct BundleTxDetails {
    pub tx_hash: H256,
    pub tx: TypedTransaction,
    pub op_hashes: Arc<Vec<H256>>,
}

#[derive(Clone, Debug)]
pub enum SkipReason {
    AccessedOtherSender {
        other_sender: Address,
    },
    InvalidTimeRange {
        valid_range: ValidTimeRange,
    },
    InsufficientFees {
        required_fees: GasFees,
        actual_fees: GasFees,
    },
}

#[derive(Clone, Debug)]
pub enum OpRejectionReason {
    FailedRevalidation { error: SimulationError },
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
