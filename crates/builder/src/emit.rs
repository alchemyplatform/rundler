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

use std::{fmt::Display, sync::Arc};

use ethers::types::{transaction::eip2718::TypedTransaction, Address, H256, U256};
use rundler_sim::SimulationError;
use rundler_types::{GasFees, ValidTimeRange};
use rundler_utils::strs;

/// Builder event
#[derive(Clone, Debug)]
pub struct BuilderEvent {
    /// Builder index that emitted the event
    pub builder_index: u64,
    /// Event kind
    pub kind: BuilderEventKind,
}

impl BuilderEvent {
    pub(crate) fn new(builder_index: u64, kind: BuilderEventKind) -> Self {
        Self {
            builder_index,
            kind,
        }
    }

    pub(crate) fn formed_bundle(
        builder_index: u64,
        tx_details: Option<BundleTxDetails>,
        nonce: u64,
        fee_increase_count: u64,
        required_fees: Option<GasFees>,
    ) -> Self {
        Self::new(
            builder_index,
            BuilderEventKind::FormedBundle {
                tx_details,
                nonce,
                fee_increase_count,
                required_fees,
            },
        )
    }

    pub(crate) fn transaction_mined(
        builder_index: u64,
        tx_hash: H256,
        nonce: u64,
        block_number: u64,
    ) -> Self {
        Self::new(
            builder_index,
            BuilderEventKind::TransactionMined {
                tx_hash,
                nonce,
                block_number,
            },
        )
    }

    pub(crate) fn latest_transaction_dropped(builder_index: u64, nonce: u64) -> Self {
        Self::new(
            builder_index,
            BuilderEventKind::LatestTransactionDropped { nonce },
        )
    }

    pub(crate) fn nonce_used_for_other_transaction(builder_index: u64, nonce: u64) -> Self {
        Self::new(
            builder_index,
            BuilderEventKind::NonceUsedForOtherTransaction { nonce },
        )
    }

    pub(crate) fn skipped_op(builder_index: u64, op_hash: H256, reason: SkipReason) -> Self {
        Self::new(
            builder_index,
            BuilderEventKind::SkippedOp { op_hash, reason },
        )
    }

    pub(crate) fn rejected_op(
        builder_index: u64,
        op_hash: H256,
        reason: OpRejectionReason,
    ) -> Self {
        Self::new(
            builder_index,
            BuilderEventKind::RejectedOp { op_hash, reason },
        )
    }
}

/// BuilderEventKind
#[derive(Clone, Debug)]
pub enum BuilderEventKind {
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
    /// Insufficient pre-verification gas for the operation at the given base fee
    InsufficientPreVerificationGas {
        base_fee: U256,
        op_fees: GasFees,
        required_pvg: U256,
        actual_pvg: U256,
    },
    /// Bundle ran out of space by gas limit to include the operation
    GasLimit,
    /// Other reason, typically internal errors
    Other { reason: Arc<String> },
}

/// Reason for rejecting an operation from a bundle
#[derive(Clone, Debug)]
pub enum OpRejectionReason {
    /// Operation failed its 2nd validation simulation attempt
    FailedRevalidation { error: SimulationError },
    /// Operation reverted during bundle formation simulation with message
    FailedInBundle { message: Arc<String> },
    /// Operation's storage slot condition was not met
    ConditionNotMet(ConditionNotMetReason),
}

/// Reason for a condition not being met
#[derive(Clone, Debug)]
pub struct ConditionNotMetReason {
    pub address: Address,
    pub slot: H256,
    pub expected: H256,
    pub actual: H256,
}

impl Display for BuilderEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            BuilderEventKind::FormedBundle {
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
                                "    Builder index: {:?}",
                                "    Transaction hash: {:?}",
                                "    Nonce: {}",
                                "    Fee increases: {}",
                                "    Required maxFeePerGas: {}",
                                "    Required maxPriorityFeePerGas: {}",
                                "    Op hashes: {}",
                            ),
                            self.builder_index,
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
                            "    Builder index: {:?}",
                            "    Nonce: {}",
                            "    Fee increases: {}",
                            "    Required maxFeePerGas: {}",
                            "    Required maxPriorityFeePerGas: {}",
                        ),
                        self.builder_index,
                        nonce,
                        fee_increase_count,
                        required_max_fee_per_gas,
                        required_max_priority_fee_per_gas
                    ),
                }
            }
            BuilderEventKind::TransactionMined {
                tx_hash,
                nonce,
                block_number,
            } => write!(
                f,
                concat!(
                    "Transaction mined!",
                    "    Builder index: {:?}",
                    "    Transaction hash: {:?}",
                    "    Nonce: {}",
                    "    Block number: {}",
                ),
                self.builder_index, tx_hash, nonce, block_number,
            ),
            BuilderEventKind::LatestTransactionDropped { nonce } => {
                write!(
                    f,
                    "Latest transaction dropped. Higher fees are needed.   Builder index: {:?}    Nonce: {nonce}",
                    self.builder_index
                )
            }
            BuilderEventKind::NonceUsedForOtherTransaction { nonce } => {
                write!(f, "Transaction failed because nonce was used by another transaction outside of this Rundler.   Builder index: {:?}    Nonce: {nonce}", self.builder_index)
            }
            BuilderEventKind::SkippedOp { op_hash, reason } => {
                write!(f, "Op skipped in bundle (but remains in pool).   Builder index: {:?}    Op hash: {op_hash:?}    Reason: {reason:?}", self.builder_index)
            }
            BuilderEventKind::RejectedOp { op_hash, reason } => {
                write!(f, "Op rejected from bundle and removed from pool.   Builder index: {:?}    Op hash: {op_hash:?}    Reason: {reason:?}", self.builder_index)
            }
        }
    }
}
