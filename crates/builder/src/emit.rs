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

use alloy_primitives::{Address, B256, U256};
use rundler_provider::{HandleOpRevert, TransactionRequest};
use rundler_sim::SimulationError;
use rundler_types::{GasFees, ValidTimeRange};
use rundler_utils::strs;

/// Builder event
#[derive(Clone, Debug)]
pub struct BuilderEvent {
    /// Builder tag that emitted the event
    pub tag: String,
    /// Event kind
    pub kind: BuilderEventKind,
}

impl BuilderEvent {
    pub(crate) fn new(tag: String, kind: BuilderEventKind) -> Self {
        Self { tag, kind }
    }

    pub(crate) fn formed_bundle(
        tag: String,
        tx_details: Option<BundleTxDetails>,
        nonce: u64,
        fee_increase_count: u64,
        required_fees: Option<GasFees>,
    ) -> Self {
        Self::new(
            tag,
            BuilderEventKind::FormedBundle {
                tx_details,
                nonce,
                fee_increase_count,
                required_fees,
            },
        )
    }

    pub(crate) fn transaction_mined(
        tag: String,
        tx_hash: B256,
        nonce: u64,
        block_number: u64,
    ) -> Self {
        Self::new(
            tag,
            BuilderEventKind::TransactionMined {
                tx_hash,
                nonce,
                block_number,
            },
        )
    }

    pub(crate) fn latest_transaction_dropped(tag: String, nonce: u64) -> Self {
        Self::new(tag, BuilderEventKind::LatestTransactionDropped { nonce })
    }

    pub(crate) fn nonce_used_for_other_transaction(tag: String, nonce: u64) -> Self {
        Self::new(
            tag,
            BuilderEventKind::NonceUsedForOtherTransaction { nonce },
        )
    }

    pub(crate) fn skipped_op(tag: String, op_hash: B256, reason: SkipReason) -> Self {
        Self::new(tag, BuilderEventKind::SkippedOp { op_hash, reason })
    }

    pub(crate) fn rejected_op(tag: String, op_hash: B256, reason: OpRejectionReason) -> Self {
        Self::new(tag, BuilderEventKind::RejectedOp { op_hash, reason })
    }
}

/// BuilderEventKind
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
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
        tx_hash: B256,
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
        op_hash: B256,
        /// Reason for skipping
        reason: SkipReason,
    },
    /// An operation was rejected from the bundle and requested to be removed from the pool
    RejectedOp {
        /// Operation hash
        op_hash: B256,
        /// Reason for rejection
        reason: OpRejectionReason,
    },
}

/// Details of a bundle transaction
#[derive(Clone, Debug)]
pub struct BundleTxDetails {
    /// Transaction hash
    pub tx_hash: B256,
    /// The transaction
    pub tx: TransactionRequest,
    /// Operations included in the bundle
    pub ops: Arc<Vec<(Address, B256)>>,
}

/// Reason for skipping an operation in a bundle
#[derive(Clone, Debug)]
pub enum SkipReason {
    /// Operation accessed another sender account included earlier in the bundle
    AccessedOtherSender { other_sender: Address },
    /// Operation did not bid high enough gas fees for inclusion in the bundle
    InsufficientFees {
        required_fees: GasFees,
        actual_fees: GasFees,
    },
    /// Insufficient pre-verification gas for the operation at the given base fee
    InsufficientPreVerificationGas {
        base_fee: u128,
        op_fees: GasFees,
        required_pvg: u128,
        actual_pvg: u128,
    },
    /// Cost of this operation is greater than the max cost of the bundler sponsorship
    OverSponsorshipMaxCost { max_cost: U256, actual_cost: U256 },
    /// Bundle ran out of space by simulation gas limit to include the operation
    SimulationGasLimit,
    /// Bundle ran out of space by target gas limit to include the operation
    TargetGasLimit,
    /// Bundle ran out of space by max gas limit to include the operation
    MaxGasLimit,
    /// Bundle ran out of space by max bundle fee to include the operation
    OverMaxBundleFee,
    /// Expected storage conflict
    ExpectedStorageConflict(String),
    /// Expected storage limit reached
    ExpectedStorageLimit,
    /// Transaction size limit reached
    TransactionSizeLimit,
    /// UO uses an unsupported aggregator
    UnsupportedAggregator(Address),
    /// Other reason, typically internal errors
    Other { reason: Arc<String> },
}

/// Reason for rejecting an operation from a bundle
#[derive(Clone, Debug)]
pub enum OpRejectionReason {
    /// Operation failed its 2nd validation simulation attempt
    FailedRevalidation { error: SimulationError },
    /// Operation failed its revert check
    FailedRevertCheck { error: HandleOpRevert },
    /// Operation reverted during bundle formation simulation with message
    FailedInBundle { message: Arc<String> },
    /// Operation's storage slot condition was not met
    ConditionNotMet(ConditionNotMetReason),
    /// Current time is outside of the operation's valid time range
    InvalidTimeRange { valid_range: ValidTimeRange },
}

/// Reason for a condition not being met
#[derive(Clone, Debug)]
pub struct ConditionNotMetReason {
    pub address: Address,
    pub slot: B256,
    pub expected: B256,
    pub actual: B256,
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
                            .ops
                            .iter()
                            .map(|(sender, hash)| format!("(sender: {sender:?} hash: {hash:?})"))
                            .collect::<Vec<_>>()
                            .join(", ");
                        write!(
                            f,
                            concat!(
                                "Bundle transaction sent!",
                                "    Builder tag: {}",
                                "    Transaction hash: {:?}",
                                "    Nonce: {}",
                                "    Fee increases: {}",
                                "    Required maxFeePerGas: {}",
                                "    Required maxPriorityFeePerGas: {}",
                                "    Ops: {}",
                            ),
                            self.tag,
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
                            "    Builder tag: {}",
                            "    Nonce: {}",
                            "    Fee increases: {}",
                            "    Required maxFeePerGas: {}",
                            "    Required maxPriorityFeePerGas: {}",
                        ),
                        self.tag,
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
                    "    Builder tag: {}",
                    "    Transaction hash: {:?}",
                    "    Nonce: {}",
                    "    Block number: {}",
                ),
                self.tag, tx_hash, nonce, block_number,
            ),
            BuilderEventKind::LatestTransactionDropped { nonce } => {
                write!(
                    f,
                    "Latest transaction dropped. Higher fees are needed.   Builder tag: {}    Nonce: {nonce}",
                    self.tag
                )
            }
            BuilderEventKind::NonceUsedForOtherTransaction { nonce } => {
                write!(
                    f,
                    "Transaction failed because nonce was used by another transaction outside of this Rundler.   Builder tag: {}    Nonce: {nonce}",
                    self.tag
                )
            }
            BuilderEventKind::SkippedOp { op_hash, reason } => {
                write!(
                    f,
                    "Op skipped in bundle (but remains in pool).   Builder tag: {}    Op hash: {op_hash:?}    Reason: {reason:?}",
                    self.tag
                )
            }
            BuilderEventKind::RejectedOp { op_hash, reason } => {
                write!(
                    f,
                    "Op rejected from bundle and removed from pool.   Builder tag: {}    Op hash: {op_hash:?}    Reason: {reason:?}",
                    self.tag
                )
            }
        }
    }
}
