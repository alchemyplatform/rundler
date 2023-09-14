use std::{fmt::Display, sync::Arc};

use ethers::types::{transaction::eip2718::TypedTransaction, Address, H256};

use crate::common::{gas::GasFees, simulation::SimulationError, strs, types::ValidTimeRange};

#[derive(Clone, Debug)]
pub struct BuilderEvent {
    pub builder_id: u64,
    pub kind: BuilderEventKind,
}

impl BuilderEvent {
    pub fn new(builder_id: u64, kind: BuilderEventKind) -> Self {
        Self { builder_id, kind }
    }

    pub fn formed_bundle(
        builder_id: u64,
        tx_details: Option<BundleTxDetails>,
        nonce: u64,
        fee_increase_count: u64,
        required_fees: Option<GasFees>,
    ) -> Self {
        Self::new(
            builder_id,
            BuilderEventKind::FormedBundle {
                tx_details,
                nonce,
                fee_increase_count,
                required_fees,
            },
        )
    }

    pub fn transaction_mined(
        builder_id: u64,
        tx_hash: H256,
        nonce: u64,
        block_number: u64,
    ) -> Self {
        Self::new(
            builder_id,
            BuilderEventKind::TransactionMined {
                tx_hash,
                nonce,
                block_number,
            },
        )
    }

    pub fn latest_transaction_dropped(builder_id: u64, nonce: u64) -> Self {
        Self::new(
            builder_id,
            BuilderEventKind::LatestTransactionDropped { nonce },
        )
    }

    pub fn nonce_used_for_other_transaction(builder_id: u64, nonce: u64) -> Self {
        Self::new(
            builder_id,
            BuilderEventKind::NonceUsedForOtherTransaction { nonce },
        )
    }

    pub fn skipped_op(builder_id: u64, op_hash: H256, reason: SkipReason) -> Self {
        Self::new(builder_id, BuilderEventKind::SkippedOp { op_hash, reason })
    }

    pub fn rejected_op(builder_id: u64, op_hash: H256, reason: OpRejectionReason) -> Self {
        Self::new(builder_id, BuilderEventKind::RejectedOp { op_hash, reason })
    }
}

#[derive(Clone, Debug)]
pub enum BuilderEventKind {
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
                                "    Builder id: {:?}",
                                "    Transaction hash: {:?}",
                                "    Nonce: {}",
                                "    Fee increases: {}",
                                "    Required maxFeePerGas: {}",
                                "    Required maxPriorityFeePerGas: {}",
                                "    Op hashes: {}",
                            ),
                            self.builder_id,
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
                            "    Builder id: {:?}",
                            "    Nonce: {}",
                            "    Fee increases: {}",
                            "    Required maxFeePerGas: {}",
                            "    Required maxPriorityFeePerGas: {}",
                        ),
                        self.builder_id,
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
                    "    Builder id: {:?}",
                    "    Transaction hash: {:?}",
                    "    Nonce: {}",
                    "    Block number: {}",
                ),
                self.builder_id, tx_hash, nonce, block_number,
            ),
            BuilderEventKind::LatestTransactionDropped { nonce } => {
                write!(
                    f,
                    "Latest transaction dropped. Higher fees are needed.  Builder id: {:?}    Nonce: {nonce}",
                    self.builder_id
                )
            }
            BuilderEventKind::NonceUsedForOtherTransaction { nonce } => {
                write!(f, "Transaction failed because nonce was used by another transaction outside of this Rundler. Builder id: {:?}    Nonce: {nonce}", self.builder_id)
            }
            BuilderEventKind::SkippedOp { op_hash, reason } => {
                write!(f, "Op skipped in bundle (but remains in pool).  Builder id: {:?}   Op hash: {op_hash:?}    Reason: {reason:?}", self.builder_id)
            }
            BuilderEventKind::RejectedOp { op_hash, reason } => {
                write!(f, "Op rejected from bundle and removed from pool.  Builder id: {:?}   Op hash: {op_hash:?}    Reason: {reason:?}", self.builder_id)
            }
        }
    }
}
