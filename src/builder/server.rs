use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context};
use ethers::{
    providers::{Http, Middleware, Provider, RetryClient},
    types::{transaction::eip2718::TypedTransaction, Address, H256, U256},
};
use tokio::{join, time};
use tonic::{async_trait, transport::Channel, Request, Response, Status};
use tracing::{
    error,
    log::{debug, info, trace, warn},
};

use crate::{
    builder::bundle_proposer::BundleProposer,
    common::{
        gas::GasFees,
        math,
        protos::{
            builder::{
                builder_server::Builder, BundlingMode, DebugSendBundleNowRequest,
                DebugSendBundleNowResponse, DebugSetBundlingModeRequest,
                DebugSetBundlingModeResponse,
            },
            op_pool::{
                self, op_pool_client::OpPoolClient, RemoveEntitiesRequest, RemoveOpsRequest,
            },
        },
        transaction_sender::{SentTxInfo, TransactionSender},
        types::{Entity, EntryPointLike, ExpectedStorage, UserOperation},
    },
};

// Overhead on gas estimates to account for inaccuracies.
const GAS_ESTIMATE_OVERHEAD_PERCENT: u64 = 10;

#[derive(Debug)]
pub struct Settings {
    pub max_blocks_to_wait_for_mine: u64,
    pub replacement_fee_percent_increase: u64,
    pub max_fee_increases: u64,
}

#[derive(Debug)]
pub struct BuilderImpl<P, E, T>
where
    P: BundleProposer,
    E: EntryPointLike,
    T: TransactionSender,
{
    is_manual_bundling_mode: AtomicBool,
    chain_id: u64,
    beneficiary: Address,
    eth_poll_interval: Duration,
    op_pool: OpPoolClient<Channel>,
    proposer: P,
    entry_point: E,
    transaction_sender: T,
    // TODO: Figure out what we really want to do for detecting new blocks.
    provider: Arc<Provider<RetryClient<Http>>>,
    settings: Settings,
}

#[derive(Debug)]
struct BundleTx {
    tx: TypedTransaction,
    expected_storage: ExpectedStorage,
    op_count: usize,
}

#[derive(Debug)]
enum SendBundleResult {
    Success {
        block_number: u64,
        attempt_number: u64,
        tx_hash: H256,
    },
    NoOperationsInitially,
    NoOperationsAfterFeeIncreases {
        initial_op_count: usize,
        attempt_number: u64,
    },
    StalledAtMaxFeeIncreases,
    Error(anyhow::Error),
}

#[derive(Debug)]
enum MineResult {
    Success {
        block_number: u64,
        attempt_number: u64,
    },
    StillPendingAfterWait,
    Dropped,
    NonceUsedForOtherTx,
    Error(anyhow::Error),
}

impl<P, E, T> BuilderImpl<P, E, T>
where
    P: BundleProposer,
    E: EntryPointLike,
    T: TransactionSender,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u64,
        beneficiary: Address,
        eth_poll_interval: Duration,
        op_pool: OpPoolClient<Channel>,
        proposer: P,
        entry_point: E,
        transaction_sender: T,
        provider: Arc<Provider<RetryClient<Http>>>,
        settings: Settings,
    ) -> Self {
        Self {
            is_manual_bundling_mode: AtomicBool::new(false),
            chain_id,
            beneficiary,
            eth_poll_interval,
            op_pool,
            proposer,
            entry_point,
            transaction_sender,
            provider,
            settings,
        }
    }

    /// Loops forever, attempting to form and send a bundle on each new block,
    /// then waiting for one bundle to be mined or dropped before forming the
    /// next one.
    pub async fn send_bundles_in_loop(&self) -> ! {
        let mut last_block_number = 0;
        loop {
            if self.is_manual_bundling_mode.load(Ordering::Relaxed) {
                time::sleep(self.eth_poll_interval).await;
                continue;
            }
            last_block_number = self.wait_for_new_block_number(last_block_number).await;
            let result = self.send_bundle_with_increasing_gas_fees().await;
            match result {
                SendBundleResult::Success {
                    block_number,
                    attempt_number,
                     tx_hash,
                } =>
                    if attempt_number == 0 {
                        info!("Bundle with hash {tx_hash:?} landed in block {block_number}");
                    } else {
                        info!("Bundle with hash {tx_hash:?} landed in block {block_number} after increasing gas fees {attempt_number} time(s)");
                    }
                SendBundleResult::NoOperationsInitially => trace!("No ops to send at block {last_block_number}"),
                SendBundleResult::NoOperationsAfterFeeIncreases {
                    initial_op_count,
                    attempt_number,
                } => info!("Bundle initially had {initial_op_count} operations, but after increasing gas fees {attempt_number} time(s) it was empty"),
                SendBundleResult::StalledAtMaxFeeIncreases => warn!("Bundle failed to mine after {} fee increases", self.settings.max_fee_increases),
                SendBundleResult::Error(error) => error!("Failed to send bundle. Will retry next block: {error:?}"),
            }
        }
    }

    /// Constructs a bundle and sends it to the entry point as a transaction. If
    /// the bundle fails to be mined after
    /// `settings.max_blocks_to_wait_for_mine` blocks, increases the gas fees by
    /// enough to send a replacement transaction, then constructs a new bundle
    /// using the new, higher gas requirements. Continues to retry with higher
    /// gas costs until one of the following happens:
    ///
    /// 1. The transaction succeeds
    /// 2. The gas fees are high enough that the bundle is empty because there
    ///    are no ops that meet the fee requirements.
    /// 3. The transaction has not succeeded after `settings.max_fee_increases`
    ///    replacements.
    async fn send_bundle_with_increasing_gas_fees(&self) -> SendBundleResult {
        let result = self.send_bundle_with_increasing_gas_fees_inner().await;
        match result {
            Ok(result) => result,
            Err(error) => SendBundleResult::Error(error),
        }
    }

    /// Helper function returning `Result` to be able to use `?`.
    async fn send_bundle_with_increasing_gas_fees_inner(&self) -> anyhow::Result<SendBundleResult> {
        let mut nonce: Option<U256> = None;
        let mut previous_fees: Option<GasFees> = None;
        let mut initial_op_count: Option<usize> = None;
        let mut tx_hashes = Vec::<H256>::new();
        for attempt_number in 0..=self.settings.max_fee_increases {
            let required_fees = previous_fees.map(|fees| {
                fees.increase_by_percent(self.settings.replacement_fee_percent_increase)
            });
            let Some(bundle_tx) = self.get_bundle_tx(required_fees).await? else {
                return Ok(if let Some(initial_op_count) = initial_op_count {
                    SendBundleResult::NoOperationsAfterFeeIncreases { initial_op_count, attempt_number }
                } else {
                    SendBundleResult::NoOperationsInitially
                });
            };
            let BundleTx {
                mut tx,
                expected_storage,
                op_count,
            } = bundle_tx;
            if let Some(nonce) = nonce {
                tx.set_nonce(nonce);
            };
            if initial_op_count.is_none() {
                initial_op_count = Some(op_count)
            };
            let current_fees = GasFees::from(&tx);
            let SentTxInfo {
                nonce: sent_nonce,
                tx_hash,
            } = self
                .transaction_sender
                .send_transaction(tx, &expected_storage)
                .await
                .context("builder should send bundle transaction")?;
            info!(
                "Sent bundle in transaction on attempt {attempt_number} with hash: {}",
                tx_hash
            );
            nonce = Some(sent_nonce);
            previous_fees = Some(current_fees);
            tx_hashes.push(tx_hash);
            let wait_result = self
                .wait_for_mine_or_max_blocks(&tx_hashes, sent_nonce)
                .await;
            match wait_result {
                MineResult::Success {
                    block_number,
                    attempt_number,
                } => {
                    return Ok(SendBundleResult::Success {
                        block_number,
                        attempt_number,
                        tx_hash: tx_hashes[attempt_number as usize],
                    })
                }
                MineResult::StillPendingAfterWait => {
                    info!("Transaction not mined for several blocks")
                }
                MineResult::Dropped => info!("Transaction dropped by provider"),
                MineResult::NonceUsedForOtherTx => warn!("Bundle nonce used by other transaction"),
                MineResult::Error(error) => return Ok(SendBundleResult::Error(error)),
            };
            info!(
                "Bundle transaction failed to mine on attempt {attempt_number} (maxFeePerGas: {}, maxPriorityFeePerGas: {}).",
                current_fees.max_fee_per_gas,
                current_fees.max_priority_fee_per_gas,
            );
        }
        Ok(SendBundleResult::StalledAtMaxFeeIncreases)
    }

    async fn wait_for_new_block_number(&self, prev_block_number: u64) -> u64 {
        loop {
            let block_number = self.provider.get_block_number().await;
            match block_number {
                Ok(n) => {
                    let n = n.as_u64();
                    if n > prev_block_number {
                        return n;
                    }
                }
                Err(error) => {
                    error!(
                        "Failed to load latest block number in builder. Will keep trying: {error}"
                    );
                }
            }
            time::sleep(self.eth_poll_interval).await;
        }
    }

    /// Waits for any of a group of transaction hashes with the same sender and
    /// nonce to mine. Returns once one of the following occurs:
    ///
    /// 1. A transaction with one of the provided hashes mines.
    /// 2. The transaction associated with the most recent hash is dropped.
    /// 3. `MAX_BLOCKS_TO_WAIT_FOR_MINE` blocks pass without any of the
    ///    transations mining.
    /// 4. The sender's nonce increases, invalidating these transactions.
    ///
    /// We need to wait on all the transaction hashes, and not just the latest
    /// one, because it's possible that one of the earlier transactions
    /// successfully mines even after we've submitted later ones.
    async fn wait_for_mine_or_max_blocks(&self, tx_hashes: &[H256], nonce: U256) -> MineResult {
        let result = self
            .wait_for_mine_or_max_blocks_inner(tx_hashes, nonce)
            .await;
        match result {
            Ok(result) => result,
            Err(error) => MineResult::Error(error),
        }
    }

    /// Helper function to allow use of `?` operator.
    async fn wait_for_mine_or_max_blocks_inner(
        &self,
        tx_hashes: &[H256],
        nonce: U256,
    ) -> anyhow::Result<MineResult> {
        if tx_hashes.is_empty() {
            bail!("tx hashes to wait for should not be empty");
        }
        let last_index = tx_hashes.len() - 1;
        let latest_tx_hash = tx_hashes[last_index];
        let mut block_number = self
            .provider
            .get_block_number()
            .await
            .context("should get block number while waiting for transaction to mine")?
            .as_u64();
        let max_block_number = block_number + self.settings.max_blocks_to_wait_for_mine;
        while block_number < max_block_number {
            // Wait for either the latest transaction's status to change or for
            // a new block to show up.
            block_number = tokio::select! {
                maybe_receipt = self.transaction_sender.wait_until_mined(latest_tx_hash) => {
                    let maybe_receipt = maybe_receipt
                        .context("should wait for latest transaction to mine or drop")?;
                    return Ok(match maybe_receipt {
                        Some(receipt) => MineResult::Success {
                            block_number: receipt
                                .block_number
                                .context("receipt should have block number")?
                                .as_u64(),
                            attempt_number: last_index as u64,
                        },
                        None => MineResult::Dropped,
                    });
                },
                new_block_number = self.wait_for_new_block_number(block_number) => new_block_number,
            };
            // A new block has appeared.
            let tx_count = self
                .provider
                .get_transaction_count(self.transaction_sender.address(), None)
                .await?;
            if tx_count > nonce {
                // A new transaction has been mined for this account. Check each
                // of the provided hashes to see which one it is, if any.
                for (attempt_number, &tx_hash) in tx_hashes.iter().enumerate().rev() {
                    let tx = self.provider.get_transaction(tx_hash).await?;
                    if let Some(tx) = tx {
                        if let Some(block_number) = tx.block_number {
                            return Ok(MineResult::Success {
                                block_number: block_number.as_u64(),
                                attempt_number: attempt_number as u64,
                            });
                        }
                    }
                }
                return Ok(MineResult::NonceUsedForOtherTx);
            }
        }
        Ok(MineResult::StillPendingAfterWait)
    }

    /// Builds a bundle and returns some metadata and the transaction to send
    /// it, or `None` if there are no valid operations available.
    async fn get_bundle_tx(
        &self,
        required_fees: Option<GasFees>,
    ) -> anyhow::Result<Option<BundleTx>> {
        let bundle = self
            .proposer
            .make_bundle(required_fees)
            .await
            .context("proposer should create bundle for builder")?;
        let remove_ops_future = async {
            let result = self.remove_ops_from_pool(&bundle.rejected_ops).await;
            if let Err(error) = result {
                error!("Failed to remove rejected ops from pool: {error}");
            }
        };
        let remove_entities_future = async {
            let result = self
                .remove_entities_from_pool(&bundle.rejected_entities)
                .await;
            if let Err(error) = result {
                error!("Failed to remove rejected entities from pool: {error}");
            }
        };
        join!(remove_ops_future, remove_entities_future);
        if bundle.is_empty() {
            if !bundle.rejected_ops.is_empty() || !bundle.rejected_entities.is_empty() {
                info!(
                "Empty bundle with {} rejected ops and {} rejected entities. Removing them from pool.",
                bundle.rejected_ops.len(),
                bundle.rejected_entities.len()
            );
            }
            return Ok(None);
        }
        info!(
            "Selected bundle with {} op(s), with {} rejected op(s) and {} rejected entities",
            bundle.len(),
            bundle.rejected_ops.len(),
            bundle.rejected_entities.len()
        );
        let gas = math::increase_by_percent(bundle.gas_estimate, GAS_ESTIMATE_OVERHEAD_PERCENT);
        let op_count = bundle.len();
        let tx = self.entry_point.get_send_bundle_transaction(
            bundle.ops_per_aggregator,
            self.beneficiary,
            gas,
            bundle.gas_fees,
        );
        Ok(Some(BundleTx {
            tx,
            expected_storage: bundle.expected_storage,
            op_count,
        }))
    }

    async fn remove_ops_from_pool(&self, ops: &[UserOperation]) -> anyhow::Result<()> {
        self.op_pool
            .clone()
            .remove_ops(RemoveOpsRequest {
                entry_point: self.entry_point.address().as_bytes().to_vec(),
                hashes: ops
                    .iter()
                    .map(|op| self.op_hash(op).as_bytes().to_vec())
                    .collect(),
            })
            .await
            .context("builder should remove rejected ops from pool")?;
        Ok(())
    }

    async fn remove_entities_from_pool(&self, entities: &[Entity]) -> anyhow::Result<()> {
        self.op_pool
            .clone()
            .remove_entities(RemoveEntitiesRequest {
                entry_point: self.entry_point.address().as_bytes().to_vec(),
                entities: entities.iter().map(op_pool::Entity::from).collect(),
            })
            .await
            .context("builder should remove rejected entities from pool")?;
        Ok(())
    }

    fn op_hash(&self, op: &UserOperation) -> H256 {
        op.op_hash(self.entry_point.address(), self.chain_id)
    }
}

#[async_trait]
impl<P, E, T> Builder for Arc<BuilderImpl<P, E, T>>
where
    P: BundleProposer,
    E: EntryPointLike,
    T: TransactionSender,
{
    async fn debug_send_bundle_now(
        &self,
        _request: Request<DebugSendBundleNowRequest>,
    ) -> tonic::Result<Response<DebugSendBundleNowResponse>> {
        debug!("Send bundle now called");
        let result = self.send_bundle_with_increasing_gas_fees().await;
        let tx_hash = match result {
            SendBundleResult::Success { tx_hash, .. } => tx_hash,
            SendBundleResult::NoOperationsInitially => {
                return Err(Status::internal("no ops to send"))
            }
            SendBundleResult::NoOperationsAfterFeeIncreases { .. } => {
                return Err(Status::internal(
                    "bundle initially had operations, but after increasing gas fees it was empty",
                ))
            }
            SendBundleResult::StalledAtMaxFeeIncreases => return Err(Status::internal("")),
            SendBundleResult::Error(error) => return Err(Status::internal(error.to_string())),
        };
        Ok(Response::new(DebugSendBundleNowResponse {
            transaction_hash: tx_hash.as_bytes().to_vec(),
        }))
    }

    async fn debug_set_bundling_mode(
        &self,
        request: Request<DebugSetBundlingModeRequest>,
    ) -> tonic::Result<Response<DebugSetBundlingModeResponse>> {
        let mode = BundlingMode::from_i32(request.into_inner().mode).unwrap_or_default();
        let is_manual_bundling = match mode {
            BundlingMode::Unspecified => {
                return Err(Status::invalid_argument("invalid bundling mode"))
            }
            BundlingMode::Manual => true,
            BundlingMode::Auto => false,
        };
        self.is_manual_bundling_mode
            .store(is_manual_bundling, Ordering::Relaxed);
        Ok(Response::new(DebugSetBundlingModeResponse {}))
    }
}

/// This stupid type exists because we need to write out some type that
/// implements `Builder` to set up the health reporter, i.e.
///
/// `health_reporter.set_serving::<BuilderService<ANY_BUILDER_HERE>>().await;`
///
/// It doesn't matter what the type is: the type parameter there is only used to
/// read the service name out of `BuilderService` which doesn't depend on the
/// `Builder` impl. But the only other `Builder` impl we have is `BuilderImpl`,
/// which has multiple type parameters whose concrete types themselves need type
/// parameters and is overall extremely nasty to write out. So we make ourselves
/// a non-instantiatable type that implements `Builder` that we can use instead.
pub enum DummyBuilder {}

#[async_trait]
impl Builder for DummyBuilder {
    async fn debug_send_bundle_now(
        &self,
        _request: Request<DebugSendBundleNowRequest>,
    ) -> tonic::Result<Response<DebugSendBundleNowResponse>> {
        panic!()
    }

    async fn debug_set_bundling_mode(
        &self,
        _request: Request<DebugSetBundlingModeRequest>,
    ) -> tonic::Result<Response<DebugSetBundlingModeResponse>> {
        panic!()
    }
}
