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

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Address, B256};
use async_stream::stream;
use async_trait::async_trait;
use futures::future::{self, BoxFuture};
use futures_util::Stream;
use metrics::Histogram;
use metrics_derive::Metrics;
use rundler_task::{
    GracefulShutdown, TaskSpawner,
    server::{HealthCheck, ServerStatus},
};
use rundler_types::{
    EntityUpdate, EntryPointAbiVersion, GasEstimate, GasFees, UserOperation, UserOperationId,
    UserOperationOptionalGas, UserOperationPermissions, UserOperationVariant,
    pool::{
        FeeEstimate, MempoolError, MinedUserOperation, NewHead, PaymasterMetadata, Pool, PoolError,
        PoolOperation, PoolOperationStatus, PoolOperationSummary, PoolResult, Reputation,
        ReputationStatus, StakeStatus, UserOperationReceiptData,
    },
};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{error, info};

use crate::{
    chain::{ChainSubscriber, UpdateType},
    mempool::{Mempool, OperationOrigin},
};

/// Services that the pool server needs per entry point for gas estimation, signature checking,
/// and event lookups. Implemented separately per entry point version.
#[async_trait]
pub(crate) trait PoolEntryPointServices: Send + Sync {
    /// Estimate gas for a user operation
    async fn estimate_gas(
        &self,
        op: UserOperationOptionalGas,
        state_override_json: Option<Vec<u8>>,
    ) -> Result<GasEstimate, PoolError>;

    /// Check whether a user operation has a valid signature
    async fn check_signature(&self, op: UserOperationVariant) -> Result<bool, PoolError>;

    /// Get a mined user operation by its hash
    async fn get_mined_by_hash(&self, hash: B256) -> Result<Option<MinedUserOperation>, PoolError>;

    /// Get a user operation receipt by its hash
    async fn get_receipt(
        &self,
        hash: B256,
        bundle_transaction: Option<B256>,
    ) -> Result<Option<UserOperationReceiptData>, PoolError>;

    /// Get a mined user operation and its receipt from a specific transaction
    async fn get_mined_from_tx(
        &self,
        uo_hash: B256,
        tx_hash: B256,
    ) -> Result<Option<(MinedUserOperation, UserOperationReceiptData)>, PoolError>;
}

/// Fee estimation service for the pool server
#[async_trait]
pub(crate) trait PoolFeeEstimator: Send + Sync {
    /// Get the maximum priority fee per gas required by the bundler
    async fn get_max_priority_fee_per_gas(&self) -> Result<u128, PoolError>;
    /// Get the latest fee estimate
    async fn get_fee_estimate(&self) -> Result<FeeEstimate, PoolError>;
    /// Get the required operation fees for the given bundle fees
    fn get_required_op_fees(&self, bundle_fees: GasFees) -> GasFees;
}

#[derive(Metrics, Clone)]
#[metrics(scope = "op_pool_internal")]
struct LocalPoolMetrics {
    #[metric(describe = "the duration in milliseconds of send call")]
    send_duration: Histogram,
}

/// Local pool server builder
#[derive(Debug)]
pub struct LocalPoolBuilder {
    req_sender: mpsc::UnboundedSender<ServerRequest>,
    req_receiver: mpsc::UnboundedReceiver<ServerRequest>,
    block_sender: broadcast::Sender<NewHead>,
}

impl LocalPoolBuilder {
    /// Create a new local pool server builder
    pub fn new(block_capacity: usize) -> Self {
        let (req_sender, req_receiver) = mpsc::unbounded_channel();
        let (block_sender, _) = broadcast::channel(block_capacity);
        Self {
            req_sender,
            req_receiver,
            block_sender,
        }
    }

    /// Get a handle to the local pool server that can be used to make requests
    pub fn get_handle(&self) -> LocalPoolHandle {
        LocalPoolHandle {
            req_sender: self.req_sender.clone(),
            metric: LocalPoolMetrics::default(),
        }
    }

    /// Run the local pool server, consumes the builder
    pub(crate) fn run(
        self,
        task_spawner: Box<dyn TaskSpawner>,
        mempools: HashMap<Address, Arc<dyn Mempool>>,
        ep_services: HashMap<Address, Arc<dyn PoolEntryPointServices>>,
        fee_estimator: Arc<dyn PoolFeeEstimator>,
        chain_subscriber: ChainSubscriber,
        shutdown: GracefulShutdown,
    ) -> BoxFuture<'static, ()> {
        let runner = LocalPoolServerRunner::new(
            self.req_receiver,
            self.block_sender,
            mempools,
            ep_services,
            fee_estimator,
            chain_subscriber,
            task_spawner,
        );
        Box::pin(runner.run(shutdown))
    }
}

/// Handle to the local pool server
///
/// Used to make requests to the local pool server
#[derive(Debug, Clone)]
pub struct LocalPoolHandle {
    req_sender: mpsc::UnboundedSender<ServerRequest>,
    metric: LocalPoolMetrics,
}

struct LocalPoolServerRunner {
    req_receiver: mpsc::UnboundedReceiver<ServerRequest>,
    block_sender: broadcast::Sender<NewHead>,
    mempools: HashMap<Address, Arc<dyn Mempool>>,
    ep_services: HashMap<Address, Arc<dyn PoolEntryPointServices>>,
    fee_estimator: Arc<dyn PoolFeeEstimator>,
    chain_subscriber: ChainSubscriber,
    task_spawner: Box<dyn TaskSpawner>,
}

impl LocalPoolHandle {
    async fn send(&self, request: ServerRequestKind) -> PoolResult<ServerResponse> {
        let (send, recv) = oneshot::channel();
        let begin_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_millis(0))
            .as_millis();

        self.req_sender
            .send(ServerRequest {
                request,
                response: send,
            })
            .map_err(|_| {
                error!("LocalPoolServer sender closed");
                PoolError::UnexpectedResponse
            })?;
        let response = recv.await.map_err(|_| {
            error!("LocalPoolServer receiver closed");
            PoolError::UnexpectedResponse
        })?;
        let end_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_millis(0))
            .as_millis();
        self.metric
            .send_duration
            .record((end_ms.saturating_sub(begin_ms)) as f64);

        response
    }
}

#[async_trait]
impl Pool for LocalPoolHandle {
    async fn get_supported_entry_points(&self) -> PoolResult<Vec<Address>> {
        let req = ServerRequestKind::GetSupportedEntryPoints;
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetSupportedEntryPoints { entry_points } => Ok(entry_points),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn add_op(
        &self,
        op: UserOperationVariant,
        perms: UserOperationPermissions,
    ) -> PoolResult<B256> {
        let req = ServerRequestKind::AddOp {
            entry_point: op.entry_point(),
            op,
            perms,
            origin: OperationOrigin::Local,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::AddOp { hash } => Ok(hash),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_ops(
        &self,
        entry_point: Address,
        max_ops: u64,
        filter_id: Option<String>,
    ) -> PoolResult<Vec<PoolOperation>> {
        let req = ServerRequestKind::GetOps {
            entry_point,
            max_ops,
            filter_id,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetOps { ops } => Ok(ops),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_ops_summaries(
        &self,
        entry_point: Address,
        max_ops: u64,
        filter_id: Option<String>,
    ) -> PoolResult<Vec<PoolOperationSummary>> {
        let req = ServerRequestKind::GetOpsSummaries {
            entry_point,
            max_ops,
            filter_id,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetOpsSummaries { summaries } => Ok(summaries),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_ops_by_hashes(
        &self,
        entry_point: Address,
        hashes: Vec<B256>,
    ) -> PoolResult<Vec<PoolOperation>> {
        let req = ServerRequestKind::GetOpsByHashes {
            entry_point,
            hashes,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetOpsByHashes { ops } => Ok(ops),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_op_by_hash(&self, hash: B256) -> PoolResult<Option<PoolOperation>> {
        let req = ServerRequestKind::GetOpByHash { hash };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetOpByHash { op } => Ok(op),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_op_by_id(&self, id: UserOperationId) -> PoolResult<Option<PoolOperation>> {
        let req = ServerRequestKind::GetOpById { id };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetOpById { op } => Ok(op),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn remove_ops(&self, entry_point: Address, ops: Vec<B256>) -> PoolResult<()> {
        let req = ServerRequestKind::RemoveOps { entry_point, ops };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::RemoveOps => Ok(()),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn remove_op_by_id(
        &self,
        entry_point: Address,
        id: UserOperationId,
    ) -> PoolResult<Option<B256>> {
        let req = ServerRequestKind::RemoveOpById { entry_point, id };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::RemoveOpById { hash } => Ok(hash),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn update_entities(
        &self,
        entry_point: Address,
        entity_updates: Vec<EntityUpdate>,
    ) -> PoolResult<()> {
        let req = ServerRequestKind::UpdateEntities {
            entry_point,
            entity_updates,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::UpdateEntities => Ok(()),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn debug_clear_state(
        &self,
        clear_mempool: bool,
        clear_paymaster: bool,
        clear_reputation: bool,
    ) -> Result<(), PoolError> {
        let req = ServerRequestKind::DebugClearState {
            clear_mempool,
            clear_reputation,
            clear_paymaster,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugClearState => Ok(()),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn admin_set_tracking(
        &self,
        entry_point: Address,
        paymaster: bool,
        reputation: bool,
    ) -> Result<(), PoolError> {
        let req = ServerRequestKind::AdminSetTracking {
            entry_point,
            paymaster,
            reputation,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::AdminSetTracking => Ok(()),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn debug_dump_mempool(&self, entry_point: Address) -> PoolResult<Vec<PoolOperation>> {
        let req = ServerRequestKind::DebugDumpMempool { entry_point };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugDumpMempool { ops } => Ok(ops),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn debug_set_reputations(
        &self,
        entry_point: Address,
        reputations: Vec<Reputation>,
    ) -> PoolResult<()> {
        let req = ServerRequestKind::DebugSetReputations {
            entry_point,
            reputations,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugSetReputations => Ok(()),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn debug_dump_reputation(&self, entry_point: Address) -> PoolResult<Vec<Reputation>> {
        let req = ServerRequestKind::DebugDumpReputation { entry_point };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugDumpReputation { reputations } => Ok(reputations),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn debug_dump_paymaster_balances(
        &self,
        entry_point: Address,
    ) -> PoolResult<Vec<PaymasterMetadata>> {
        let req = ServerRequestKind::DebugDumpPaymasterBalances { entry_point };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugDumpPaymasterBalances { balances } => Ok(balances),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_stake_status(
        &self,
        entry_point: Address,
        address: Address,
    ) -> PoolResult<StakeStatus> {
        let req = ServerRequestKind::GetStakeStatus {
            entry_point,
            address,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetStakeStatus { status } => Ok(status),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_reputation_status(
        &self,
        entry_point: Address,
        address: Address,
    ) -> PoolResult<ReputationStatus> {
        let req = ServerRequestKind::GetReputationStatus {
            entry_point,
            address,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetReputationStatus { status } => Ok(status),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn subscribe_new_heads(
        &self,
        to_track: Vec<Address>,
    ) -> PoolResult<Pin<Box<dyn Stream<Item = NewHead> + Send>>> {
        let req = ServerRequestKind::SubscribeNewHeads { to_track };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::SubscribeNewHeads { mut new_heads } => Ok(Box::pin(stream! {
                loop {
                    match new_heads.recv().await {
                        Ok(block) => yield block,
                        Err(broadcast::error::RecvError::Lagged(c)) => {
                            error!("new_heads_receiver lagged {c} blocks");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("new_heads_receiver closed, ending subscription");
                            break;
                        }
                    }
                }
            })),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn notify_pending_bundle(
        &self,
        entry_point: Address,
        tx_hash: B256,
        sent_at_block: u64,
        builder_address: Address,
        uo_hashes: Vec<B256>,
    ) -> PoolResult<()> {
        let req = ServerRequestKind::NotifyPendingBundle {
            entry_point,
            tx_hash,
            sent_at_block,
            builder_address,
            uo_hashes,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::NotifyPendingBundle => Ok(()),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_op_status(&self, hash: B256) -> PoolResult<Option<PoolOperationStatus>> {
        let req = ServerRequestKind::GetOpStatus { hash };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetOpStatus { status } => Ok(status),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn estimate_user_operation_gas(
        &self,
        entry_point: Address,
        op: UserOperationOptionalGas,
        state_override_json: Option<Vec<u8>>,
    ) -> PoolResult<GasEstimate> {
        let req = ServerRequestKind::EstimateUserOperationGas {
            entry_point,
            op,
            state_override_json,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::EstimateUserOperationGas { estimate } => Ok(estimate),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_max_priority_fee_per_gas(&self) -> PoolResult<u128> {
        let req = ServerRequestKind::GetMaxPriorityFeePerGas;
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetMaxPriorityFeePerGas { fee } => Ok(fee),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_fee_estimate(&self) -> PoolResult<FeeEstimate> {
        let req = ServerRequestKind::GetFeeEstimate;
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetFeeEstimate(resp) => resp,
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_required_op_fees(&self, bundle_fees: GasFees) -> PoolResult<GasFees> {
        let req = ServerRequestKind::GetRequiredOpFees { bundle_fees };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetRequiredOpFees(resp) => resp,
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn check_signature(
        &self,
        entry_point: Address,
        op: UserOperationVariant,
    ) -> PoolResult<bool> {
        let req = ServerRequestKind::CheckSignature { entry_point, op };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::CheckSignature { valid } => Ok(valid),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_mined_by_hash(&self, hash: B256) -> PoolResult<Option<MinedUserOperation>> {
        let req = ServerRequestKind::GetMinedByHash { hash };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetMinedByHash { mined } => Ok(mined),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_user_operation_receipt(
        &self,
        hash: B256,
        bundle_transaction: Option<B256>,
    ) -> PoolResult<Option<UserOperationReceiptData>> {
        let req = ServerRequestKind::GetUserOperationReceipt {
            hash,
            bundle_transaction,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetUserOperationReceipt { receipt } => Ok(receipt),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_mined_user_operation(
        &self,
        uo_hash: B256,
        tx_hash: B256,
        entry_point: Address,
    ) -> PoolResult<Option<(MinedUserOperation, UserOperationReceiptData)>> {
        let req = ServerRequestKind::GetMinedUserOperation {
            uo_hash,
            tx_hash,
            entry_point,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetMinedUserOperation { result } => Ok(result),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }
}

#[async_trait]
impl HealthCheck for LocalPoolHandle {
    fn name(&self) -> &'static str {
        "LocalPoolServer"
    }

    async fn status(&self) -> ServerStatus {
        match tokio::time::timeout(Duration::from_secs(1), self.get_supported_entry_points()).await
        {
            Ok(Ok(_)) => ServerStatus::Serving,
            Ok(Err(e)) => {
                tracing::error!("Healthcheck: failed to get supported entry points in pool: {e:?}");
                ServerStatus::NotServing
            }
            _ => {
                tracing::error!("Healthcheck: timed out getting supported entry points in pool");
                ServerStatus::NotServing
            }
        }
    }
}

impl LocalPoolServerRunner {
    fn new(
        req_receiver: mpsc::UnboundedReceiver<ServerRequest>,
        block_sender: broadcast::Sender<NewHead>,
        mempools: HashMap<Address, Arc<dyn Mempool>>,
        ep_services: HashMap<Address, Arc<dyn PoolEntryPointServices>>,
        fee_estimator: Arc<dyn PoolFeeEstimator>,
        chain_subscriber: ChainSubscriber,
        task_spawner: Box<dyn TaskSpawner>,
    ) -> Self {
        Self {
            req_receiver,
            block_sender,
            mempools,
            ep_services,
            fee_estimator,
            chain_subscriber,
            task_spawner,
        }
    }

    fn get_ep_services(
        &self,
        entry_point: Address,
    ) -> PoolResult<&Arc<dyn PoolEntryPointServices>> {
        self.ep_services
            .get(&entry_point)
            .ok_or_else(|| PoolError::MempoolError(MempoolError::UnknownEntryPoint(entry_point)))
    }

    fn get_pool(&self, entry_point: Address) -> PoolResult<&Arc<dyn Mempool>> {
        self.mempools
            .get(&entry_point)
            .ok_or_else(|| PoolError::MempoolError(MempoolError::UnknownEntryPoint(entry_point)))
    }

    fn get_ops(
        &self,
        entry_point: Address,
        max_ops: u64,
        filter_id: Option<String>,
    ) -> PoolResult<Vec<PoolOperation>> {
        let mempool = self.get_pool(entry_point)?;
        Ok(mempool
            .best_operations(max_ops as usize, filter_id)?
            .iter()
            .map(|op| (**op).clone())
            .collect())
    }

    fn get_ops_summaries(
        &self,
        entry_point: Address,
        max_ops: u64,
        filter_id: Option<String>,
    ) -> PoolResult<Vec<PoolOperationSummary>> {
        let mempool = self.get_pool(entry_point)?;
        Ok(mempool
            .best_operations(max_ops as usize, filter_id)?
            .iter()
            .map(|op| op.as_ref().into())
            .collect())
    }

    fn get_ops_by_hashes(
        &self,
        entry_point: Address,
        hashes: Vec<B256>,
    ) -> PoolResult<Vec<PoolOperation>> {
        let mempool = self.get_pool(entry_point)?;
        Ok(hashes
            .iter()
            .filter_map(|hash| {
                mempool
                    .get_user_operation_by_hash(*hash)
                    .map(|op| (*op).clone())
            })
            .collect())
    }

    fn get_op_by_hash(&self, hash: B256) -> PoolResult<Option<PoolOperation>> {
        for mempool in self.mempools.values() {
            if let Some(op) = mempool.get_user_operation_by_hash(hash) {
                return Ok(Some((*op).clone()));
            }
        }
        Ok(None)
    }

    fn get_op_by_id(&self, id: &UserOperationId) -> PoolResult<Option<PoolOperation>> {
        for mempool in self.mempools.values() {
            if let Some(op) = mempool.get_op_by_id(id) {
                return Ok(Some((*op).clone()));
            }
        }
        Ok(None)
    }

    fn remove_ops(&self, entry_point: Address, ops: &[B256]) -> PoolResult<()> {
        let mempool = self.get_pool(entry_point)?;
        mempool.remove_operations(ops);
        Ok(())
    }

    fn remove_op_by_id(
        &self,
        entry_point: Address,
        id: &UserOperationId,
    ) -> PoolResult<Option<B256>> {
        let mempool = self.get_pool(entry_point)?;
        mempool.remove_op_by_id(id).map_err(|e| e.into())
    }

    fn update_entities<'a>(
        &self,
        entry_point: Address,
        entity_updates: impl IntoIterator<Item = &'a EntityUpdate>,
    ) -> PoolResult<()> {
        let mempool = self.get_pool(entry_point)?;
        for update in entity_updates {
            mempool.update_entity(*update);
        }
        Ok(())
    }

    fn debug_clear_state(
        &self,
        clear_mempool: bool,
        clear_paymaster: bool,
        clear_reputation: bool,
    ) -> PoolResult<()> {
        for mempool in self.mempools.values() {
            mempool.clear_state(clear_mempool, clear_paymaster, clear_reputation);
        }
        Ok(())
    }

    fn admin_set_tracking(
        &self,
        entry_point: Address,
        paymaster: bool,
        reputation: bool,
    ) -> PoolResult<()> {
        let mempool = self.get_pool(entry_point)?;
        mempool.set_tracking(paymaster, reputation);
        Ok(())
    }

    fn debug_dump_mempool(&self, entry_point: Address) -> PoolResult<Vec<PoolOperation>> {
        let mempool = self.get_pool(entry_point)?;
        let mut ops = mempool
            .all_operations(usize::MAX)
            .iter()
            .map(|op| (**op).clone())
            .collect::<Vec<_>>();
        ops.sort_by(|a, b| a.uo.id().cmp(&b.uo.id()));
        Ok(ops)
    }

    fn debug_set_reputations<'a>(
        &self,
        entry_point: Address,
        reputations: impl IntoIterator<Item = &'a Reputation>,
    ) -> PoolResult<()> {
        let mempool = self.get_pool(entry_point)?;
        for rep in reputations {
            mempool.set_reputation(rep.address, rep.ops_seen, rep.ops_included);
        }
        Ok(())
    }

    fn debug_dump_reputation(&self, entry_point: Address) -> PoolResult<Vec<Reputation>> {
        let mempool = self.get_pool(entry_point)?;
        Ok(mempool.dump_reputation())
    }

    fn debug_dump_paymaster_balances(
        &self,
        entry_point: Address,
    ) -> PoolResult<Vec<PaymasterMetadata>> {
        let mempool = self.get_pool(entry_point)?;
        Ok(mempool.dump_paymaster_balances())
    }

    fn get_reputation_status(
        &self,
        entry_point: Address,
        address: Address,
    ) -> PoolResult<ReputationStatus> {
        let mempool = self.get_pool(entry_point)?;
        Ok(mempool.get_reputation_status(address))
    }

    fn notify_pending_bundle(
        &self,
        entry_point: Address,
        tx_hash: B256,
        sent_at_block: u64,
        builder_address: Address,
        uo_hashes: Vec<B256>,
    ) -> PoolResult<()> {
        let mempool = self.get_pool(entry_point)?;
        mempool.set_pending_bundle(tx_hash, sent_at_block, builder_address, uo_hashes);
        Ok(())
    }

    fn get_op_status(&self, hash: B256) -> PoolResult<Option<PoolOperationStatus>> {
        for mempool in self.mempools.values() {
            if let Some(status) = mempool.get_operation_status(hash) {
                return Ok(Some(status));
            }
        }
        Ok(None)
    }

    fn get_pool_and_spawn<F, Fut>(
        &self,
        entry_point: Address,
        response: oneshot::Sender<Result<ServerResponse, PoolError>>,
        f: F,
    ) where
        F: FnOnce(Arc<dyn Mempool>, oneshot::Sender<Result<ServerResponse, PoolError>>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        match self.get_pool(entry_point) {
            Ok(mempool) => {
                let mempool = Arc::clone(mempool);
                self.task_spawner.spawn(Box::pin(f(mempool, response)));
            }
            Err(e) => {
                if let Err(e) = response.send(Err(e)) {
                    tracing::error!("Failed to send response: {:?}", e);
                }
            }
        }
    }

    async fn run(mut self, shutdown: GracefulShutdown) {
        let mut chain_updates = self.chain_subscriber.subscribe();

        loop {
            tokio::select! {
                _ = shutdown.clone() => {
                    break;
                }
                chain_update = chain_updates.recv() => {
                    if let Ok(chain_update) = chain_update {
                        // Update each mempool before notifying listeners of the chain update
                        // This allows the mempools to update their state before the listeners
                        // pull information from the mempool.
                        // For example, a bundle builder listening for a new block to kick off
                        // its bundle building process will want to be able to query the mempool
                        // and only receive operations that have not yet been mined.
                        let block_sender = self.block_sender.clone();
                        let update_futures : Vec<_> = self.mempools.values().map(|m| {
                            let m = Arc::clone(m);
                            let cu = Arc::clone(&chain_update);
                            async move { m.on_chain_update(&cu).await }
                        }).collect();
                        self.task_spawner.spawn(Box::pin(async move {
                            future::join_all(update_futures).await;

                            if chain_update.update_type == UpdateType::Confirmed {
                                let _ = block_sender.send(NewHead {
                                    block_hash: chain_update.latest_block_hash,
                                    block_number: chain_update.latest_block_number,
                                    address_updates: chain_update.address_updates.clone(),
                                });
                            }
                        }));
                    }
                }
                Some(req) = self.req_receiver.recv() => {
                    let resp = match req.request {
                        // Async methods
                        // Responses are sent in the spawned task
                        ServerRequestKind::AddOp { entry_point, op, perms, origin } => {
                            let fut = |mempool: Arc<dyn Mempool>, response: oneshot::Sender<Result<ServerResponse, PoolError>>| async move {
                                let resp = 'resp: {
                                    match mempool.entry_point_version().abi_version() {
                                        EntryPointAbiVersion::V0_6 => {
                                            if !matches!(&op, UserOperationVariant::V0_6(_)){
                                                 break 'resp Err(anyhow::anyhow!("Invalid user operation version for mempool v0.6 {:?}", op.uo_type()).into());
                                            }
                                        }
                                        EntryPointAbiVersion::V0_7 => {
                                            if !matches!(&op, UserOperationVariant::V0_7(_)){
                                                break 'resp Err(anyhow::anyhow!("Invalid user operation version for mempool v0.7 {:?}", op.uo_type()).into());
                                            }
                                        }
                                    }

                                    match mempool.add_operation(origin, op, perms).await {
                                        Ok(hash) => Ok(ServerResponse::AddOp { hash }),
                                        Err(e) => Err(e.into()),
                                    }
                                };

                                if let Err(e) = response.send(resp) {
                                    tracing::error!("Failed to send response: {:?}", e);
                                }
                            };

                            self.get_pool_and_spawn(entry_point, req.response, fut);
                            continue;
                        },
                        ServerRequestKind::GetStakeStatus { entry_point, address }=> {
                            let fut = |mempool: Arc<dyn Mempool>, response: oneshot::Sender<Result<ServerResponse, PoolError>>| async move {
                                let resp = match mempool.get_stake_status(address).await {
                                    Ok(status) => Ok(ServerResponse::GetStakeStatus { status }),
                                    Err(e) => Err(e.into()),
                                };
                                if let Err(e) = response.send(resp) {
                                    tracing::error!("Failed to send response: {:?}", e);
                                }
                            };
                            self.get_pool_and_spawn(entry_point, req.response, fut);
                            continue;
                        },
                        ServerRequestKind::EstimateUserOperationGas { entry_point, op, state_override_json } => {
                            match self.get_ep_services(entry_point) {
                                Ok(services) => {
                                    let services = Arc::clone(services);
                                    let response = req.response;
                                    self.task_spawner.spawn(Box::pin(async move {
                                        let resp = match services.estimate_gas(op, state_override_json).await {
                                            Ok(estimate) => Ok(ServerResponse::EstimateUserOperationGas { estimate }),
                                            Err(e) => Err(e),
                                        };
                                        if let Err(e) = response.send(resp) {
                                            tracing::error!("Failed to send response: {:?}", e);
                                        }
                                    }));
                                }
                                Err(e) => {
                                    if let Err(e) = req.response.send(Err(e)) {
                                        tracing::error!("Failed to send response: {:?}", e);
                                    }
                                }
                            }
                            continue;
                        },
                        ServerRequestKind::GetMaxPriorityFeePerGas => {
                            let fee_estimator = Arc::clone(&self.fee_estimator);
                            let response = req.response;
                            self.task_spawner.spawn(Box::pin(async move {
                                let resp = match fee_estimator.get_max_priority_fee_per_gas().await {
                                    Ok(fee) => Ok(ServerResponse::GetMaxPriorityFeePerGas { fee }),
                                    Err(e) => Err(e),
                                };
                                if let Err(e) = response.send(resp) {
                                    tracing::error!("Failed to send response: {:?}", e);
                                }
                            }));
                            continue;
                        },
                        ServerRequestKind::GetFeeEstimate => {
                            let fee_estimator = Arc::clone(&self.fee_estimator);
                            let tx = req.response;
                            tokio::spawn(async move {
                                let resp = match fee_estimator.get_fee_estimate().await {
                                    Ok(estimate) => ServerResponse::GetFeeEstimate(Ok(estimate)),
                                    Err(e) => ServerResponse::GetFeeEstimate(Err(e)),
                                };
                                if tx.send(Ok(resp)).is_err() {
                                    tracing::error!("response receiver dropped");
                                }
                            });
                            continue;
                        },
                        ServerRequestKind::GetRequiredOpFees { bundle_fees } => {
                            let fee_estimator = Arc::clone(&self.fee_estimator);
                            let tx = req.response;
                            let resp = ServerResponse::GetRequiredOpFees(Ok(fee_estimator.get_required_op_fees(bundle_fees)));
                            if tx.send(Ok(resp)).is_err() {
                                tracing::error!("response receiver dropped");
                            }
                            continue;
                        },
                        ServerRequestKind::CheckSignature { entry_point, op } => {
                            match self.get_ep_services(entry_point) {
                                Ok(services) => {
                                    let services = Arc::clone(services);
                                    let response = req.response;
                                    self.task_spawner.spawn(Box::pin(async move {
                                        let resp = match services.check_signature(op).await {
                                            Ok(valid) => Ok(ServerResponse::CheckSignature { valid }),
                                            Err(e) => Err(e),
                                        };
                                        if let Err(e) = response.send(resp) {
                                            tracing::error!("Failed to send response: {:?}", e);
                                        }
                                    }));
                                }
                                Err(e) => {
                                    if let Err(e) = req.response.send(Err(e)) {
                                        tracing::error!("Failed to send response: {:?}", e);
                                    }
                                }
                            }
                            continue;
                        },
                        ServerRequestKind::GetMinedByHash { hash } => {
                            // Search all EP services for the mined operation
                            let services: Vec<_> = self.ep_services.values().map(Arc::clone).collect();
                            let response = req.response;
                            self.task_spawner.spawn(Box::pin(async move {
                                let mut result = None;
                                for svc in services {
                                    match svc.get_mined_by_hash(hash).await {
                                        Ok(Some(m)) => { result = Some(m); break; }
                                        Ok(None) => {}
                                        Err(e) => { let _ = response.send(Err(e)); return; }
                                    }
                                }
                                let _ = response.send(Ok(ServerResponse::GetMinedByHash { mined: result }));
                            }));
                            continue;
                        },
                        ServerRequestKind::GetUserOperationReceipt { hash, bundle_transaction } => {
                            let services: Vec<_> = self.ep_services.values().map(Arc::clone).collect();
                            let response = req.response;
                            self.task_spawner.spawn(Box::pin(async move {
                                let mut result = None;
                                for svc in services {
                                    match svc.get_receipt(hash, bundle_transaction).await {
                                        Ok(Some(r)) => { result = Some(r); break; }
                                        Ok(None) => {}
                                        Err(e) => { let _ = response.send(Err(e)); return; }
                                    }
                                }
                                let _ = response.send(Ok(ServerResponse::GetUserOperationReceipt { receipt: result }));
                            }));
                            continue;
                        },
                        ServerRequestKind::GetMinedUserOperation { uo_hash, tx_hash, entry_point } => {
                            match self.get_ep_services(entry_point) {
                                Ok(services) => {
                                    let services = Arc::clone(services);
                                    let response = req.response;
                                    self.task_spawner.spawn(Box::pin(async move {
                                        let resp = match services.get_mined_from_tx(uo_hash, tx_hash).await {
                                            Ok(r) => Ok(ServerResponse::GetMinedUserOperation { result: r }),
                                            Err(e) => Err(e),
                                        };
                                        if let Err(e) = response.send(resp) {
                                            tracing::error!("Failed to send response: {:?}", e);
                                        }
                                    }));
                                }
                                Err(e) => {
                                    if let Err(e) = req.response.send(Err(e)) {
                                        tracing::error!("Failed to send response: {:?}", e);
                                    }
                                }
                            }
                            continue;
                        },

                        // Sync methods
                        // Responses are sent in the main loop below
                        ServerRequestKind::GetSupportedEntryPoints => {
                            Ok(ServerResponse::GetSupportedEntryPoints {
                                entry_points: self.mempools.keys().copied().collect()
                            })
                        },
                        ServerRequestKind::GetOps { entry_point, max_ops, filter_id } => {
                            match self.get_ops(entry_point, max_ops, filter_id) {
                                Ok(ops) => Ok(ServerResponse::GetOps { ops }),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::GetOpsSummaries { entry_point, max_ops, filter_id } => {
                            match self.get_ops_summaries(entry_point, max_ops, filter_id) {
                                Ok(summaries) => Ok(ServerResponse::GetOpsSummaries { summaries }),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::GetOpsByHashes { entry_point, hashes } => {
                            match self.get_ops_by_hashes(entry_point, hashes) {
                                Ok(ops) => Ok(ServerResponse::GetOpsByHashes { ops }),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::GetOpByHash { hash } => {
                            match self.get_op_by_hash(hash) {
                                Ok(op) => Ok(ServerResponse::GetOpByHash { op }),
                                Err(e) => Err(e),
                            }
                        }
                        ServerRequestKind::GetOpById { id } => {
                            match self.get_op_by_id(&id) {
                                Ok(op) => Ok(ServerResponse::GetOpById { op }),
                                Err(e) => Err(e),
                            }
                        }
                        ServerRequestKind::RemoveOps { entry_point, ops } => {
                            match self.remove_ops(entry_point, &ops) {
                                Ok(_) => Ok(ServerResponse::RemoveOps),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::RemoveOpById { entry_point, id } => {
                            match self.remove_op_by_id(entry_point, &id) {
                                Ok(hash) => Ok(ServerResponse::RemoveOpById{ hash }),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::AdminSetTracking{ entry_point, paymaster, reputation } => {
                            match self.admin_set_tracking(entry_point, paymaster, reputation) {
                                Ok(_) => Ok(ServerResponse::AdminSetTracking),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::UpdateEntities { entry_point, entity_updates } => {
                            match self.update_entities(entry_point, &entity_updates) {
                                Ok(_) => Ok(ServerResponse::UpdateEntities),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::DebugClearState { clear_mempool, clear_paymaster, clear_reputation } => {
                            match self.debug_clear_state(clear_mempool, clear_paymaster, clear_reputation) {
                                Ok(_) => Ok(ServerResponse::DebugClearState),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::DebugDumpMempool { entry_point } => {
                            match self.debug_dump_mempool(entry_point) {
                                Ok(ops) => Ok(ServerResponse::DebugDumpMempool { ops }),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::DebugSetReputations { entry_point, reputations } => {
                            match self.debug_set_reputations(entry_point, &reputations) {
                                Ok(_) => Ok(ServerResponse::DebugSetReputations),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::DebugDumpReputation { entry_point } => {
                            match self.debug_dump_reputation(entry_point) {
                                Ok(reputations) => Ok(ServerResponse::DebugDumpReputation { reputations }),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::DebugDumpPaymasterBalances { entry_point } => {
                            match self.debug_dump_paymaster_balances(entry_point) {
                                Ok(balances) => Ok(ServerResponse::DebugDumpPaymasterBalances { balances }),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::GetReputationStatus{ entry_point, address } => {
                            match self.get_reputation_status(entry_point, address) {
                                Ok(status) => Ok(ServerResponse::GetReputationStatus { status }),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::SubscribeNewHeads { to_track } => {
                            self.chain_subscriber.track_addresses(to_track);
                            Ok(ServerResponse::SubscribeNewHeads { new_heads: self.block_sender.subscribe() } )
                        },
                        ServerRequestKind::NotifyPendingBundle { entry_point, tx_hash, sent_at_block, builder_address, uo_hashes } => {
                            match self.notify_pending_bundle(entry_point, tx_hash, sent_at_block, builder_address, uo_hashes) {
                                Ok(_) => Ok(ServerResponse::NotifyPendingBundle),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::GetOpStatus { hash } => {
                            match self.get_op_status(hash) {
                                Ok(status) => Ok(ServerResponse::GetOpStatus { status }),
                                Err(e) => Err(e),
                            }
                        }
                    };
                    if let Err(e) = req.response.send(resp) {
                        tracing::error!("Failed to send response: {:?}", e);
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
struct ServerRequest {
    request: ServerRequestKind,
    response: oneshot::Sender<PoolResult<ServerResponse>>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ServerRequestKind {
    GetSupportedEntryPoints,
    AddOp {
        entry_point: Address,
        op: UserOperationVariant,
        perms: UserOperationPermissions,
        origin: OperationOrigin,
    },
    GetOps {
        entry_point: Address,
        max_ops: u64,
        filter_id: Option<String>,
    },
    GetOpsSummaries {
        entry_point: Address,
        max_ops: u64,
        filter_id: Option<String>,
    },
    GetOpsByHashes {
        entry_point: Address,
        hashes: Vec<B256>,
    },
    GetOpByHash {
        hash: B256,
    },
    GetOpById {
        id: UserOperationId,
    },
    RemoveOps {
        entry_point: Address,
        ops: Vec<B256>,
    },
    RemoveOpById {
        entry_point: Address,
        id: UserOperationId,
    },
    UpdateEntities {
        entry_point: Address,
        entity_updates: Vec<EntityUpdate>,
    },
    DebugClearState {
        clear_mempool: bool,
        clear_reputation: bool,
        clear_paymaster: bool,
    },
    AdminSetTracking {
        entry_point: Address,
        paymaster: bool,
        reputation: bool,
    },
    DebugDumpMempool {
        entry_point: Address,
    },
    DebugSetReputations {
        entry_point: Address,
        reputations: Vec<Reputation>,
    },
    DebugDumpReputation {
        entry_point: Address,
    },
    DebugDumpPaymasterBalances {
        entry_point: Address,
    },
    GetReputationStatus {
        entry_point: Address,
        address: Address,
    },
    GetStakeStatus {
        entry_point: Address,
        address: Address,
    },
    SubscribeNewHeads {
        to_track: Vec<Address>,
    },
    NotifyPendingBundle {
        entry_point: Address,
        tx_hash: B256,
        sent_at_block: u64,
        builder_address: Address,
        uo_hashes: Vec<B256>,
    },
    GetOpStatus {
        hash: B256,
    },
    EstimateUserOperationGas {
        entry_point: Address,
        op: UserOperationOptionalGas,
        state_override_json: Option<Vec<u8>>,
    },
    GetMaxPriorityFeePerGas,
    GetFeeEstimate,
    GetRequiredOpFees {
        bundle_fees: GasFees,
    },
    CheckSignature {
        entry_point: Address,
        op: UserOperationVariant,
    },
    GetMinedByHash {
        hash: B256,
    },
    GetUserOperationReceipt {
        hash: B256,
        bundle_transaction: Option<B256>,
    },
    GetMinedUserOperation {
        uo_hash: B256,
        tx_hash: B256,
        entry_point: Address,
    },
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ServerResponse {
    GetSupportedEntryPoints {
        entry_points: Vec<Address>,
    },
    AddOp {
        hash: B256,
    },
    GetOps {
        ops: Vec<PoolOperation>,
    },
    GetOpsSummaries {
        summaries: Vec<PoolOperationSummary>,
    },
    GetOpsByHashes {
        ops: Vec<PoolOperation>,
    },
    GetOpByHash {
        op: Option<PoolOperation>,
    },
    GetOpById {
        op: Option<PoolOperation>,
    },
    RemoveOps,
    RemoveOpById {
        hash: Option<B256>,
    },
    UpdateEntities,
    DebugClearState,
    AdminSetTracking,
    DebugDumpMempool {
        ops: Vec<PoolOperation>,
    },
    DebugSetReputations,
    DebugDumpReputation {
        reputations: Vec<Reputation>,
    },
    DebugDumpPaymasterBalances {
        balances: Vec<PaymasterMetadata>,
    },
    GetReputationStatus {
        status: ReputationStatus,
    },
    GetStakeStatus {
        status: StakeStatus,
    },
    SubscribeNewHeads {
        new_heads: broadcast::Receiver<NewHead>,
    },
    NotifyPendingBundle,
    GetOpStatus {
        status: Option<PoolOperationStatus>,
    },
    EstimateUserOperationGas {
        estimate: GasEstimate,
    },
    GetMaxPriorityFeePerGas {
        fee: u128,
    },
    GetFeeEstimate(Result<FeeEstimate, PoolError>),
    GetRequiredOpFees(Result<GasFees, PoolError>),
    CheckSignature {
        valid: bool,
    },
    GetMinedByHash {
        mined: Option<MinedUserOperation>,
    },
    GetUserOperationReceipt {
        receipt: Option<UserOperationReceiptData>,
    },
    GetMinedUserOperation {
        result: Option<(MinedUserOperation, UserOperationReceiptData)>,
    },
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, iter::zip, sync::Arc};

    use futures_util::StreamExt;
    use parking_lot::RwLock;
    use reth_tasks::TaskManager;
    use rundler_types::{
        EntryPointVersion, chain::ChainSpec, v0_6::UserOperation as UserOperationV0_6,
        v0_7::UserOperation as UserOperationV0_7,
    };

    use super::*;
    use crate::{chain::ChainUpdate, mempool::MockMempool};

    #[tokio::test]
    async fn test_add_op() {
        let mut mock_pool = MockMempool::new();
        let hash0 = B256::random();
        mock_pool
            .expect_entry_point_version()
            .returning(|| EntryPointVersion::V0_6);
        mock_pool
            .expect_add_operation()
            .returning(move |_, _, _| Ok(hash0));

        let ep = ChainSpec::default().entry_point_address_v0_6;
        let pool: Arc<dyn Mempool> = Arc::new(mock_pool);
        let state = setup(HashMap::from([(ep, pool)]));

        let hash1 = state
            .handle
            .add_op(mock_op(), UserOperationPermissions::default())
            .await
            .unwrap();
        assert_eq!(hash0, hash1);
    }

    #[tokio::test]
    async fn test_chain_update() {
        let mut mock_pool = MockMempool::new();
        mock_pool.expect_on_chain_update().returning(|_| ());

        let ep = Address::random();
        let pool: Arc<dyn Mempool> = Arc::new(mock_pool);
        let state = setup(HashMap::from([(ep, pool)]));

        let mut sub = state.handle.subscribe_new_heads(vec![]).await.unwrap();

        let hash = B256::random();
        let number = 1234;
        state
            .chain_update_tx
            .send(Arc::new(ChainUpdate {
                latest_block_hash: hash,
                latest_block_number: number,
                ..Default::default()
            }))
            .unwrap();

        let new_block = sub.next().await.unwrap();
        assert_eq!(hash, new_block.block_hash);
        assert_eq!(number, new_block.block_number);
    }

    #[tokio::test]
    async fn test_get_supported_entry_points() {
        let mut eps0 = vec![Address::random(), Address::random(), Address::random()];

        let state = setup(
            eps0.iter()
                .map(|ep| {
                    let pool: Arc<dyn Mempool> = Arc::new(MockMempool::new());
                    (*ep, pool)
                })
                .collect(),
        );

        let mut eps1 = state.handle.get_supported_entry_points().await.unwrap();

        eps0.sort();
        eps1.sort();
        assert_eq!(eps0, eps1);
    }

    #[tokio::test]
    async fn test_multiple_entry_points() {
        let cs = ChainSpec::default();
        let eps = [cs.entry_point_address_v0_6, cs.entry_point_address_v0_7];
        let mut pools = [MockMempool::new(), MockMempool::new()];
        let h0 = B256::random();
        let h1 = B256::random();
        pools[0]
            .expect_entry_point_version()
            .returning(|| EntryPointVersion::V0_6);
        pools[0]
            .expect_add_operation()
            .returning(move |_, _, _| Ok(h0));
        pools[1]
            .expect_entry_point_version()
            .returning(|| EntryPointVersion::V0_7);
        pools[1]
            .expect_add_operation()
            .returning(move |_, _, _| Ok(h1));

        let state = setup(
            zip(eps.iter(), pools.into_iter())
                .map(|(ep, pool)| {
                    let pool: Arc<dyn Mempool> = Arc::new(pool);
                    (*ep, pool)
                })
                .collect(),
        );

        assert_eq!(
            h0,
            state
                .handle
                .add_op(mock_op(), UserOperationPermissions::default())
                .await
                .unwrap()
        );
        assert_eq!(
            h1,
            state
                .handle
                .add_op(mock_op_v0_7(), UserOperationPermissions::default())
                .await
                .unwrap()
        );
    }

    struct NoopFeeEstimator;

    #[async_trait]
    impl PoolFeeEstimator for NoopFeeEstimator {
        async fn get_max_priority_fee_per_gas(&self) -> Result<u128, PoolError> {
            Ok(0)
        }
        async fn get_fee_estimate(&self) -> Result<FeeEstimate, PoolError> {
            Ok(FeeEstimate {
                block_number: 0,
                base_fee: 0,
                required_base_fee: 0,
                required_priority_fee: 0,
            })
        }
        fn get_required_op_fees(&self, _bundle_fees: GasFees) -> GasFees {
            GasFees::default()
        }
    }

    struct State {
        handle: LocalPoolHandle,
        chain_update_tx: Arc<broadcast::Sender<Arc<ChainUpdate>>>,
        _task_manager: TaskManager,
    }

    fn setup(pools: HashMap<Address, Arc<dyn Mempool>>) -> State {
        let builder = LocalPoolBuilder::new(10);
        let handle = builder.get_handle();
        let (tx, _) = broadcast::channel(10);
        let tx = Arc::new(tx);
        let tm = TaskManager::current();
        let ts = tm.executor();
        let ts_box = Box::new(ts.clone());
        let chain_subscriber = ChainSubscriber {
            sender: tx.clone(),
            to_track: Arc::new(RwLock::new(HashSet::new())),
        };

        // Create empty ep_services and a no-op fee estimator for tests
        let ep_services: HashMap<Address, Arc<dyn PoolEntryPointServices>> = HashMap::new();
        let fee_estimator: Arc<dyn PoolFeeEstimator> = Arc::new(NoopFeeEstimator);

        ts.spawn_critical_with_graceful_shutdown_signal("test pool", |shutdown| {
            builder.run(
                ts_box,
                pools,
                ep_services,
                fee_estimator,
                chain_subscriber,
                shutdown,
            )
        });

        State {
            handle,
            chain_update_tx: tx,
            _task_manager: tm,
        }
    }

    fn mock_op() -> UserOperationVariant {
        UserOperationVariant::V0_6(UserOperationV0_6::default())
    }

    fn mock_op_v0_7() -> UserOperationVariant {
        UserOperationVariant::V0_7(UserOperationV0_7::default())
    }
}
