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

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use async_stream::stream;
use async_trait::async_trait;
use ethers::types::{Address, H256};
use futures::future;
use futures_util::Stream;
use rundler_task::server::{HealthCheck, ServerStatus};
use rundler_types::{
    pool::{
        MempoolError, NewHead, PaymasterMetadata, Pool, PoolError, PoolOperation, PoolResult,
        Reputation, ReputationStatus, StakeStatus,
    },
    EntityUpdate, EntryPointVersion, UserOperationId, UserOperationVariant,
};
use tokio::{
    sync::{broadcast, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::error;

use crate::{
    chain::ChainUpdate,
    mempool::{Mempool, OperationOrigin},
};

/// Local pool server builder
#[derive(Debug)]
pub struct LocalPoolBuilder {
    req_sender: mpsc::Sender<ServerRequest>,
    req_receiver: mpsc::Receiver<ServerRequest>,
    block_sender: broadcast::Sender<NewHead>,
}

impl LocalPoolBuilder {
    /// Create a new local pool server builder
    pub fn new(request_capacity: usize, block_capacity: usize) -> Self {
        let (req_sender, req_receiver) = mpsc::channel(request_capacity);
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
        }
    }

    /// Run the local pool server, consumes the builder
    pub fn run(
        self,
        mempools: HashMap<Address, Arc<dyn Mempool>>,
        chain_updates: broadcast::Receiver<Arc<ChainUpdate>>,
        shutdown_token: CancellationToken,
    ) -> JoinHandle<anyhow::Result<()>> {
        let mut runner = LocalPoolServerRunner::new(
            self.req_receiver,
            self.block_sender,
            mempools,
            chain_updates,
        );
        tokio::spawn(async move { runner.run(shutdown_token).await })
    }
}

/// Handle to the local pool server
///
/// Used to make requests to the local pool server
#[derive(Debug, Clone)]
pub struct LocalPoolHandle {
    req_sender: mpsc::Sender<ServerRequest>,
}

struct LocalPoolServerRunner {
    req_receiver: mpsc::Receiver<ServerRequest>,
    block_sender: broadcast::Sender<NewHead>,
    mempools: HashMap<Address, Arc<dyn Mempool>>,
    chain_updates: broadcast::Receiver<Arc<ChainUpdate>>,
}

impl LocalPoolHandle {
    async fn send(&self, request: ServerRequestKind) -> PoolResult<ServerResponse> {
        let (send, recv) = oneshot::channel();
        self.req_sender
            .send(ServerRequest {
                request,
                response: send,
            })
            .await
            .map_err(|_| anyhow::anyhow!("LocalPoolServer closed"))?;
        recv.await
            .map_err(|_| anyhow::anyhow!("LocalPoolServer closed"))?
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

    async fn add_op(&self, entry_point: Address, op: UserOperationVariant) -> PoolResult<H256> {
        let req = ServerRequestKind::AddOp {
            entry_point,
            op,
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
        shard_index: u64,
    ) -> PoolResult<Vec<PoolOperation>> {
        let req = ServerRequestKind::GetOps {
            entry_point,
            max_ops,
            shard_index,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetOps { ops } => Ok(ops),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn get_op_by_hash(&self, hash: H256) -> PoolResult<Option<PoolOperation>> {
        let req = ServerRequestKind::GetOpByHash { hash };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetOpByHash { op } => Ok(op),
            _ => Err(PoolError::UnexpectedResponse),
        }
    }

    async fn remove_ops(&self, entry_point: Address, ops: Vec<H256>) -> PoolResult<()> {
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
    ) -> PoolResult<Option<H256>> {
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

    async fn subscribe_new_heads(&self) -> PoolResult<Pin<Box<dyn Stream<Item = NewHead> + Send>>> {
        let req = ServerRequestKind::SubscribeNewHeads;
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
                            error!("new_heads_receiver closed");
                            break;
                        }
                    }
                }
            })),
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
        if self.get_supported_entry_points().await.is_ok() {
            ServerStatus::Serving
        } else {
            ServerStatus::NotServing
        }
    }
}

impl LocalPoolServerRunner {
    fn new(
        req_receiver: mpsc::Receiver<ServerRequest>,
        block_sender: broadcast::Sender<NewHead>,
        mempools: HashMap<Address, Arc<dyn Mempool>>,
        chain_updates: broadcast::Receiver<Arc<ChainUpdate>>,
    ) -> Self {
        Self {
            req_receiver,
            block_sender,
            mempools,
            chain_updates,
        }
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
        shard_index: u64,
    ) -> PoolResult<Vec<PoolOperation>> {
        let mempool = self.get_pool(entry_point)?;
        Ok(mempool
            .best_operations(max_ops as usize, shard_index)?
            .iter()
            .map(|op| (**op).clone())
            .collect())
    }

    fn get_op_by_hash(&self, hash: H256) -> PoolResult<Option<PoolOperation>> {
        for mempool in self.mempools.values() {
            if let Some(op) = mempool.get_user_operation_by_hash(hash) {
                return Ok(Some((*op).clone()));
            }
        }
        Ok(None)
    }

    fn remove_ops(&self, entry_point: Address, ops: &[H256]) -> PoolResult<()> {
        let mempool = self.get_pool(entry_point)?;
        mempool.remove_operations(ops);
        Ok(())
    }

    fn remove_op_by_id(
        &self,
        entry_point: Address,
        id: &UserOperationId,
    ) -> PoolResult<Option<H256>> {
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
        Ok(mempool
            .all_operations(usize::MAX)
            .iter()
            .map(|op| (**op).clone())
            .collect())
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
                tokio::spawn(f(mempool, response));
            }
            Err(e) => {
                if let Err(e) = response.send(Err(e)) {
                    tracing::error!("Failed to send response: {:?}", e);
                }
            }
        }
    }

    async fn run(&mut self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    break;
                }
                chain_update = self.chain_updates.recv() => {
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
                        tokio::spawn(async move {
                            future::join_all(update_futures).await;
                            let _ = block_sender.send(NewHead {
                                block_hash: chain_update.latest_block_hash,
                                block_number: chain_update.latest_block_number,
                            });
                        });
                    }
                }
                Some(req) = self.req_receiver.recv() => {
                    let resp = match req.request {
                        // Async methods
                        // Responses are sent in the spawned task
                        ServerRequestKind::AddOp { entry_point, op, origin } => {
                            let fut = |mempool: Arc<dyn Mempool>, response: oneshot::Sender<Result<ServerResponse, PoolError>>| async move {
                                let resp = 'resp: {
                                    match mempool.entry_point_version() {
                                        EntryPointVersion::V0_6 => {
                                            if !matches!(&op, UserOperationVariant::V0_6(_)){
                                                 break 'resp Err(anyhow::anyhow!("Invalid user operation version for mempool v0.6 {:?}", op.uo_type()).into());
                                            }
                                        }
                                        EntryPointVersion::V0_7 => {
                                            if !matches!(&op, UserOperationVariant::V0_7(_)){
                                                break 'resp Err(anyhow::anyhow!("Invalid user operation version for mempool v0.7 {:?}", op.uo_type()).into());
                                            }
                                        }
                                        EntryPointVersion::Unspecified => {
                                            panic!("Found mempool with unspecified entry point version")
                                        }
                                    }

                                    match mempool.add_operation(origin, op).await {
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

                        // Sync methods
                        // Responses are sent in the main loop below
                        ServerRequestKind::GetSupportedEntryPoints => {
                            Ok(ServerResponse::GetSupportedEntryPoints {
                                entry_points: self.mempools.keys().copied().collect()
                            })
                        },
                        ServerRequestKind::GetOps { entry_point, max_ops, shard_index } => {
                            match self.get_ops(entry_point, max_ops, shard_index) {
                                Ok(ops) => Ok(ServerResponse::GetOps { ops }),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::GetOpByHash { hash } => {
                            match self.get_op_by_hash(hash) {
                                Ok(op) => Ok(ServerResponse::GetOpByHash { op }),
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
                        ServerRequestKind::SubscribeNewHeads => {
                            Ok(ServerResponse::SubscribeNewHeads { new_heads: self.block_sender.subscribe() } )
                        }
                    };
                    if let Err(e) = req.response.send(resp) {
                        tracing::error!("Failed to send response: {:?}", e);
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct ServerRequest {
    request: ServerRequestKind,
    response: oneshot::Sender<PoolResult<ServerResponse>>,
}

#[derive(Debug)]
enum ServerRequestKind {
    GetSupportedEntryPoints,
    AddOp {
        entry_point: Address,
        op: UserOperationVariant,
        origin: OperationOrigin,
    },
    GetOps {
        entry_point: Address,
        max_ops: u64,
        shard_index: u64,
    },
    GetOpByHash {
        hash: H256,
    },
    RemoveOps {
        entry_point: Address,
        ops: Vec<H256>,
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
    SubscribeNewHeads,
}

#[derive(Debug)]
enum ServerResponse {
    GetSupportedEntryPoints {
        entry_points: Vec<Address>,
    },
    AddOp {
        hash: H256,
    },
    GetOps {
        ops: Vec<PoolOperation>,
    },
    GetOpByHash {
        op: Option<PoolOperation>,
    },
    RemoveOps,
    RemoveOpById {
        hash: Option<H256>,
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
}

#[cfg(test)]
mod tests {
    use std::{iter::zip, sync::Arc};

    use futures_util::StreamExt;
    use rundler_types::v0_6::UserOperation;

    use super::*;
    use crate::{chain::ChainUpdate, mempool::MockMempool};

    #[tokio::test]
    async fn test_add_op() {
        let mut mock_pool = MockMempool::new();
        let hash0 = H256::random();
        mock_pool
            .expect_entry_point_version()
            .returning(|| EntryPointVersion::V0_6);
        mock_pool
            .expect_add_operation()
            .returning(move |_, _| Ok(hash0));

        let ep = Address::random();
        let pool: Arc<dyn Mempool> = Arc::new(mock_pool);
        let state = setup(HashMap::from([(ep, pool)]));

        let hash1 = state.handle.add_op(ep, mock_op()).await.unwrap();
        assert_eq!(hash0, hash1);
    }

    #[tokio::test]
    async fn test_chain_update() {
        let mut mock_pool = MockMempool::new();
        mock_pool.expect_on_chain_update().returning(|_| ());

        let ep = Address::random();
        let pool: Arc<dyn Mempool> = Arc::new(mock_pool);
        let state = setup(HashMap::from([(ep, pool)]));

        let mut sub = state.handle.subscribe_new_heads().await.unwrap();

        let hash = H256::random();
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
        let eps = [Address::random(), Address::random(), Address::random()];
        let mut pools = [MockMempool::new(), MockMempool::new(), MockMempool::new()];
        let h0 = H256::random();
        let h1 = H256::random();
        let h2 = H256::random();
        let hashes = [h0, h1, h2];
        pools[0]
            .expect_entry_point_version()
            .returning(|| EntryPointVersion::V0_6);
        pools[0]
            .expect_add_operation()
            .returning(move |_, _| Ok(h0));
        pools[1]
            .expect_entry_point_version()
            .returning(|| EntryPointVersion::V0_6);
        pools[1]
            .expect_add_operation()
            .returning(move |_, _| Ok(h1));
        pools[2]
            .expect_entry_point_version()
            .returning(|| EntryPointVersion::V0_6);
        pools[2]
            .expect_add_operation()
            .returning(move |_, _| Ok(h2));

        let state = setup(
            zip(eps.iter(), pools.into_iter())
                .map(|(ep, pool)| {
                    let pool: Arc<dyn Mempool> = Arc::new(pool);
                    (*ep, pool)
                })
                .collect(),
        );

        for (ep, hash) in zip(eps.iter(), hashes.iter()) {
            assert_eq!(*hash, state.handle.add_op(*ep, mock_op()).await.unwrap());
        }
    }

    struct State {
        handle: LocalPoolHandle,
        chain_update_tx: broadcast::Sender<Arc<ChainUpdate>>,
        _run_handle: JoinHandle<anyhow::Result<()>>,
    }

    fn setup(pools: HashMap<Address, Arc<dyn Mempool>>) -> State {
        let builder = LocalPoolBuilder::new(10, 10);
        let handle = builder.get_handle();
        let (tx, rx) = broadcast::channel(10);
        let run_handle = builder.run(pools, rx, CancellationToken::new());
        State {
            handle,
            chain_update_tx: tx,
            _run_handle: run_handle,
        }
    }

    fn mock_op() -> UserOperationVariant {
        UserOperationVariant::V0_6(UserOperation::default())
    }
}
