use std::{collections::HashMap, pin::Pin, sync::Arc};

use async_stream::stream;
use ethers::types::{Address, H256};
use futures_util::Stream;
use rundler_types::{Entity, UserOperation};
use tokio::{
    sync::{broadcast, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tonic::async_trait;
use tracing::error;

use crate::{
    common::server::{HealthCheck, ServerStatus},
    op_pool::{
        chain::ChainUpdate,
        mempool::{Mempool, OperationOrigin, PoolOperation},
        server::{NewHead, PoolServer, Reputation},
        MempoolError, PoolResult, PoolServerError,
    },
};

#[derive(Debug)]
pub struct LocalPoolBuilder {
    req_sender: mpsc::Sender<ServerRequest>,
    req_receiver: mpsc::Receiver<ServerRequest>,
    block_sender: broadcast::Sender<NewHead>,
}

impl LocalPoolBuilder {
    pub fn new(request_capacity: usize, block_capacity: usize) -> Self {
        let (req_sender, req_receiver) = mpsc::channel(request_capacity);
        let (block_sender, _) = broadcast::channel(block_capacity);
        Self {
            req_sender,
            req_receiver,
            block_sender,
        }
    }

    pub fn get_handle(&self) -> LocalPoolHandle {
        LocalPoolHandle {
            req_sender: self.req_sender.clone(),
        }
    }

    pub fn run<M: Mempool>(
        self,
        mempools: HashMap<Address, Arc<M>>,
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

#[derive(Debug, Clone)]
pub struct LocalPoolHandle {
    req_sender: mpsc::Sender<ServerRequest>,
}

pub struct LocalPoolServerRunner<M> {
    req_receiver: mpsc::Receiver<ServerRequest>,
    block_sender: broadcast::Sender<NewHead>,
    mempools: HashMap<Address, Arc<M>>,
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
impl PoolServer for LocalPoolHandle {
    async fn get_supported_entry_points(&self) -> PoolResult<Vec<Address>> {
        let req = ServerRequestKind::GetSupportedEntryPoints;
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetSupportedEntryPoints { entry_points } => Ok(entry_points),
            _ => Err(PoolServerError::UnexpectedResponse),
        }
    }

    async fn add_op(&self, entry_point: Address, op: UserOperation) -> PoolResult<H256> {
        let req = ServerRequestKind::AddOp {
            entry_point,
            op,
            origin: OperationOrigin::Local,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::AddOp { hash } => Ok(hash),
            _ => Err(PoolServerError::UnexpectedResponse),
        }
    }

    async fn get_ops(&self, entry_point: Address, max_ops: u64) -> PoolResult<Vec<PoolOperation>> {
        let req = ServerRequestKind::GetOps {
            entry_point,
            max_ops,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetOps { ops } => Ok(ops),
            _ => Err(PoolServerError::UnexpectedResponse),
        }
    }

    async fn remove_ops(&self, entry_point: Address, ops: Vec<H256>) -> PoolResult<()> {
        let req = ServerRequestKind::RemoveOps { entry_point, ops };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::RemoveOps => Ok(()),
            _ => Err(PoolServerError::UnexpectedResponse),
        }
    }

    async fn remove_entities(&self, entry_point: Address, entities: Vec<Entity>) -> PoolResult<()> {
        let req = ServerRequestKind::RemoveEntities {
            entry_point,
            entities,
        };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::RemoveEntities => Ok(()),
            _ => Err(PoolServerError::UnexpectedResponse),
        }
    }

    async fn debug_clear_state(&self) -> Result<(), PoolServerError> {
        let req = ServerRequestKind::DebugClearState;
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugClearState => Ok(()),
            _ => Err(PoolServerError::UnexpectedResponse),
        }
    }

    async fn debug_dump_mempool(&self, entry_point: Address) -> PoolResult<Vec<PoolOperation>> {
        let req = ServerRequestKind::DebugDumpMempool { entry_point };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugDumpMempool { ops } => Ok(ops),
            _ => Err(PoolServerError::UnexpectedResponse),
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
            _ => Err(PoolServerError::UnexpectedResponse),
        }
    }

    async fn debug_dump_reputation(&self, entry_point: Address) -> PoolResult<Vec<Reputation>> {
        let req = ServerRequestKind::DebugDumpReputation { entry_point };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugDumpReputation { reputations } => Ok(reputations),
            _ => Err(PoolServerError::UnexpectedResponse),
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
            _ => Err(PoolServerError::UnexpectedResponse),
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

impl<M> LocalPoolServerRunner<M>
where
    M: Mempool,
{
    fn new(
        req_receiver: mpsc::Receiver<ServerRequest>,
        block_sender: broadcast::Sender<NewHead>,
        mempools: HashMap<Address, Arc<M>>,
        chain_updates: broadcast::Receiver<Arc<ChainUpdate>>,
    ) -> Self {
        Self {
            req_receiver,
            block_sender,
            mempools,
            chain_updates,
        }
    }

    fn get_pool(&self, entry_point: Address) -> PoolResult<&Arc<M>> {
        self.mempools.get(&entry_point).ok_or_else(|| {
            PoolServerError::MempoolError(MempoolError::UnknownEntryPoint(entry_point))
        })
    }

    fn get_ops(&self, entry_point: Address, max_ops: u64) -> PoolResult<Vec<PoolOperation>> {
        let mempool = self.get_pool(entry_point)?;
        Ok(mempool
            .best_operations(max_ops as usize)
            .iter()
            .map(|op| (**op).clone())
            .collect())
    }

    fn remove_ops(&self, entry_point: Address, ops: &[H256]) -> PoolResult<()> {
        let mempool = self.get_pool(entry_point)?;
        mempool.remove_operations(ops);
        Ok(())
    }

    fn remove_entities<'a>(
        &self,
        entry_point: Address,
        entities: impl IntoIterator<Item = &'a Entity>,
    ) -> PoolResult<()> {
        let mempool = self.get_pool(entry_point)?;
        for entity in entities {
            mempool.remove_entity(*entity);
        }
        Ok(())
    }

    fn debug_clear_state(&self) -> PoolResult<()> {
        for mempool in self.mempools.values() {
            mempool.clear();
        }
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
                        for mempool in self.mempools.values() {
                            mempool.on_chain_update(&chain_update);
                        }

                        let _ = self.block_sender.send(NewHead {
                            block_hash: chain_update.latest_block_hash,
                            block_number: chain_update.latest_block_number,
                        });
                    }
                }
                Some(req) = self.req_receiver.recv() => {
                    let resp = match req.request {
                        ServerRequestKind::GetSupportedEntryPoints => {
                            Ok(ServerResponse::GetSupportedEntryPoints {
                                entry_points: self.mempools.keys().copied().collect()
                            })
                        },
                        ServerRequestKind::AddOp { entry_point, op, origin } => {
                            match self.get_pool(entry_point) {
                                Ok(mempool) => {
                                    let mempool = Arc::clone(mempool);
                                    tokio::spawn(async move {
                                        let resp = match mempool.add_operation(origin, op).await {
                                            Ok(hash) => Ok(ServerResponse::AddOp { hash }),
                                            Err(e) => Err(e.into()),
                                        };
                                        if let Err(e) = req.response.send(resp) {
                                            tracing::error!("Failed to send response: {:?}", e);
                                        }
                                    });
                                    continue;
                                },
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::GetOps { entry_point, max_ops } => {
                            match self.get_ops(entry_point, max_ops) {
                                Ok(ops) => Ok(ServerResponse::GetOps { ops }),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::RemoveOps { entry_point, ops } => {
                            match self.remove_ops(entry_point, &ops) {
                                Ok(_) => Ok(ServerResponse::RemoveOps),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::RemoveEntities { entry_point, entities } => {
                            match self.remove_entities(entry_point, &entities) {
                                Ok(_) => Ok(ServerResponse::RemoveEntities),
                                Err(e) => Err(e),
                            }
                        },
                        ServerRequestKind::DebugClearState => {
                            match self.debug_clear_state() {
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
    pub request: ServerRequestKind,
    pub response: oneshot::Sender<PoolResult<ServerResponse>>,
}

#[derive(Debug)]
enum ServerRequestKind {
    GetSupportedEntryPoints,
    AddOp {
        entry_point: Address,
        op: UserOperation,
        origin: OperationOrigin,
    },
    GetOps {
        entry_point: Address,
        max_ops: u64,
    },
    RemoveOps {
        entry_point: Address,
        ops: Vec<H256>,
    },
    RemoveEntities {
        entry_point: Address,
        entities: Vec<Entity>,
    },
    DebugClearState,
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
    RemoveOps,
    RemoveEntities,
    DebugClearState,
    DebugDumpMempool {
        ops: Vec<PoolOperation>,
    },
    DebugSetReputations,
    DebugDumpReputation {
        reputations: Vec<Reputation>,
    },
    SubscribeNewHeads {
        new_heads: broadcast::Receiver<NewHead>,
    },
}

#[cfg(test)]
mod tests {
    use std::{iter::zip, sync::Arc};

    use futures_util::StreamExt;

    use super::*;
    use crate::op_pool::{chain::ChainUpdate, mempool::MockMempool};

    #[tokio::test]
    async fn test_add_op() {
        let mut mock_pool = MockMempool::new();
        let hash0 = H256::random();
        mock_pool
            .expect_add_operation()
            .returning(move |_, _| Ok(hash0));

        let ep = Address::random();
        let state = setup(HashMap::from([(ep, Arc::new(mock_pool))]));

        let hash1 = state
            .handle
            .add_op(ep, UserOperation::default())
            .await
            .unwrap();
        assert_eq!(hash0, hash1);
    }

    #[tokio::test]
    async fn test_chain_update() {
        let mut mock_pool = MockMempool::new();
        mock_pool.expect_on_chain_update().returning(|_| ());

        let ep = Address::random();
        let state = setup(HashMap::from([(ep, Arc::new(mock_pool))]));

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
                .map(|ep| (*ep, Arc::new(MockMempool::new())))
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
            .expect_add_operation()
            .returning(move |_, _| Ok(h0));
        pools[1]
            .expect_add_operation()
            .returning(move |_, _| Ok(h1));
        pools[2]
            .expect_add_operation()
            .returning(move |_, _| Ok(h2));

        let state = setup(
            zip(eps.iter(), pools.into_iter())
                .map(|(ep, pool)| (*ep, Arc::new(pool)))
                .collect(),
        );

        for (ep, hash) in zip(eps.iter(), hashes.iter()) {
            assert_eq!(
                *hash,
                state
                    .handle
                    .add_op(*ep, UserOperation::default())
                    .await
                    .unwrap()
            );
        }
    }

    struct State {
        handle: LocalPoolHandle,
        chain_update_tx: broadcast::Sender<Arc<ChainUpdate>>,
        _run_handle: JoinHandle<anyhow::Result<()>>,
    }

    fn setup(pools: HashMap<Address, Arc<MockMempool>>) -> State {
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
}
