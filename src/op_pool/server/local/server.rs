use ethers::types::{Address, H256};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    common::types::{Entity, UserOperation},
    op_pool::{
        mempool::{Mempool, MempoolGroup, OperationOrigin, PoolOperation},
        server::Reputation,
        PoolResult,
    },
};

pub fn spawn_local_mempool_server<M: Mempool>(
    mempool_runner: MempoolGroup<M>,
    receiver: mpsc::Receiver<ServerRequest>,
    shutdown_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let mut server = LocalPoolServer::new(receiver, mempool_runner);
    let handle = tokio::spawn(async move { server.run(shutdown_token).await });
    Ok(handle)
}

pub struct LocalPoolServer<M> {
    receiver: mpsc::Receiver<ServerRequest>,
    mempools: MempoolGroup<M>,
}

impl<M> LocalPoolServer<M>
where
    M: Mempool,
{
    pub fn new(receiver: mpsc::Receiver<ServerRequest>, mempools: MempoolGroup<M>) -> Self {
        Self { receiver, mempools }
    }

    pub async fn run(&mut self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    break;
                }
                Some(req) = self.receiver.recv() => {
                    let resp = match req.request {
                        ServerRequestKind::GetSupportedEntryPoints => {
                            Ok(ServerResponse::GetSupportedEntryPoints {
                                entry_points: self.mempools.get_supported_entry_points()
                            })
                        },
                        ServerRequestKind::AddOp { entry_point, op } => {
                            match self.mempools.add_op(entry_point, op, OperationOrigin::Local).await {
                                Ok(hash) => Ok(ServerResponse::AddOp { hash }),
                                Err(e) => Err(e.into()),
                            }
                        },
                        ServerRequestKind::GetOps { entry_point, max_ops } => {
                            match self.mempools.get_ops(entry_point, max_ops) {
                                Ok(ops) => Ok(ServerResponse::GetOps { ops }),
                                Err(e) => Err(e.into()),
                            }
                        },
                        ServerRequestKind::RemoveOps { entry_point, ops } => {
                            match self.mempools.remove_ops(entry_point, &ops) {
                                Ok(_) => Ok(ServerResponse::RemoveOps),
                                Err(e) => Err(e.into()),
                            }
                        },
                        ServerRequestKind::RemoveEntities { entry_point, entities } => {
                            match self.mempools.remove_entities(entry_point, &entities) {
                                Ok(_) => Ok(ServerResponse::RemoveOps),
                                Err(e) => Err(e.into()),
                            }
                        },
                        ServerRequestKind::DebugClearState => {
                            match self.mempools.debug_clear_state() {
                                Ok(_) => Ok(ServerResponse::RemoveOps),
                                Err(e) => Err(e.into()),
                            }
                        },
                        ServerRequestKind::DebugDumpMempool { entry_point } => {
                            match self.mempools.debug_dump_mempool(entry_point) {
                                Ok(ops) => Ok(ServerResponse::DebugDumpMempool { ops }),
                                Err(e) => Err(e.into()),
                            }
                        },
                        ServerRequestKind::DebugSetReputations { entry_point, reputations } => {
                            match self.mempools.debug_set_reputations(entry_point, &reputations) {
                                Ok(_) => Ok(ServerResponse::DebugSetReputations),
                                Err(e) => Err(e.into()),
                            }
                        },
                        ServerRequestKind::DebugDumpReputation { entry_point } => {
                            match  self.mempools.debug_dump_reputation(entry_point) {
                                Ok(reputations) => Ok(ServerResponse::DebugDumpReputation { reputations }),
                                Err(e) => Err(e.into()),
                            }
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
pub struct ServerRequest {
    pub request: ServerRequestKind,
    pub response: oneshot::Sender<PoolResult<ServerResponse>>,
}

#[derive(Clone, Debug)]
pub enum ServerRequestKind {
    GetSupportedEntryPoints,
    AddOp {
        entry_point: Address,
        op: UserOperation,
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
}

#[derive(Clone, Debug)]
pub enum ServerResponse {
    GetSupportedEntryPoints { entry_points: Vec<Address> },
    AddOp { hash: H256 },
    GetOps { ops: Vec<PoolOperation> },
    RemoveOps,
    RemoveEntities,
    DebugClearState,
    DebugDumpMempool { ops: Vec<PoolOperation> },
    DebugSetReputations,
    DebugDumpReputation { reputations: Vec<Reputation> },
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use super::*;
    use crate::op_pool::{mempool::MockMempool, LocalPoolClient, PoolClient};

    #[tokio::test]
    async fn send_receive() {
        let ep = Address::random();
        let mut mock_pool = MockMempool::new();
        mock_pool.expect_entry_point().returning(move || ep);

        let mempool_group = MempoolGroup::new(vec![Arc::new(mock_pool)]);
        let (tx, rx) = mpsc::channel(1);
        let shutdown_token = CancellationToken::new();
        let handle = spawn_local_mempool_server(mempool_group, rx, shutdown_token.clone()).unwrap();

        let client = LocalPoolClient::new(tx);
        let ret = client.get_supported_entry_points().await.unwrap();
        assert_eq!(ret, vec![ep]);

        shutdown_token.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn early_shutdown() {
        let ep = Address::random();
        let mut mock_pool = MockMempool::new();
        mock_pool.expect_entry_point().returning(move || ep);

        let mempool_group = MempoolGroup::new(vec![Arc::new(mock_pool)]);
        let (tx, rx) = mpsc::channel(1);
        let shutdown_token = CancellationToken::new();
        let handle = spawn_local_mempool_server(mempool_group, rx, shutdown_token.clone()).unwrap();

        shutdown_token.cancel();
        handle.await.unwrap().unwrap();

        let client = LocalPoolClient::new(tx);
        let ret = client.get_supported_entry_points().await;
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn add_op() {
        let ep = Address::random();
        let mut mock_pool = MockMempool::new();
        let uo = UserOperation::default();
        let uo_hash = uo.op_hash(ep, 0);

        mock_pool.expect_entry_point().returning(move || ep);
        mock_pool
            .expect_add_operation()
            .returning(move |_, _| Ok(uo_hash));

        let mempool_group = MempoolGroup::new(vec![Arc::new(mock_pool)]);
        let (tx, rx) = mpsc::channel(1);
        let shutdown_token = CancellationToken::new();
        let handle = spawn_local_mempool_server(mempool_group, rx, shutdown_token.clone()).unwrap();

        let client = LocalPoolClient::new(tx);
        let ret = client.add_op(ep, uo).await.unwrap();
        assert_eq!(ret, uo_hash);

        shutdown_token.cancel();
        handle.await.unwrap().unwrap();
    }
}
