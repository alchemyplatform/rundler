use ethers::types::{Address, H256};
use tokio::sync::{broadcast, mpsc, oneshot};
use tonic::async_trait;

use super::server::{ServerRequest, ServerRequestKind, ServerResponse};
use crate::{
    common::types::{Entity, UserOperation},
    op_pool::{
        mempool::PoolOperation,
        server::{error::PoolServerError, NewBlock, PoolClient, Reputation},
        PoolResult,
    },
};

#[derive(Debug)]
pub struct LocalPoolClient {
    sender: mpsc::Sender<ServerRequest>,
    block_receiver: broadcast::Receiver<NewBlock>,
}

impl LocalPoolClient {
    pub fn new(
        sender: mpsc::Sender<ServerRequest>,
        block_receiver: broadcast::Receiver<NewBlock>,
    ) -> Self {
        Self {
            sender,
            block_receiver,
        }
    }

    async fn send(&self, request: ServerRequestKind) -> PoolResult<ServerResponse> {
        let (send, recv) = oneshot::channel();
        self.sender
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
impl PoolClient for LocalPoolClient {
    async fn get_supported_entry_points(&self) -> PoolResult<Vec<Address>> {
        let req = ServerRequestKind::GetSupportedEntryPoints;
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetSupportedEntryPoints { entry_points } => Ok(entry_points),
            _ => Err(PoolServerError::UnexpectedResponse),
        }
    }

    async fn add_op(&self, entry_point: Address, op: UserOperation) -> PoolResult<H256> {
        let req = ServerRequestKind::AddOp { entry_point, op };
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

    async fn subscribe_new_blocks(&self) -> PoolResult<broadcast::Receiver<NewBlock>> {
        Ok(self.block_receiver.resubscribe())
    }
}

impl Clone for LocalPoolClient {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            block_receiver: self.block_receiver.resubscribe(),
        }
    }
}
