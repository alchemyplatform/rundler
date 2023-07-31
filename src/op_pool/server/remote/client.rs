use anyhow::bail;
use ethers::types::{Address, H256};
use tokio_util::sync::CancellationToken;
use tonic::{async_trait, transport::Channel};

use super::protos::{
    self, add_op_response, debug_clear_state_response, debug_dump_mempool_response,
    debug_dump_reputation_response, debug_set_reputation_response, get_ops_response,
    op_pool_client::OpPoolClient, remove_entities_response, remove_ops_response, AddOpRequest,
    DebugClearStateRequest, DebugDumpMempoolRequest, DebugDumpReputationRequest,
    DebugSetReputationRequest, GetOpsRequest, RemoveEntitiesRequest, RemoveOpsRequest,
};
use crate::{
    common::{
        protos::{from_bytes, ConversionError},
        server::connect_with_retries,
        types::{Entity, UserOperation},
    },
    op_pool::{
        mempool::{PoolOperation, Reputation},
        server::{error::PoolServerError, PoolClient},
        PoolResult,
    },
};

#[derive(Clone, Debug)]
pub struct RemotePoolClient {
    op_pool_client: OpPoolClient<Channel>,
}

impl RemotePoolClient {
    pub fn new(client: OpPoolClient<Channel>) -> Self {
        Self {
            op_pool_client: client,
        }
    }
}

#[async_trait]
impl PoolClient for RemotePoolClient {
    async fn get_supported_entry_points(&self) -> PoolResult<Vec<Address>> {
        Ok(self
            .op_pool_client
            .clone()
            .get_supported_entry_points(protos::GetSupportedEntryPointsRequest {})
            .await?
            .into_inner()
            .entry_points
            .into_iter()
            .map(|ep| from_bytes(ep.as_slice()))
            .collect::<Result<_, ConversionError>>()?)
    }

    async fn add_op(&self, entry_point: Address, op: UserOperation) -> PoolResult<H256> {
        let res = self
            .op_pool_client
            .clone()
            .add_op(AddOpRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                op: Some(protos::UserOperation::from(&op)),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(add_op_response::Result::Success(s)) => Ok(H256::from_slice(&s.hash)),
            Some(add_op_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn get_ops(&self, entry_point: Address, max_ops: u64) -> PoolResult<Vec<PoolOperation>> {
        let res = self
            .op_pool_client
            .clone()
            .get_ops(GetOpsRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                max_ops,
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(get_ops_response::Result::Success(s)) => s
                .ops
                .into_iter()
                .map(PoolOperation::try_from)
                .map(|res| res.map_err(PoolServerError::from))
                .collect(),
            Some(get_ops_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn remove_ops(&self, entry_point: Address, ops: Vec<H256>) -> PoolResult<()> {
        let res = self
            .op_pool_client
            .clone()
            .remove_ops(RemoveOpsRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                hashes: ops.into_iter().map(|h| h.as_bytes().to_vec()).collect(),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(remove_ops_response::Result::Success(_)) => Ok(()),
            Some(remove_ops_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn remove_entities(&self, entry_point: Address, entities: Vec<Entity>) -> PoolResult<()> {
        let res = self
            .op_pool_client
            .clone()
            .remove_entities(RemoveEntitiesRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                entities: entities.iter().map(protos::Entity::from).collect(),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(remove_entities_response::Result::Success(_)) => Ok(()),
            Some(remove_entities_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn debug_clear_state(&self) -> PoolResult<()> {
        let res = self
            .op_pool_client
            .clone()
            .debug_clear_state(DebugClearStateRequest {})
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_clear_state_response::Result::Success(_)) => Ok(()),
            Some(debug_clear_state_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn debug_dump_mempool(&self, entry_point: Address) -> PoolResult<Vec<PoolOperation>> {
        let res = self
            .op_pool_client
            .clone()
            .debug_dump_mempool(DebugDumpMempoolRequest {
                entry_point: entry_point.as_bytes().to_vec(),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_dump_mempool_response::Result::Success(s)) => s
                .ops
                .into_iter()
                .map(PoolOperation::try_from)
                .map(|res| res.map_err(PoolServerError::from))
                .collect(),
            Some(debug_dump_mempool_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn debug_set_reputations(
        &self,
        entry_point: Address,
        reputations: Vec<Reputation>,
    ) -> PoolResult<()> {
        let res = self
            .op_pool_client
            .clone()
            .debug_set_reputation(DebugSetReputationRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                reputations: reputations
                    .into_iter()
                    .map(protos::Reputation::from)
                    .collect(),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_set_reputation_response::Result::Success(_)) => Ok(()),
            Some(debug_set_reputation_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn debug_dump_reputation(&self, entry_point: Address) -> PoolResult<Vec<Reputation>> {
        let res = self
            .op_pool_client
            .clone()
            .debug_dump_reputation(DebugDumpReputationRequest {
                entry_point: entry_point.as_bytes().to_vec(),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_dump_reputation_response::Result::Success(s)) => s
                .reputations
                .into_iter()
                .map(Reputation::try_from)
                .map(|res| res.map_err(PoolServerError::from))
                .collect(),
            Some(debug_dump_reputation_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }
}

pub async fn connect_remote_pool_client(
    op_pool_url: &str,
    shutdown_token: CancellationToken,
) -> anyhow::Result<RemotePoolClient> {
    tokio::select! {
        _ = shutdown_token.cancelled() => {
            tracing::error!("bailing from connecting client, server shutting down");
            bail!("Server shutting down")
        }
        res = connect_with_retries("op pool from builder", op_pool_url, OpPoolClient::connect) => {
            Ok(RemotePoolClient::new(res?))
        }
    }
}
