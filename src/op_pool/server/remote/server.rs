use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use ethers::types::{Address, H256};
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::{async_trait, transport::Server, Request, Response, Result, Status};

use super::protos::{
    add_op_response, debug_clear_state_response, debug_dump_mempool_response,
    debug_dump_reputation_response, debug_set_reputation_response, get_ops_response,
    op_pool_server::{OpPool, OpPoolServer},
    remove_entities_response, remove_ops_response, AddOpRequest, AddOpResponse, AddOpSuccess,
    DebugClearStateRequest, DebugClearStateResponse, DebugClearStateSuccess,
    DebugDumpMempoolRequest, DebugDumpMempoolResponse, DebugDumpMempoolSuccess,
    DebugDumpReputationRequest, DebugDumpReputationResponse, DebugDumpReputationSuccess,
    DebugSetReputationRequest, DebugSetReputationResponse, DebugSetReputationSuccess,
    GetOpsRequest, GetOpsResponse, GetOpsSuccess, GetSupportedEntryPointsRequest,
    GetSupportedEntryPointsResponse, MempoolOp, NewHead, RemoveEntitiesRequest,
    RemoveEntitiesResponse, RemoveEntitiesSuccess, RemoveOpsRequest, RemoveOpsResponse,
    RemoveOpsSuccess, SubscribeNewHeadsRequest, SubscribeNewHeadsResponse,
    OP_POOL_FILE_DESCRIPTOR_SET,
};
use crate::{
    common::{grpc::metrics::GrpcMetricsLayer, protos::from_bytes, types::Entity},
    op_pool::mempool::{Mempool, MempoolGroup, OperationOrigin, Reputation},
};

const MAX_REMOTE_BLOCK_SUBSCRIPTIONS: usize = 32;

pub async fn spawn_remote_mempool_server<M: Mempool>(
    chain_id: u64,
    mempool_group: Arc<MempoolGroup<M>>,
    addr: SocketAddr,
    shutdown_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    // gRPC server
    let pool_impl = Arc::new(OpPoolImpl::new(chain_id, mempool_group));
    let op_pool_server = OpPoolServer::new(Arc::clone(&pool_impl));
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(OP_POOL_FILE_DESCRIPTOR_SET)
        .build()?;

    // health service
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<OpPoolServer<Arc<OpPoolImpl<M>>>>()
        .await;

    let metrics_layer = GrpcMetricsLayer::new("op_pool".to_string());
    let handle = tokio::spawn(async move {
        Server::builder()
            .layer(metrics_layer)
            .add_service(op_pool_server)
            .add_service(reflection_service)
            .add_service(health_service)
            .serve_with_shutdown(addr, async move { shutdown_token.cancelled().await })
            .await
            .map_err(|e| anyhow::anyhow!(format!("pool server failed: {e:?}")))
    });

    Ok(handle)
}

struct OpPoolImpl<M: Mempool> {
    chain_id: u64,
    mempools: Arc<MempoolGroup<M>>,
    num_block_subscriptions: Arc<AtomicUsize>,
}

impl<M> OpPoolImpl<M>
where
    M: Mempool,
{
    pub fn new(chain_id: u64, mempools: Arc<MempoolGroup<M>>) -> Self {
        Self {
            chain_id,
            mempools,
            num_block_subscriptions: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn get_entry_point(&self, req_entry_point: &[u8]) -> Result<Address> {
        from_bytes(req_entry_point)
            .map_err(|e| Status::invalid_argument(format!("Invalid entry point: {e}")))
    }
}

#[async_trait]
impl<M> OpPool for Arc<OpPoolImpl<M>>
where
    M: Mempool + 'static,
{
    async fn get_supported_entry_points(
        &self,
        _request: Request<GetSupportedEntryPointsRequest>,
    ) -> Result<Response<GetSupportedEntryPointsResponse>> {
        Ok(Response::new(GetSupportedEntryPointsResponse {
            chain_id: self.chain_id,
            entry_points: self
                .mempools
                .get_supported_entry_points()
                .into_iter()
                .map(|ep| ep.as_bytes().to_vec())
                .collect(),
        }))
    }

    async fn add_op(&self, request: Request<AddOpRequest>) -> Result<Response<AddOpResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let proto_op = req
            .op
            .ok_or_else(|| Status::invalid_argument("Operation is required in AddOpRequest"))?;
        let uo = proto_op.try_into().map_err(|e| {
            Status::invalid_argument(format!("Failed to convert to UserOperation: {e}"))
        })?;

        let resp = match self.mempools.add_op(ep, uo, OperationOrigin::Local).await {
            Ok(hash) => AddOpResponse {
                result: Some(add_op_response::Result::Success(AddOpSuccess {
                    hash: hash.as_bytes().to_vec(),
                })),
            },
            Err(error) => AddOpResponse {
                result: Some(add_op_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn get_ops(&self, request: Request<GetOpsRequest>) -> Result<Response<GetOpsResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let resp = match self.mempools.get_ops(ep, req.max_ops) {
            Ok(ops) => GetOpsResponse {
                result: Some(get_ops_response::Result::Success(GetOpsSuccess {
                    ops: ops.iter().map(MempoolOp::from).collect(),
                })),
            },
            Err(error) => GetOpsResponse {
                result: Some(get_ops_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn remove_ops(
        &self,
        request: Request<RemoveOpsRequest>,
    ) -> Result<Response<RemoveOpsResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let hashes: Vec<H256> = req
            .hashes
            .into_iter()
            .map(|h| {
                if h.len() != 32 {
                    return Err(Status::invalid_argument("Hash must be 32 bytes long"));
                }
                Ok(H256::from_slice(&h))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let resp = match self.mempools.remove_ops(ep, &hashes) {
            Ok(_) => RemoveOpsResponse {
                result: Some(remove_ops_response::Result::Success(RemoveOpsSuccess {})),
            },
            Err(error) => RemoveOpsResponse {
                result: Some(remove_ops_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn remove_entities(
        &self,
        request: Request<RemoveEntitiesRequest>,
    ) -> Result<Response<RemoveEntitiesResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;
        let entities = req
            .entities
            .iter()
            .map(|et| et.try_into())
            .collect::<Result<Vec<Entity>, _>>()
            .map_err(|e| Status::internal(format!("Failed to convert to proto entity: {e}")))?;

        self.mempools
            .remove_entities(ep, &entities)
            .map_err(|e| Status::internal(e.to_string()))?;

        let resp = match self.mempools.remove_entities(ep, &entities) {
            Ok(_) => RemoveEntitiesResponse {
                result: Some(remove_entities_response::Result::Success(
                    RemoveEntitiesSuccess {},
                )),
            },
            Err(error) => RemoveEntitiesResponse {
                result: Some(remove_entities_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn debug_clear_state(
        &self,
        _request: Request<DebugClearStateRequest>,
    ) -> Result<Response<DebugClearStateResponse>> {
        let resp = match self.mempools.debug_clear_state() {
            Ok(_) => DebugClearStateResponse {
                result: Some(debug_clear_state_response::Result::Success(
                    DebugClearStateSuccess {},
                )),
            },
            Err(error) => DebugClearStateResponse {
                result: Some(debug_clear_state_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn debug_dump_mempool(
        &self,
        request: Request<DebugDumpMempoolRequest>,
    ) -> Result<Response<DebugDumpMempoolResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let resp = match self.mempools.debug_dump_mempool(ep) {
            Ok(ops) => DebugDumpMempoolResponse {
                result: Some(debug_dump_mempool_response::Result::Success(
                    DebugDumpMempoolSuccess {
                        ops: ops.iter().map(MempoolOp::from).collect(),
                    },
                )),
            },
            Err(error) => DebugDumpMempoolResponse {
                result: Some(debug_dump_mempool_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn debug_set_reputation(
        &self,
        request: Request<DebugSetReputationRequest>,
    ) -> Result<Response<DebugSetReputationResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let reps = if req.reputations.is_empty() {
            return Err(Status::invalid_argument(
                "Reputation is required in DebugSetReputationRequest",
            ));
        } else {
            req.reputations
        };

        let reps = reps
            .into_iter()
            .map(|r| r.try_into())
            .collect::<Result<Vec<Reputation>, _>>()
            .map_err(|e| {
                Status::internal(format!("Failed to convert from proto reputation {e}"))
            })?;

        let resp = match self.mempools.debug_set_reputations(ep, &reps) {
            Ok(_) => DebugSetReputationResponse {
                result: Some(debug_set_reputation_response::Result::Success(
                    DebugSetReputationSuccess {},
                )),
            },
            Err(error) => DebugSetReputationResponse {
                result: Some(debug_set_reputation_response::Result::Failure(error.into())),
            },
        };

        Ok(Response::new(resp))
    }

    async fn debug_dump_reputation(
        &self,
        request: Request<DebugDumpReputationRequest>,
    ) -> Result<Response<DebugDumpReputationResponse>> {
        let req = request.into_inner();
        let ep = self.get_entry_point(&req.entry_point)?;

        let resp = match self.mempools.debug_dump_reputation(ep) {
            Ok(reps) => DebugDumpReputationResponse {
                result: Some(debug_dump_reputation_response::Result::Success(
                    DebugDumpReputationSuccess {
                        reputations: reps.into_iter().map(Into::into).collect(),
                    },
                )),
            },
            Err(error) => DebugDumpReputationResponse {
                result: Some(debug_dump_reputation_response::Result::Failure(
                    error.into(),
                )),
            },
        };

        Ok(Response::new(resp))
    }

    type SubscribeNewHeadsStream = ReceiverStream<Result<SubscribeNewHeadsResponse>>;

    async fn subscribe_new_heads(
        &self,
        _request: Request<SubscribeNewHeadsRequest>,
    ) -> Result<Response<Self::SubscribeNewHeadsStream>> {
        let (tx, rx) = mpsc::channel(1024);

        if self.num_block_subscriptions.fetch_add(1, Ordering::Relaxed)
            >= MAX_REMOTE_BLOCK_SUBSCRIPTIONS
        {
            self.num_block_subscriptions.fetch_sub(1, Ordering::Relaxed);
            return Err(Status::resource_exhausted("Too many block subscriptions"));
        }

        let num_block_subscriptions = Arc::clone(&self.num_block_subscriptions);
        let mut chain_updates = self.mempools.clone().subscribe_chain_update();
        tokio::spawn(async move {
            loop {
                match chain_updates.recv().await {
                    Ok(chain_update) => {
                        if tx
                            .send(Ok(SubscribeNewHeadsResponse {
                                new_head: Some(NewHead {
                                    block_hash: chain_update.latest_block_hash.as_bytes().to_vec(),
                                    block_number: chain_update.latest_block_number,
                                }),
                            }))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        tracing::warn!("chain update channel closed");
                        break;
                    }
                }
            }
            num_block_subscriptions.fetch_sub(1, Ordering::Relaxed);
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
