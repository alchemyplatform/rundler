use std::sync::Arc;

use super::mempool::{Mempool, OperationOrigin, PoolOperation};
use super::metrics::OpPoolMetrics;
use crate::common::protos::op_pool::op_pool_server::OpPool;
use crate::common::protos::op_pool::{
    AddOpRequest, AddOpResponse, DebugClearStateRequest, DebugClearStateResponse,
    DebugDumpMempoolRequest, DebugDumpMempoolResponse, DebugDumpReputationRequest,
    DebugDumpReputationResponse, DebugSetReputationRequest, DebugSetReputationResponse,
    GetOpsRequest, GetOpsResponse, GetSupportedEntryPointsRequest, GetSupportedEntryPointsResponse,
    MempoolOp, RemoveOpsRequest, RemoveOpsResponse, UserOperation,
};
use ethers::types::{Address, H256, U256};
use tonic::{async_trait, Request, Response};

pub struct OpPoolImpl<M: Mempool> {
    chain_id: U256,
    mempool: Arc<M>,
    metrics: OpPoolMetrics,
}

impl<M> OpPoolImpl<M>
where
    M: Mempool,
{
    pub fn new(chain_id: U256, mempool: Arc<M>) -> Self {
        Self {
            chain_id,
            metrics: OpPoolMetrics::default(),
            mempool,
        }
    }
}

#[async_trait]
impl<M> OpPool for OpPoolImpl<M>
where
    M: Mempool + 'static,
{
    async fn get_supported_entry_points(
        &self,
        _request: Request<GetSupportedEntryPointsRequest>,
    ) -> tonic::Result<Response<GetSupportedEntryPointsResponse>> {
        self.metrics.request_counter.increment(1);
        let mempool_ep = self.mempool.entry_point();
        let cid: [u8; 32] = self.chain_id.into();
        Ok(Response::new(GetSupportedEntryPointsResponse {
            chain_id: cid.to_vec(),
            entry_points: vec![mempool_ep.as_bytes().to_vec()],
        }))
    }

    async fn add_op(
        &self,
        request: Request<AddOpRequest>,
    ) -> tonic::Result<Response<AddOpResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let uo = req.uo.ok_or_else(|| {
            tonic::Status::invalid_argument("Operation is required in AddOpRequest")
        })?;

        let agg = if !req.aggregator.is_empty() {
            Some(Self::get_address(&req.aggregator)?)
        } else {
            None
        };

        let hash = self
            .mempool
            .add_operation(
                OperationOrigin::Local,
                PoolOperation {
                    uo: uo.into(),
                    aggregator: agg,
                },
            )
            .map_err(|e| {
                tonic::Status::internal(format!("Failed to add operation to mempool: {e}"))
            })?;

        Ok(Response::new(AddOpResponse {
            hash: hash.as_bytes().to_vec(),
        }))
    }

    async fn get_ops(
        &self,
        request: Request<GetOpsRequest>,
    ) -> tonic::Result<Response<GetOpsResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let ops = self.mempool.best_operations(req.max_ops as usize);

        Ok(Response::new(GetOpsResponse {
            ops: ops.iter().map(|op| MempoolOp::from(&(**op))).collect(),
        }))
    }

    async fn remove_ops(
        &self,
        request: Request<RemoveOpsRequest>,
    ) -> tonic::Result<Response<RemoveOpsResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let hashes: Vec<H256> = req
            .hashes
            .into_iter()
            .map(|h| {
                if h.len() != 32 {
                    return Err(tonic::Status::invalid_argument(
                        "Hash must be 32 bytes long",
                    ));
                }
                Ok(H256::from_slice(&h))
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.mempool.remove_operations(&hashes);

        Ok(Response::new(RemoveOpsResponse {}))
    }

    async fn debug_clear_state(
        &self,
        _request: Request<DebugClearStateRequest>,
    ) -> tonic::Result<Response<DebugClearStateResponse>> {
        self.metrics.request_counter.increment(1);
        self.mempool.clear();
        Ok(Response::new(DebugClearStateResponse {}))
    }

    async fn debug_dump_mempool(
        &self,
        request: Request<DebugDumpMempoolRequest>,
    ) -> tonic::Result<Response<DebugDumpMempoolResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let ops = self.mempool.best_operations(usize::MAX);

        Ok(Response::new(DebugDumpMempoolResponse {
            ops: ops.iter().map(|op| MempoolOp::from(&(**op))).collect(),
        }))
    }

    async fn debug_set_reputation(
        &self,
        request: Request<DebugSetReputationRequest>,
    ) -> tonic::Result<Response<DebugSetReputationResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let rep = match &req.reputation {
            Some(rep) => rep,
            None => {
                return Err(tonic::Status::invalid_argument(
                    "Reputation is required in DebugSetReputationRequest",
                ))
            }
        };

        let addr = Self::get_address(&rep.address)?;
        self.mempool
            .set_reputation(addr, rep.ops_seen, rep.ops_included);

        Ok(Response::new(DebugSetReputationResponse {}))
    }

    async fn debug_dump_reputation(
        &self,
        request: Request<DebugDumpReputationRequest>,
    ) -> tonic::Result<Response<DebugDumpReputationResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let reps = self.mempool.dump_reputation();
        Ok(Response::new(DebugDumpReputationResponse {
            reputations: reps,
        }))
    }
}

impl<M> OpPoolImpl<M>
where
    M: Mempool,
{
    fn check_entry_point(req_entry_point: &[u8], pool_entry_point: Address) -> tonic::Result<()> {
        let req_ep = Self::get_address(req_entry_point)?;
        if req_ep != pool_entry_point {
            return Err(tonic::Status::invalid_argument(format!(
                "Invalid entry point: {req_ep:?}, expected {pool_entry_point:?}"
            )));
        }

        Ok(())
    }

    fn get_address(bytes: &[u8]) -> tonic::Result<Address> {
        let len = bytes.len();
        if len != 20 {
            return Err(tonic::Status::invalid_argument(format!(
                "Invalid address length: {len}, expected 20"
            )));
        }

        Ok(Address::from_slice(bytes))
    }
}

impl From<&PoolOperation> for MempoolOp {
    fn from(op: &PoolOperation) -> Self {
        MempoolOp {
            uo: Some(UserOperation::from(&op.uo)),
            aggregator: op.aggregator.map_or(vec![], |a| a.as_bytes().to_vec()),
        }
    }
}
