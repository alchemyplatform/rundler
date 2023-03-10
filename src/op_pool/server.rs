use std::sync::Arc;

use super::mempool::{Mempool, OperationOrigin};
use super::metrics::OpPoolMetrics;
use crate::common::protos::op_pool::op_pool_server::OpPool;
use crate::common::protos::op_pool::{
    AddOpRequest, AddOpResponse, DebugClearStateRequest, DebugClearStateResponse,
    DebugDumpMempoolRequest, DebugDumpMempoolResponse, DebugDumpReputationRequest,
    DebugDumpReputationResponse, DebugSetReputationRequest, DebugSetReputationResponse,
    GetOpsRequest, GetOpsResponse, GetSupportedEntryPointsRequest, GetSupportedEntryPointsResponse,
    MempoolOp, RemoveOpsRequest, RemoveOpsResponse,
};
use crate::common::protos::ProtoBytes;
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

    fn check_entry_point(req_entry_point: &[u8], pool_entry_point: Address) -> tonic::Result<()> {
        let req_ep: Address = ProtoBytes(req_entry_point)
            .try_into()
            .map_err(|e| tonic::Status::invalid_argument(format!("Invalid entry point: {e}")))?;
        if req_ep != pool_entry_point {
            return Err(tonic::Status::invalid_argument(format!(
                "Invalid entry point: {req_ep:?}, expected {pool_entry_point:?}"
            )));
        }

        Ok(())
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

        let proto_op = req.op.ok_or_else(|| {
            tonic::Status::invalid_argument("Operation is required in AddOpRequest")
        })?;

        let pool_op = proto_op.try_into().map_err(|e| {
            tonic::Status::invalid_argument(format!("Failed to parse operation: {e}"))
        })?;

        let hash = self
            .mempool
            .add_operation(OperationOrigin::Local, pool_op)
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

        let ops = self
            .mempool
            .best_operations(req.max_ops as usize)
            .iter()
            .map(|op| MempoolOp::try_from(&(**op)))
            .collect::<Result<Vec<MempoolOp>, _>>()
            .map_err(|e| {
                tonic::Status::internal(format!("Failed to convert to proto mempool op: {e}"))
            })?;

        Ok(Response::new(GetOpsResponse { ops }))
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

        let ops = self
            .mempool
            .best_operations(usize::MAX)
            .iter()
            .map(|op| MempoolOp::try_from(&(**op)))
            .collect::<Result<Vec<MempoolOp>, _>>()
            .map_err(|e| {
                tonic::Status::internal(format!("Failed to convert to proto mempool op: {e}"))
            })?;

        Ok(Response::new(DebugDumpMempoolResponse { ops }))
    }

    async fn debug_set_reputation(
        &self,
        request: Request<DebugSetReputationRequest>,
    ) -> tonic::Result<Response<DebugSetReputationResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let reps = if req.reputations.is_empty() {
            return Err(tonic::Status::invalid_argument(
                "Reputation is required in DebugSetReputationRequest",
            ));
        } else {
            req.reputations
        };

        for rep in reps {
            let addr = ProtoBytes(&rep.address)
                .try_into()
                .map_err(|e| tonic::Status::invalid_argument(format!("Invalid address: {e}")))?;

            self.mempool
                .set_reputation(addr, rep.ops_seen, rep.ops_included);
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ADDRESS_ARR: [u8; 20] = [
        0x11, 0xaB, 0xB0, 0x5d, 0x9A, 0xd3, 0x18, 0xbf, 0x65, 0x65, 0x26, 0x72, 0xB1, 0x3b, 0x1d,
        0xcb, 0x0E, 0x6D, 0x4a, 0x32,
    ];
    const TEST_ADDRESS_STR: &'static str = "0x11aBB05d9Ad318bf65652672B13b1dcB0E6D4a32";

    use crate::common::protos::op_pool::{self, Reputation};
    use crate::op_pool::events::NewBlockEvent;
    use crate::op_pool::mempool::PoolOperation;

    #[test]
    fn test_check_entry_point() {
        let entry_pt_addr = TEST_ADDRESS_STR.parse().unwrap();
        let result = OpPoolImpl::<MockMempool>::check_entry_point(&TEST_ADDRESS_ARR, entry_pt_addr);
        assert_eq!(result.unwrap(), ());
    }

    #[tokio::test]
    async fn test_add_op_fails_with_mismatch_entry_point() {
        let oppool = given_oppool();
        let request = Request::new(AddOpRequest {
            entry_point: [0; 20].to_vec(),
            op: None,
        });

        let result = oppool.add_op(request).await;

        assert!(result.is_err());
        let result = result.unwrap_err();
        assert_eq!(result.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_add_op_fails_with_null_uop() {
        let oppool = given_oppool();
        let request = Request::new(AddOpRequest {
            entry_point: TEST_ADDRESS_ARR.to_vec(),
            op: None,
        });

        let result = oppool.add_op(request).await;

        assert!(result.is_err());
        let result = result.unwrap_err();
        assert_eq!(result.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_add_op_fails_with_bad_proto_op() {
        let oppool = given_oppool();
        let request = Request::new(AddOpRequest {
            entry_point: TEST_ADDRESS_ARR.to_vec(),
            op: Some(op_pool::MempoolOp::default()),
        });

        let result = oppool.add_op(request).await;

        assert!(result.is_err());
        let result = result.unwrap_err();
        assert_eq!(result.code(), tonic::Code::InvalidArgument);
    }

    fn given_oppool() -> OpPoolImpl<MockMempool> {
        OpPoolImpl::<MockMempool>::new(1.into(), MockMempool::default().into())
    }

    pub struct MockMempool {
        entry_point: Address,
    }

    impl Default for MockMempool {
        fn default() -> Self {
            Self {
                entry_point: TEST_ADDRESS_ARR.into(),
            }
        }
    }

    impl Mempool for MockMempool {
        fn entry_point(&self) -> Address {
            self.entry_point
        }

        fn on_new_block(&self, _event: &NewBlockEvent) {}

        fn add_operation(
            &self,
            _origin: OperationOrigin,
            _opp: PoolOperation,
        ) -> anyhow::Result<H256> {
            Ok(H256::zero())
        }

        fn add_operations(
            &self,
            _origin: OperationOrigin,
            _operations: impl IntoIterator<Item = PoolOperation>,
        ) -> Vec<anyhow::Result<H256>> {
            vec![]
        }

        fn remove_operations<'a>(&self, _hashes: impl IntoIterator<Item = &'a H256>) {}

        fn best_operations(&self, _max: usize) -> Vec<Arc<PoolOperation>> {
            vec![]
        }

        fn clear(&self) {}

        fn dump_reputation(&self) -> Vec<Reputation> {
            vec![]
        }

        fn set_reputation(&self, _address: Address, _ops_seenn: u64, _ops_included: u64) {}
    }
}
