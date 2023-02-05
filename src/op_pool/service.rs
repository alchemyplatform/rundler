use crate::common::protos::op_pool::op_pool_server::OpPool;
use crate::common::protos::op_pool::{AddOpRequest, AddOpResponse};
use tonic::{async_trait, Request, Response};

pub struct OpPoolImpl;

#[async_trait]
impl OpPool for OpPoolImpl {
    async fn add_op(
        &self,
        _request: Request<AddOpRequest>,
    ) -> tonic::Result<Response<AddOpResponse>> {
        Ok(Response::new(AddOpResponse::default()))
    }
}
