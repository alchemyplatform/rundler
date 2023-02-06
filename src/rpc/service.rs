use crate::common::protos::op_pool::AddOpRequest;
use crate::common::protos::op_pool::UserOperation as GrpcUserOperation;
use crate::common::types::UserOperation;
use ethers::types::Address;
use jsonrpsee::core::Error as RpcError;
use jsonrpsee::proc_macros::rpc;
use tonic::async_trait;

// TODO: Are we satisfied with the error messages these stubs generate?
// If not, we might have to parse params by hand or write our own helpers.

#[rpc(server, namespace = "eth")]
pub trait Rpc {
    #[method(name = "sendUserOperation")]
    async fn send_user_operation(
        &self,
        op: UserOperation,
        entry_point: Address,
    ) -> Result<String, RpcError>;
}

pub struct RpcImpl;

#[async_trait]
impl RpcServer for RpcImpl {
    async fn send_user_operation(
        &self,
        op: UserOperation,
        entry_point: Address,
    ) -> Result<String, RpcError> {
        let _ = AddOpRequest {
            op: Some(GrpcUserOperation::from(&op)),
            entrypoint: entry_point.as_bytes().to_vec(),
        };
        todo!()
    }
}
