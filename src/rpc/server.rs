use std::env;

use crate::common::protos::op_pool::AddOpRequest;
use crate::common::protos::op_pool::UserOperation as GrpcUserOperation;
use crate::common::types::UserOperation;
use ethers::types::Address;
use jsonrpsee::core::Error as RpcError;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::ServerBuilder;
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
            entry_point: entry_point.as_bytes().to_vec(),
        };
        todo!()
    }
}

pub async fn start_jsonrpc() -> anyhow::Result<()> {
    let port: u16 = env::var("JSONRPC_PORT")
        .as_deref()
        .unwrap_or("8000")
        .parse()?;
    let addr = format!("127.0.0.1:{port}");
    let server = ServerBuilder::default().build(addr).await?;
    let addr = server.local_addr()?;
    println!("Starting JSONRPC at {addr}");
    let handle = server.start(RpcImpl.into_rpc())?;
    handle.stopped().await;
    Ok(())
}
