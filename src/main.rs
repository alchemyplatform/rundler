use crate::common::protos::op_pool::op_pool_server::OpPoolServer;
use crate::common::protos::op_pool::OP_POOL_FILE_DESCRIPTOR_SET;
use crate::op_pool::OpPoolImpl;
use crate::rpc::{RpcImpl, RpcServer};
use jsonrpsee::server::ServerBuilder;
use std::env;
use std::net::SocketAddr;
use tonic::transport::Server;

mod common;
mod core;
mod op_pool;
mod rpc;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // TODO: catch errors, wait for gRPC to start.
    tokio::spawn(start_grpc());
    start_jsonrpc().await?;
    Ok(())
}

async fn start_jsonrpc() -> anyhow::Result<()> {
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

async fn start_grpc() -> anyhow::Result<()> {
    let port: u16 = env::var("GRPC_PORT")
        .as_deref()
        .unwrap_or("50051")
        .parse()?;
    let addr: SocketAddr = format!("[::]:{port}").parse()?;
    let op_pool_server = OpPoolServer::new(OpPoolImpl);
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(OP_POOL_FILE_DESCRIPTOR_SET)
        .build()?;
    println!("Starting gRPC on port {port}");
    Server::builder()
        .add_service(op_pool_server)
        .add_service(reflection_service)
        .serve(addr)
        .await?;
    Ok(())
}
