use super::server::start_grpc;

pub async fn run() -> Result<(), anyhow::Error> {
    // TODO: catch errors, wait for gRPC to start.
    tokio::spawn(start_grpc("127.0.0.1::50051".parse()?));
    Ok(())
}
