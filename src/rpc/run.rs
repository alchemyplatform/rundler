use super::server::start_jsonrpc;

pub async fn run() -> Result<(), anyhow::Error> {
    start_jsonrpc().await?;
    Ok(())
}
