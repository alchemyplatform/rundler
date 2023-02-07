use alchemy_bundler::{bundler, op_pool, rpc};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    op_pool::run().await?;
    bundler::run().await?;
    rpc::run().await?;
    Ok(())
}
