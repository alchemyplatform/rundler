use dotenv::dotenv;
use rundler_rundler::common::{dev::DevClients, eth};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv()?;
    let clients = DevClients::new_from_env()?;
    let DevClients {
        wallet,
        entry_point,
        bundler_client,
        ..
    } = &clients;

    // simply call the nonce method multiple times
    for i in 0..10 {
        println!("Sending op {i}");
        let op = clients.new_wallet_op(wallet.nonce(), 0.into()).await?;
        let call = entry_point.handle_ops(vec![op], bundler_client.address());
        eth::await_mined_tx(call.send(), "send user operation").await?;
    }

    Ok(())
}
