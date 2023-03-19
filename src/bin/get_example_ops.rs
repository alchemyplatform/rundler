use alchemy_bundler::common::dev::DevClients;
use dotenv::dotenv;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv()?;
    let clients = DevClients::new_from_env()?;
    // We'll make operations that call the entry point's addStake.
    let op = clients
        .new_wallet_op(clients.entry_point.add_stake(1), 1.into())
        .await?;
    println!("User operation to make wallet call EntryPoint#addStake():");
    println!();
    println!("{}", serde_json::to_string_pretty(&op)?);
    let op = clients
        .new_wallet_op_with_paymaster(clients.entry_point.add_stake(1), 1.into())
        .await?;
    println!();
    println!("User operation to make wallet call EntryPoint#addStake() with paymaster:");
    println!();
    println!("{}", serde_json::to_string_pretty(&op)?);
    Ok(())
}
