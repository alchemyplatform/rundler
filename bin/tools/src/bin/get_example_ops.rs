use dotenv::dotenv;
use rundler_dev::DevClients;
use rundler_rpc::RpcUserOperation;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv()?;
    let clients = DevClients::new_from_env()?;
    // We'll make operations that call the entry point's addStake.
    let op = clients
        .new_wallet_op(clients.entry_point.add_stake(1), 1.into())
        .await?;
    println!("User operation to make wallet call EntryPoint#addStake():");
    println!(
        "{}",
        serde_json::to_string(&RpcUserOperation::from(op.clone()))?
    );
    let op = clients
        .new_wallet_op_with_paymaster(clients.entry_point.add_stake(1), 1.into())
        .await?;
    println!();
    println!("User operation to make wallet call EntryPoint#addStake() with paymaster:");
    println!("{}", serde_json::to_string(&RpcUserOperation::from(op))?);
    Ok(())
}
