// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

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
