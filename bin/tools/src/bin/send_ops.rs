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
use rundler_dev::{self, DevClients};

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
        rundler_dev::await_mined_tx(call.send(), "send user operation").await?;
    }

    Ok(())
}
