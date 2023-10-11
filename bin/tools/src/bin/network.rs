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

use std::net::SocketAddr;

use clap::Parser;
use rundler_network::{Config as NetworkConfig, Network};
use tokio::sync::mpsc;

const PRIVATE_KEY: &str = "b0ddfec7d365b4599ff8367e960f8c4890364f99e2151beac352338cc0cfe1bc";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    let private_key = if cli.bootnode.is_none() {
        println!("Starting as a bootnode");
        PRIVATE_KEY.into()
    } else {
        println!("Starting as a regular node");
        let enr_key = discv5::enr::CombinedKey::generate_secp256k1();
        hex::encode(enr_key.encode())
    };

    let bootnodes = cli
        .bootnode
        .map(|b| vec![b.parse().expect("invalid bootnode")])
        .unwrap_or_default();
    let listen_address: SocketAddr = format!("127.0.0.1:{}", cli.port).parse()?;

    let config = NetworkConfig {
        private_key,
        listen_address,
        bootnodes,
        ..Default::default()
    };

    let (_, action_recv) = mpsc::unbounded_channel();
    let (event_send, _) = mpsc::unbounded_channel();

    println!("Config: {:?}", config);
    let network = Network::new(config, event_send, action_recv).await?;
    println!("ENR: {}", network.enr());

    network.run().await?;
    Ok(())
}

#[derive(Debug, Parser)]
#[clap(name = "rundler network tester")]
struct Cli {
    /// The port used to listen on all interfaces
    #[clap(short)]
    port: u16,

    #[clap(short)]
    bootnode: Option<String>,
}
