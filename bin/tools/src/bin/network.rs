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

use std::{net::SocketAddr, time::Duration};

use clap::Parser;
use rundler_network::{Config as NetworkConfig, Network, RpcNetworkConfig};

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
        network_config: RpcNetworkConfig {
            max_chunk_size: 1048576,
            request_timeout: Duration::from_secs(10),
            ttfb_timeout: Duration::from_secs(5),
            connection_keep_alive: Duration::from_secs(60),
        },
        target_num_peers: 1,
        ping_interval: Duration::from_secs(10),
        status_interval: Duration::from_secs(10),
        tick_interval: Duration::from_secs(1),
    };

    println!("Config: {:?}", config);
    let network = Network::new(config).await?;
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
