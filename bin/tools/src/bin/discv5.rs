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

use std::net::Ipv4Addr;

use discv5::{
    enr,
    enr::{CombinedKey, NodeId},
    socket::ListenConfig,
    Discv5, Discv5ConfigBuilder, Enr,
};

const BOOT_ENR: &str = "enr:-KS4QCQ532T4aeH41TZSa_FrI6zg0Jf9WpiZ1Rw132AOnaq1TOXR_39a_waEPSKnO3KtDUDm7ZyuWoPck98muyJfoFYFgmlkgnY0gmlwhCOy3eCPbWVtcG9vbF9zdWJuZXRziAAAAAAAAAAAiXNlY3AyNTZrMaEDqEoI-drfPYvv-nb7T2cPA_g18xcEijBBdlW4tZ8sZteDdGNwghDxg3VkcIIQ8Q";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let enr_key = CombinedKey::generate_secp256k1();
    let enr = enr::EnrBuilder::new("v4").build(&enr_key).unwrap();

    let listen_config = ListenConfig::Ipv4 {
        ip: Ipv4Addr::UNSPECIFIED,
        port: 9000,
    };

    let config = Discv5ConfigBuilder::new(listen_config).build();

    let mut discv5: Discv5 = Discv5::new(enr, enr_key, config).unwrap();

    let boot_enr: Enr = BOOT_ENR.parse().unwrap();
    discv5.add_enr(boot_enr).unwrap();

    discv5.start().await.unwrap();

    let found_nodes = discv5.find_node(NodeId::random()).await.unwrap();
    println!("Found nodes: {:?}", found_nodes);

    for node in found_nodes {
        println!("Pinging node: {:?}", node);
        let pong = discv5.send_ping(node).await.unwrap();
        println!("Pong: {:?}", pong);
    }

    Ok(())
}
