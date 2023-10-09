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

use discv5::{enr::CombinedPublicKey, Enr};
use futures::StreamExt;
use libp2p::{
    core::upgrade,
    identify,
    identity::{secp256k1, Keypair, PublicKey},
    multiaddr::Protocol,
    noise, ping,
    swarm::{keep_alive, NetworkBehaviour, SwarmBuilder, SwarmEvent},
    tcp, Multiaddr, PeerId, Transport,
};

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    keep_alive: keep_alive::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let local_key = secp256k1::Keypair::generate();
    let local_key: Keypair = local_key.into();
    let local_peer_id = PeerId::from(local_key.public());

    let transport = tcp::tokio::Transport::default()
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(
            noise::Config::new(&local_key).expect("Signing libp2p-noise static DH keypair failed."),
        )
        .multiplex(libp2p::yamux::Config::default())
        .boxed();

    let behaviour = MyBehaviour {
        keep_alive: keep_alive::Behaviour,
        ping: ping::Behaviour::new(ping::Config::new()),
        identify: identify::Behaviour::new(identify::Config::new(
            "/ipfs/0.1.0".into(),
            local_key.public(),
        )),
    };

    let mut swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id).build();

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    for l in swarm.listeners() {
        println!("Listening on {:?}", l);
    }

    if let Some(addr) = std::env::args().nth(1) {
        let remote: Multiaddr = addr.parse().unwrap();
        swarm.dial(remote)?;
        println!("Dialed {addr}")
    }

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
            SwarmEvent::Behaviour(event) => println!("{event:?}"),
            _ => {}
        }
    }
}

// -----------------------
// copied from lighthouse
pub trait EnrExt {
    fn peer_id(&self) -> PeerId;

    fn multiaddr(&self) -> Vec<Multiaddr>;
}
impl EnrExt for Enr {
    fn peer_id(&self) -> PeerId {
        self.public_key().as_peer_id()
    }
    fn multiaddr(&self) -> Vec<Multiaddr> {
        let mut multiaddrs: Vec<Multiaddr> = Vec::new();
        if let Some(ip) = self.ip4() {
            if let Some(udp) = self.udp4() {
                let mut multiaddr: Multiaddr = ip.into();
                multiaddr.push(Protocol::Udp(udp));
                multiaddrs.push(multiaddr);
            }
        }
        multiaddrs
    }
}

pub trait CombinedKeyPublicExt {
    fn as_peer_id(&self) -> PeerId;
}

impl CombinedKeyPublicExt for CombinedPublicKey {
    fn as_peer_id(&self) -> PeerId {
        match self {
            Self::Secp256k1(pk) => {
                let pk_bytes = pk.to_sec1_bytes();
                let libp2p_pk: PublicKey = secp256k1::PublicKey::try_from_bytes(&pk_bytes)
                    .expect("valid public key")
                    .into();
                PeerId::from_public_key(&libp2p_pk)
            }
            Self::Ed25519(_) => {
                panic!("Ed25519 is not supported yet");
            }
        }
    }
}
