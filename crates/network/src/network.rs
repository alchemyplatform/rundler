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

use discv5::Enr;
use ethers::types::H256;
use futures::StreamExt;
use libp2p::{
    core,
    core::{transport::upgrade, ConnectedPoint},
    identify,
    identity::{secp256k1, Keypair},
    noise,
    swarm::{keep_alive, SwarmBuilder, SwarmEvent},
    tcp, Multiaddr, PeerId, Swarm, Transport,
};
use tracing::{debug, error, info};

use super::{
    behaviour::{Behaviour, BehaviourEvent},
    discovery::{
        self,
        enr::{build_enr, EnrExt},
    },
    peer_manager, Result,
};
use crate::rpc::{
    self,
    message::{
        ErrorKind, Ping, Pong, Request, Response, ResponseError, Status, MAX_OPS_PER_REQUEST,
    },
    NetworkConfig,
};

#[derive(Debug)]
pub struct Config {
    pub private_key: String,
    pub listen_address: SocketAddr,
    pub bootnodes: Vec<Enr>,
    pub network_config: NetworkConfig,
    pub target_num_peers: usize,
    pub ping_interval: Duration,
    pub status_interval: Duration,
    pub tick_interval: Duration,
}

pub struct Network {
    swarm: Swarm<Behaviour>,
    enr: Enr,
}

impl Network {
    pub async fn new(config: Config) -> Result<Self> {
        let local_key: Keypair = secp256k1::Keypair::from(
            secp256k1::SecretKey::try_from_bytes(&mut hex::decode(&config.private_key).unwrap())
                .unwrap(),
        )
        .into();
        let local_peer_id = PeerId::from(local_key.public());

        let (enr, enr_key) = build_enr(&config);

        let mplex_config = libp2p_mplex::MplexConfig::new();
        let yamux_config = libp2p::yamux::Config::default();

        let transport = tcp::tokio::Transport::default()
            .upgrade(upgrade::Version::V1Lazy)
            .authenticate(noise::Config::new(&local_key).unwrap())
            .multiplex(core::upgrade::SelectUpgrade::new(
                yamux_config,
                mplex_config,
            ))
            .boxed();

        let discovery = discovery::Behaviour::new(&config, enr.clone(), enr_key).await?;
        let peer_manager = peer_manager::Behaviour::new(&config);
        let rpc = rpc::Behaviour::new(config.network_config.clone());

        let behaviour = Behaviour {
            keep_alive: keep_alive::Behaviour,
            rpc,
            discovery,
            identify: identify::Behaviour::new(identify::Config::new(
                "erc4337/0.1.0".into(),
                local_key.public(),
            )),
            peer_manager,
        };

        let multi_addr: Multiaddr = match config.listen_address {
            SocketAddr::V4(addr) => format!("/ip4/{}/tcp/{}", addr.ip(), addr.port()),
            SocketAddr::V6(addr) => format!("/ip6/{}/tcp/{}", addr.ip(), addr.port()),
        }
        .try_into()
        .unwrap();

        let mut swarm =
            SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id).build();

        swarm.listen_on(multi_addr).unwrap();

        for bootnode in config.bootnodes {
            for multi_addr in bootnode.multiaddr() {
                if multi_addr.to_string().contains("udp") {
                    continue;
                }
                debug!("Dialing bootnode multiaddr {:?}", multi_addr);
                swarm.dial(multi_addr).unwrap();
            }
        }

        Ok(Self { swarm, enr })
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            if let Some(event) = self.swarm.next().await {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => info!("Listening on {address:?}"),
                    SwarmEvent::Behaviour(BehaviourEvent::Discovery(e)) => {
                        self.on_discovery_event(e)
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Identify(e)) => debug!("Identify: {e:?}"),
                    SwarmEvent::Behaviour(BehaviourEvent::PeerManager(e)) => {
                        self.on_peer_manager_event(e)
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Rpc(e)) => self.on_rpc_event(e),
                    SwarmEvent::ConnectionEstablished {
                        peer_id, endpoint, ..
                    } => {
                        self.on_connection_established(peer_id, endpoint);
                    }
                    e => debug!("Unhandled event: {:?}", e),
                }
            }
        }
    }

    pub fn enr(&self) -> &Enr {
        &self.enr
    }

    fn on_connection_established(&mut self, peer: PeerId, endpoint: ConnectedPoint) {
        info!(
            "Connection established with peer {:?} at endpoint {:?}",
            peer, endpoint
        );
        match endpoint {
            ConnectedPoint::Dialer { .. } => {
                self.send_status(peer);
            }
            ConnectedPoint::Listener { .. } => {}
        }
    }

    fn on_discovery_event(&mut self, event: discovery::DiscoveredPeers) {
        if !event.peers.is_empty() {
            self.swarm
                .behaviour_mut()
                .peer_manager
                .discovered_peers(event.peers);
        }
    }

    fn on_peer_manager_event(&mut self, event: peer_manager::Event) {
        match event {
            peer_manager::Event::Ping(peer_id) => {
                self.send_ping(peer_id);
            }
            peer_manager::Event::Status(peer_id) => {
                self.send_status(peer_id);
            }
            peer_manager::Event::Discover(num_peers) => {
                self.swarm.behaviour_mut().discovery.start_query(num_peers);
            }
        }
    }

    fn on_rpc_event(&mut self, event: rpc::Event) {
        match event {
            rpc::Event::Request(peer_id, request_id, request) => match request {
                Request::Status(status) => {
                    debug!("Received status: {:?} from peer {:?}", status, peer_id);
                    self.swarm.behaviour_mut().rpc.send_response(
                        request_id,
                        Ok(Response::Status(Status {
                            // TODO fill this in
                            supported_mempools: vec![ethers::types::H256::random()],
                        })),
                    );
                    self.swarm
                        .behaviour_mut()
                        .peer_manager
                        .status_request(&peer_id);
                }
                Request::Goodbye(_) => {
                    todo!();
                }
                Request::Ping(ping) => {
                    debug!("Received ping: {:?} from peer {:?}", ping, peer_id);
                    self.swarm.behaviour_mut().rpc.send_response(
                        request_id,
                        Ok(Response::Ping(Pong {
                            // TODO fill this in
                            metadata_seq_number: 0,
                        })),
                    );
                    self.swarm
                        .behaviour_mut()
                        .peer_manager
                        .ping_request(&peer_id);
                }
                Request::Metadata => {
                    todo!();
                }
                Request::PooledUserOpHashes(_) => {
                    todo!();
                }
                Request::PooledUserOpsByHash(r) => {
                    if r.hashes.len() > MAX_OPS_PER_REQUEST {
                        // todo notify peer manager
                        self.swarm.behaviour_mut().rpc.send_response(
                            request_id,
                            Err(ResponseError {
                                kind: ErrorKind::InvalidRequest,
                                message: format!(
                                    "Too many hashes in request. Max: {}, Got: {}",
                                    MAX_OPS_PER_REQUEST,
                                    r.hashes.len()
                                ),
                            }),
                        );
                    } else {
                        todo!();
                    }
                }
            },
            rpc::Event::Response(peer_id, _, response) => match response {
                Ok(Response::Status(status)) => {
                    debug!("Received status: {:?} from peer {:?}", status, peer_id);
                    self.swarm
                        .behaviour_mut()
                        .peer_manager
                        .status_response(&peer_id);
                }
                Ok(Response::Ping(pong)) => {
                    debug!("Received pong: {:?} from peer {:?}", pong, peer_id);
                    self.swarm
                        .behaviour_mut()
                        .peer_manager
                        .ping_response(&peer_id);
                }
                Ok(Response::Metadata(_)) => {
                    todo!();
                }
                Ok(Response::PooledUserOpHashes(_)) => {
                    todo!();
                }
                Ok(Response::PooledUserOpsByHash(_)) => {
                    todo!();
                }
                Err(e) => {
                    error!("Received error: {:?}", e);
                    todo!();
                }
            },
        }
    }

    fn send_status(&mut self, peer: PeerId) {
        debug!("Sending status to peer {:?}", peer);
        self.swarm.behaviour_mut().rpc.send_request(
            &peer,
            Request::Status(Status {
                // TODO fill this in
                supported_mempools: vec![H256::random()],
            }),
        );
    }

    fn send_ping(&mut self, peer: PeerId) {
        debug!("Sending ping to peer {:?}", peer);
        self.swarm.behaviour_mut().rpc.send_request(
            &peer,
            Request::Ping(Ping {
                // TODO fill this in
                metadata_seq_number: 0,
            }),
        );
    }
}
