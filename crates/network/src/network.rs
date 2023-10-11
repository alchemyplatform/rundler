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
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::{
    behaviour::{Behaviour, BehaviourEvent},
    enr::{self, EnrExt},
    error::Result,
    rpc::{
        self,
        message::{
            ErrorKind, Metadata, Ping, Pong, PooledUserOpHashesRequest, PooledUserOpHashesResponse,
            PooledUserOpsByHashRequest, PooledUserOpsByHashResponse, Request, Response,
            ResponseError, Status, MAX_OPS_PER_REQUEST,
        },
        ConnectionConfig,
    },
};

/// Configuration for the network
#[derive(Debug)]
pub struct Config {
    /// private key in hex for ENR
    pub private_key: String,
    /// address to listen on
    pub listen_address: SocketAddr,
    /// bootnodes to connect to
    pub bootnodes: Vec<Enr>,
    /// configuration for network connections
    pub network_config: ConnectionConfig,
    /// supported mempools
    pub supported_mempools: Vec<H256>,
    /// metadata sequence number
    pub metadata_seq_number: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            private_key: String::default(),
            listen_address: SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                0,
            ),
            bootnodes: vec![],
            network_config: ConnectionConfig::default(),
            supported_mempools: vec![],
            metadata_seq_number: 0,
        }
    }
}

/// Requests available to application
#[derive(Debug)]
pub enum AppRequest {
    /// Pooled user op hashes request
    PooledUserOpHashes(PooledUserOpHashesRequest),
    /// Pooled user ops by hash request
    PooledUserOpsByHash(PooledUserOpsByHashRequest),
}

/// Responses available to application
#[derive(Debug)]
pub enum AppResponse {
    /// Pooled user op hashes response
    PooledUserOpHashes(PooledUserOpHashesResponse),
    /// Pooled user ops by hash response
    PooledUserOpsByHash(PooledUserOpsByHashResponse),
}

/// Result of application request
pub type AppResponseResult = std::result::Result<AppResponse, ResponseError>;

/// Request id for application
///
/// Use to associate requests from the application with responses
/// from the network.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AppRequestId(pub u64);

/// Request id for the network
///
/// Use to associate requests from the network with responses
/// from the application.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PeerRequestId(pub u64);

/// Events emitted by the network
#[derive(Debug)]
pub enum Event {
    /// Peer connected, can send requests
    PeerConnected(PeerId),
    /// Peer disconnected, can no longer send requests
    PeerDisconnected(PeerId),
    /// Network shutdown complete
    ShutdownComplete,
    /// Request from peer
    RequestReceived(PeerId, PeerRequestId, AppRequest),
    /// Response from peer
    ResponseReceived(PeerId, AppRequestId, AppResponseResult),
    // TODO: gossip messages will go here
}

/// Actions sent to the network
#[derive(Debug)]
pub enum Action {
    /// Shutdown the network, say goodbye to peers
    ///
    /// This will eventually cause the network to shutdown after goodbye
    /// messages are sent to all peers. The network will send a
    /// `ShutdownComplete` event when shutdown is complete.
    Shutdown,
    /// Request to send to peer
    Request(PeerId, AppRequestId, AppRequest),
    /// Response to send to peer
    Response(PeerRequestId, AppResponseResult),
    // TODO: gossip messages will go here
}

// Requests sent by the network
#[derive(Debug)]
pub(crate) enum NetworkRequestId {
    // Internal requests from the network
    Internal,
    // External requests from the application
    App(AppRequestId),
}

/// ERC-4337 P2P network
pub struct Network {
    swarm: Swarm<Behaviour>,
    enr: Enr,
    config: Config,

    event_sender: mpsc::UnboundedSender<Event>,
    action_recv: mpsc::UnboundedReceiver<Action>,
}

impl Network {
    /// Create a new network
    pub async fn new(
        config: Config,
        event_sender: mpsc::UnboundedSender<Event>,
        action_recv: mpsc::UnboundedReceiver<Action>,
    ) -> Result<Self> {
        let local_key: Keypair = secp256k1::Keypair::from(
            secp256k1::SecretKey::try_from_bytes(&mut hex::decode(&config.private_key).unwrap())
                .unwrap(),
        )
        .into();
        let local_peer_id = PeerId::from(local_key.public());

        let (enr, _enr_key) = enr::build_enr(&config);

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

        let rpc = rpc::Behaviour::new(config.network_config.clone());

        let behaviour = Behaviour {
            keep_alive: keep_alive::Behaviour,
            rpc,
            identify: identify::Behaviour::new(identify::Config::new(
                "erc4337/0.1.0".into(),
                local_key.public(),
            )),
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

        for bootnode in &config.bootnodes {
            for multi_addr in bootnode.multiaddr() {
                if multi_addr.to_string().contains("udp") {
                    continue;
                }
                debug!("Dialing bootnode multiaddr {:?}", multi_addr);
                swarm.dial(multi_addr).unwrap();
            }
        }

        Ok(Self {
            swarm,
            enr,
            config,
            event_sender,
            action_recv,
        })
    }

    /// Run the network. Consumes self.
    pub async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                Some(action) = self.action_recv.recv() => {
                    match action {
                        Action::Request(peer_id, request_id, req) => {
                            self.swarm.behaviour_mut().rpc.send_request(
                                &peer_id,
                                NetworkRequestId::App(request_id),
                                req.into(),
                            );
                        },
                        Action::Response(request_id, req) => {
                            self.swarm.behaviour_mut().rpc.send_response(
                                request_id,
                                req.map(Into::into),
                            );
                        },
                        Action::Shutdown => {
                            info!("Shutting down network");

                            // TODO: say goodbye to peers, wait for requests to be sent

                            self.send_event(Event::ShutdownComplete);
                            return Ok(());
                        }
                    }
                },
                Some(swarm_event) = self.swarm.next() => {
                    match swarm_event {
                        SwarmEvent::NewListenAddr { address, .. } => info!("Listening on {address:?}"),
                        SwarmEvent::Behaviour(BehaviourEvent::Identify(e)) => debug!("Identify: {e:?}"),
                        SwarmEvent::Behaviour(BehaviourEvent::Rpc(e)) => self.on_rpc_event(e),
                        SwarmEvent::ConnectionEstablished {
                            peer_id, endpoint, ..
                        } => {
                            self.on_connection_established(peer_id, endpoint);
                        }
                        SwarmEvent::ConnectionClosed {
                            peer_id, endpoint, ..
                        } => {
                            debug!("Connection closed with peer {:?} at endpoint {:?}", peer_id, endpoint);
                            self.send_event(Event::PeerDisconnected(peer_id));
                        }
                        e => debug!("Unhandled event: {:?}", e),
                    }
                },
            }
        }
    }

    /// Get the ENR of the node after constructing
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
                self.request_status(peer);
            }
            ConnectedPoint::Listener { .. } => {}
        }
        self.send_event(Event::PeerConnected(peer));
    }

    fn on_rpc_event(&mut self, event: rpc::Event) {
        match event {
            rpc::Event::Request(peer_id, request_id, request) => match request {
                Request::Status(status) => {
                    debug!("Received status: {:?} from peer {:?}", status, peer_id);
                    self.swarm.behaviour_mut().rpc.send_response(
                        request_id,
                        Ok(Response::Status(Status {
                            supported_mempools: self.config.supported_mempools.clone(),
                        })),
                    );
                    // Notify peer manager to update status
                }
                Request::Goodbye(_) => {
                    // Notify peer manager to remove peer
                    todo!();
                }
                Request::Ping(ping) => {
                    debug!("Received ping: {:?} from peer {:?}", ping, peer_id);
                    self.swarm.behaviour_mut().rpc.send_response(
                        request_id,
                        Ok(Response::Ping(Pong {
                            metadata_seq_number: self.config.metadata_seq_number,
                        })),
                    );
                    // Notify peer manager to update ping time
                }
                Request::Metadata => {
                    self.swarm.behaviour_mut().rpc.send_response(
                        request_id,
                        Ok(Response::Metadata(Metadata {
                            seq_number: self.config.metadata_seq_number,
                        })),
                    );
                }
                Request::PooledUserOpHashes(r) => {
                    self.send_event(Event::RequestReceived(
                        peer_id,
                        request_id,
                        AppRequest::PooledUserOpHashes(r),
                    ));
                }
                Request::PooledUserOpsByHash(r) => {
                    if r.hashes.len() > MAX_OPS_PER_REQUEST {
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
                        // Notify peer manager to update metadata
                    } else {
                        // Send request to network manager
                        self.send_event(Event::RequestReceived(
                            peer_id,
                            request_id,
                            AppRequest::PooledUserOpsByHash(r),
                        ));
                    }
                }
            },
            rpc::Event::Response(peer_id, request_id, response) => match response {
                Ok(Response::Status(status)) => {
                    debug!("Received status: {:?} from peer {:?}", status, peer_id);
                    // Notify peer manager to update status
                }
                Ok(Response::Ping(pong)) => {
                    debug!("Received pong: {:?} from peer {:?}", pong, peer_id);
                    // Notify peer manager to update ping time
                }
                Ok(Response::Metadata(_)) => {
                    todo!();
                    // Notify peer manager to update metadata
                }
                Ok(Response::PooledUserOpHashes(r)) => {
                    let NetworkRequestId::App(id) = request_id else {
                        error!(
                            "Received unexpected request id for PooledUserOpHashes: {:?}",
                            request_id
                        );
                        return;
                    };

                    // Send response to network manager
                    self.send_event(Event::ResponseReceived(
                        peer_id,
                        id,
                        Ok(AppResponse::PooledUserOpHashes(r)),
                    ));
                }
                Ok(Response::PooledUserOpsByHash(r)) => {
                    let NetworkRequestId::App(id) = request_id else {
                        error!(
                            "Received unexpected request id for PooledUserOpsByHash: {:?}",
                            request_id
                        );
                        return;
                    };

                    // Send response to network manager
                    self.send_event(Event::ResponseReceived(
                        peer_id,
                        id,
                        Ok(AppResponse::PooledUserOpsByHash(r)),
                    ));
                }
                Err(e) => {
                    error!("Received response error: {:?}", e);
                    // If external request, return error to network manager
                    if let NetworkRequestId::App(id) = request_id {
                        self.send_event(Event::ResponseReceived(peer_id, id, Err(e)));
                    }
                }
            },
        }
    }

    fn send_event(&mut self, event: Event) {
        if let Err(e) = self.event_sender.send(event) {
            error!("Failed to send event to application: {:?}", e);
        }
    }

    // A status request is sent in response to a new dialed connection
    // and at a regular interval to all peers.
    fn request_status(&mut self, peer: PeerId) {
        debug!("Requesting status from peer {:?}", peer);
        self.swarm.behaviour_mut().rpc.send_request(
            &peer,
            NetworkRequestId::Internal,
            Request::Status(Status {
                supported_mempools: self.config.supported_mempools.clone(),
            }),
        );
    }

    // A metadata request is sent when a ping/pong is received with a different
    // metadata sequence number than the local cached version.
    fn _request_metadata(&mut self, peer: PeerId) {
        debug!("Sending metadata request to peer {:?}", peer);
        self.swarm.behaviour_mut().rpc.send_request(
            &peer,
            NetworkRequestId::Internal,
            Request::Metadata,
        );
    }

    // A ping request is sent at a regular interval to all peers.
    fn _ping(&mut self, peer: PeerId) {
        debug!("Sending ping to peer {:?}", peer);
        self.swarm.behaviour_mut().rpc.send_request(
            &peer,
            NetworkRequestId::Internal,
            Request::Ping(Ping {
                metadata_seq_number: self.config.metadata_seq_number,
            }),
        );
    }
}

impl From<AppRequest> for Request {
    fn from(req: AppRequest) -> Self {
        match req {
            AppRequest::PooledUserOpHashes(r) => Request::PooledUserOpHashes(r),
            AppRequest::PooledUserOpsByHash(r) => Request::PooledUserOpsByHash(r),
        }
    }
}

impl From<AppResponse> for Response {
    fn from(res: AppResponse) -> Self {
        match res {
            AppResponse::PooledUserOpHashes(r) => Response::PooledUserOpHashes(r),
            AppResponse::PooledUserOpsByHash(r) => Response::PooledUserOpsByHash(r),
        }
    }
}
