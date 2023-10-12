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

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use discv5::Enr;
use ethers::types::H256;
use futures::StreamExt;
use libp2p::{
    core,
    core::{transport::upgrade, ConnectedPoint},
    gossipsub::{self, MessageAcceptance, MessageId, PublishError},
    identify,
    identity::{secp256k1, Keypair},
    noise,
    swarm::{keep_alive, DialError, SwarmBuilder, SwarmEvent},
    tcp, Multiaddr, PeerId, Swarm, Transport,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::{
    behaviour::{Behaviour, BehaviourEvent, GossipSub},
    discovery::{
        self,
        enr::{self, EnrExt},
    },
    error::Result,
    gossip::{self, message::Message as GossipMessage, topic, topic::Topic, SnappyTransform},
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
    /// tick interval for updating internal state
    pub tick_interval: std::time::Duration,
    /// target number of peers to connect to
    pub target_num_peers: usize,
    /// max size of gossip messages
    pub gossip_max_size: usize,
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
            tick_interval: std::time::Duration::from_secs(1),
            target_num_peers: 16,
            gossip_max_size: 1024 * 1024,
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
    PeerConnected {
        /// Peer that connected
        peer_id: PeerId,
    },
    /// Peer disconnected, can no longer send requests
    PeerDisconnected {
        /// Peer that disconnected
        peer_id: PeerId,
    },
    /// Network shutdown complete
    ShutdownComplete,
    /// Request from peer
    RequestReceived {
        /// Peer that sent the request
        peer_id: PeerId,
        /// Request ID to associate with response
        request_id: PeerRequestId,
        /// The request
        request: AppRequest,
    },
    /// Response from peer
    ResponseReceived {
        /// Peer that sent the response
        peer_id: PeerId,
        /// Request ID to associate with response
        request_id: AppRequestId,
        /// The response
        response: AppResponseResult,
    },
    /// Gossip messages
    GossipMessage {
        /// Message ID
        id: MessageId,
        /// Peer that sent the message, not necessarily the original author
        peer_id: PeerId,
        /// The mempool id
        mempool_id: H256,
        /// The message
        message: gossip::message::Message,
    },
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
    Request {
        /// Peer to send request to
        peer_id: PeerId,
        /// Request ID to associate with response
        request_id: AppRequestId,
        /// The request
        request: AppRequest,
    },
    /// Response to send to peer
    Response {
        /// Request ID to associate with response
        request_id: PeerRequestId,
        /// The response
        response: AppResponseResult,
    },
    /// Gossip message to send
    GossipMessage {
        /// The mempool ids to gossip on
        mempool_ids: Vec<H256>,
        /// The message to gossip
        message: GossipMessage,
    },
    /// Validate gossip message
    ValidateMessage {
        /// Peer that sent the message, not necessarily the original author
        peer_id: PeerId,
        /// The message ID
        id: MessageId,
        /// Validation result
        result: MessageAcceptance,
    },
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

    // TODO move this to peer manager
    known_peers: HashSet<PeerId>,
    // TODO determine what to do with messages that can't be sent
    // due to insufficient peers. This is to help testing.
    gossip_cache: HashMap<Topic, HashSet<Vec<u8>>>,
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

        let (enr, enr_key) = enr::build_enr(&config);

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

        let transform = SnappyTransform::new(config.gossip_max_size);
        let gossipsub = gossipsub::Behaviour::new_with_transform(
            gossipsub::MessageAuthenticity::Anonymous,
            gossip::gossipsub_config(&config),
            // TODO enable metrics
            None,
            transform,
        )
        .expect("should create gossipsub behaviour");

        let rpc = rpc::Behaviour::new(config.network_config.clone());

        let discovery = discovery::Behaviour::new(&config, enr.clone(), enr_key).await?;

        let behaviour = Behaviour {
            keep_alive: keep_alive::Behaviour,
            gossipsub,
            rpc,
            discovery,
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

        let known_peers = config
            .bootnodes
            .iter()
            .map(|b| b.peer_id())
            .collect::<HashSet<_>>();

        for mempool in &config.supported_mempools {
            for topic in topic::mempool_to_topics(*mempool) {
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&topic.into())
                    .unwrap();
            }
        }

        Ok(Self {
            swarm,
            enr,
            config,
            event_sender,
            action_recv,
            known_peers,
            gossip_cache: HashMap::new(),
        })
    }

    /// Run the network. Consumes self.
    pub async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                Some(action) = self.action_recv.recv() => {
                    match action {
                        Action::Shutdown => {
                            info!("Shutting down network");

                            // TODO: say goodbye to peers, wait for requests to be sent

                            self.send_event(Event::ShutdownComplete);
                            return Ok(());
                        }
                        Action::Request{peer_id, request_id, request} => {
                            self.rpc_mut().send_request(
                                &peer_id,
                                NetworkRequestId::App(request_id),
                                request.into(),
                            );
                        },
                        Action::Response{request_id, response} => {
                            self.rpc_mut().send_response(
                                request_id,
                                response.map(Into::into),
                            );
                        },
                        Action::GossipMessage{mempool_ids, message} => {
                            for mempool in mempool_ids {
                                let topic = message.topic(mempool);
                                debug!("Publishing gossip message on topic {:?}", topic);
                                if let Err(e) = self.gossip_mut().publish(topic, message.clone().encode()) {
                                    error!("Failed to publish gossip message: {:?}", e);

                                    let encoded = message.clone().encode();
                                    let topic = message.topic(mempool);
                                    if let PublishError::InsufficientPeers = e {
                                        if let Some(c) = self.gossip_cache.get_mut(&topic) {
                                            c.insert(encoded);
                                        } else {
                                            let mut c = HashSet::new();
                                            c.insert(encoded);
                                            self.gossip_cache.insert(topic, c);
                                        }
                                    }

                                }
                            }
                        },
                        Action::ValidateMessage{peer_id, id, result} => {
                            if let Err(e) = self.gossip_mut().report_message_validation_result(
                                &id,
                                &peer_id,
                                result,
                            ) {
                                error!("Failed to report message validation result: {:?}", e);
                            }
                        },
                    }
                },
                Some(swarm_event) = self.swarm.next() => {
                    match swarm_event {
                        SwarmEvent::NewListenAddr { address, .. } => info!("Listening on {address:?}"),
                        SwarmEvent::Behaviour(BehaviourEvent::Identify(e)) => debug!("Identify: {e:?}"),
                        SwarmEvent::Behaviour(BehaviourEvent::Discovery(discovered_peers)) => {
                            for peer in discovered_peers.peers {
                                if self.known_peers.insert(peer.peer_id()) {
                                    debug!("Discovered peer {:?}", peer);
                                    if let Err(e) = dial_tcp(&mut self.swarm, &peer) {
                                        error!("Failed to dial peer {:?}: {:?}", peer, e);
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(e)) => self.on_gossipsub_event(e),
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
                            self.send_event(Event::PeerDisconnected{peer_id});
                            self.known_peers.remove(&peer_id);
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

    fn on_connection_established(&mut self, peer_id: PeerId, endpoint: ConnectedPoint) {
        info!(
            "Connection established with peer {:?} at endpoint {:?}",
            peer_id, endpoint
        );
        match endpoint {
            ConnectedPoint::Dialer { .. } => {
                self.request_status(peer_id);
            }
            ConnectedPoint::Listener { .. } => {}
        }
        self.send_event(Event::PeerConnected { peer_id });

        // TODO peer manager
        // peers can discover us first and connect to us
        if self.known_peers.insert(peer_id) {
            debug!("Discovered peer {:?}", peer_id);
        }
    }

    fn on_gossipsub_event(&mut self, event: gossipsub::Event) {
        match event {
            gossipsub::Event::Message {
                propagation_source: peer_id,
                message,
                message_id,
            } => {
                let Ok(topic) = message.topic.try_into() else {
                    error!("Received message on unknown topic");
                    return;
                };
                match GossipMessage::decode(&topic, message.data) {
                    Ok(message) => {
                        debug!("Received gossip message: {:?}", message);
                        self.send_event(Event::GossipMessage {
                            id: message_id,
                            peer_id,
                            mempool_id: topic.mempool_id(),
                            message,
                        });
                    }
                    Err(e) => {
                        error!("Failed to decode gossip message: {:?}", e);
                        if let Err(e) = self.gossip_mut().report_message_validation_result(
                            &message_id,
                            &peer_id,
                            MessageAcceptance::Reject,
                        ) {
                            error!("Failed to report message validation result: {:?}", e);
                        }
                    }
                }
            }
            gossipsub::Event::Subscribed { topic, .. } => {
                debug!("Subscribed to topic {:?}", topic);
                let topic = match Topic::try_from(topic) {
                    Ok(topic) => topic,
                    Err(e) => {
                        error!("Failed to decode topic: {:?}", e);
                        return;
                    }
                };
                if let Some(c) = self.gossip_cache.remove(&topic) {
                    for message in c {
                        if let Err(e) = self.gossip_mut().publish(topic.clone(), message) {
                            error!("Failed to publish gossip message: {:?}", e);
                        }
                    }
                }
            }
            e => debug!("Unhandled gossipsub event: {:?}", e),
        }
    }

    fn on_rpc_event(&mut self, event: rpc::Event) {
        match event {
            rpc::Event::Request(peer_id, request_id, request) => match request {
                Request::Status(status) => {
                    debug!("Received status: {:?} from peer {:?}", status, peer_id);
                    let response = Ok(Response::Status(Status {
                        supported_mempools: self.config.supported_mempools.clone(),
                    }));
                    self.rpc_mut().send_response(request_id, response);
                    // Notify peer manager to update status
                }
                Request::Goodbye(_) => {
                    // Notify peer manager to remove peer
                    todo!();
                }
                Request::Ping(ping) => {
                    debug!("Received ping: {:?} from peer {:?}", ping, peer_id);
                    let response = Ok(Response::Ping(Pong {
                        metadata_seq_number: self.config.metadata_seq_number,
                    }));
                    self.rpc_mut().send_response(request_id, response);
                    // Notify peer manager to update ping time
                }
                Request::Metadata => {
                    let response = Ok(Response::Metadata(Metadata {
                        seq_number: self.config.metadata_seq_number,
                    }));
                    self.rpc_mut().send_response(request_id, response);
                }
                Request::PooledUserOpHashes(r) => {
                    self.send_event(Event::RequestReceived {
                        peer_id,
                        request_id,
                        request: AppRequest::PooledUserOpHashes(r),
                    });
                }
                Request::PooledUserOpsByHash(r) => {
                    if r.hashes.len() > MAX_OPS_PER_REQUEST {
                        self.rpc_mut().send_response(
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
                        self.send_event(Event::RequestReceived {
                            peer_id,
                            request_id,
                            request: AppRequest::PooledUserOpsByHash(r),
                        });
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
                    let NetworkRequestId::App(request_id) = request_id else {
                        error!(
                            "Received unexpected request id for PooledUserOpHashes: {:?}",
                            request_id
                        );
                        return;
                    };

                    // Send response to network manager
                    self.send_event(Event::ResponseReceived {
                        peer_id,
                        request_id,
                        response: Ok(AppResponse::PooledUserOpHashes(r)),
                    });
                }
                Ok(Response::PooledUserOpsByHash(r)) => {
                    let NetworkRequestId::App(request_id) = request_id else {
                        error!(
                            "Received unexpected request id for PooledUserOpsByHash: {:?}",
                            request_id
                        );
                        return;
                    };

                    // Send response to network manager
                    self.send_event(Event::ResponseReceived {
                        peer_id,
                        request_id,
                        response: Ok(AppResponse::PooledUserOpsByHash(r)),
                    });
                }
                Err(e) => {
                    error!("Received response error: {:?}", e);
                    // If external request, return error to network manager
                    if let NetworkRequestId::App(request_id) = request_id {
                        self.send_event(Event::ResponseReceived {
                            peer_id,
                            request_id,
                            response: Err(e),
                        });
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
    fn request_status(&mut self, peer_id: PeerId) {
        debug!("Requesting status from peer {:?}", peer_id);
        let request = Request::Status(Status {
            supported_mempools: self.config.supported_mempools.clone(),
        });
        self.send_internal_request(peer_id, request)
    }

    // A metadata request is sent when a ping/pong is received with a different
    // metadata sequence number than the local cached version.
    fn _request_metadata(&mut self, peer_id: PeerId) {
        debug!("Sending metadata request to peer {:?}", peer_id);
        self.send_internal_request(peer_id, Request::Metadata)
    }

    // A ping request is sent at a regular interval to all peers.
    fn _ping(&mut self, peer: PeerId) {
        debug!("Sending ping to peer {:?}", peer);
        let request = Request::Ping(Ping {
            metadata_seq_number: self.config.metadata_seq_number,
        });
        self.rpc_mut()
            .send_request(&peer, NetworkRequestId::Internal, request);
    }

    fn gossip_mut(&mut self) -> &mut GossipSub {
        &mut self.swarm.behaviour_mut().gossipsub
    }

    fn rpc_mut(&mut self) -> &mut rpc::Behaviour {
        &mut self.swarm.behaviour_mut().rpc
    }

    fn _discovery_mut(&mut self) -> &mut discovery::Behaviour {
        &mut self.swarm.behaviour_mut().discovery
    }

    fn send_internal_request(&mut self, peer_id: PeerId, request: Request) {
        self.rpc_mut()
            .send_request(&peer_id, NetworkRequestId::Internal, request);
    }
}

fn dial_tcp(swarm: &mut Swarm<Behaviour>, enr: &Enr) -> std::result::Result<(), DialError> {
    for multi_addr in enr.multiaddr() {
        if multi_addr.to_string().contains("udp") {
            continue;
        }
        debug!("Dialing bootnode multiaddr {:?}", multi_addr);
        return swarm.dial(multi_addr);
    }

    Err(DialError::NoAddresses)
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
