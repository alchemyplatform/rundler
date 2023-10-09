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
    collections::HashSet,
    task::{Context, Poll, Waker},
};

use delay_map::HashSetDelay;
use discv5::Enr;
use futures::StreamExt;
use libp2p::{
    core::Endpoint,
    swarm::{
        behaviour::{ConnectionClosed, ConnectionEstablished},
        dial_opts::{DialOpts, PeerCondition},
        dummy::ConnectionHandler,
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, PollParameters, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
    Multiaddr, PeerId,
};
use tokio::time::Interval;
use tracing::{debug, info};

use crate::{discovery::enr::EnrExt, Config};

#[derive(Debug)]
pub enum Event {
    Ping(PeerId),
    Status(PeerId),
    Discover(usize),
}

pub struct Behaviour {
    events: Vec<Event>,
    peers_to_dial: Vec<Enr>,
    peers: HashSet<PeerId>,
    waker: Option<Waker>,
    peers_to_ping: HashSetDelay<PeerId>,
    peers_to_status: HashSetDelay<PeerId>,
    target_num_peers: usize,
    tick: Interval,
}

impl Behaviour {
    pub fn new(config: &Config) -> Self {
        Self {
            events: vec![],
            peers_to_dial: vec![],
            peers: HashSet::new(),
            waker: None,
            peers_to_ping: HashSetDelay::new(config.ping_interval),
            peers_to_status: HashSetDelay::new(config.status_interval),
            target_num_peers: config.target_num_peers,
            tick: tokio::time::interval(config.tick_interval),
        }
    }

    pub fn discovered_peers(&mut self, peers: Vec<Enr>) {
        let mut dialed = false;
        for peer in peers {
            if !self.peers.contains(&peer.peer_id()) {
                info!("Discovered new peer {:?}", peer.peer_id());
                self.peers_to_dial.push(peer);
                dialed = true;
            }
        }

        if dialed {
            self.wake();
        }
    }

    // TODO: read spec again and implement:
    // - peer database
    // - We should hold peer statuses and metadata
    // - We should also have some notion of peer reputation
    // - We can shut down connections to peers that are not
    // responding to pings or status requests
    // - Disconnect peers with no shared mempools

    pub fn ping_request(&mut self, peer: &PeerId) {
        // reset ping timer
        self.peers_to_ping.insert(*peer);
    }

    pub fn ping_response(&mut self, peer: &PeerId) {
        // TODO check sequence number against database and issue
        // a metadata request if out of date

        // reset ping timer
        self.peers_to_ping.insert(*peer);
    }

    pub fn status_request(&mut self, peer: &PeerId) {
        // reset status timer
        self.peers_to_status.insert(*peer);
    }

    pub fn status_response(&mut self, peer: &PeerId) {
        // reset status timer
        self.peers_to_status.insert(*peer);
    }

    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    fn tick(&mut self) {
        if self.peers.len() < self.target_num_peers {
            self.events
                .push(Event::Discover(self.target_num_peers - self.peers.len()));
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = ConnectionHandler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm<Self::ConnectionHandler>) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id, endpoint, ..
            }) => {
                debug!(
                    "Connection established with peer {:?} at {:?}",
                    peer_id, endpoint,
                );
                self.peers.insert(peer_id);
                self.peers_to_ping.insert(peer_id);
                self.peers_to_status.insert(peer_id);
            }
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id, endpoint, ..
            }) => {
                debug!(
                    "Connection closed with peer {:?} at {:?}",
                    peer_id, endpoint
                );
                self.peers.remove(&peer_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: THandlerOutEvent<Self>,
    ) {
        // no events
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        _params: &mut impl PollParameters,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if self.tick.poll_tick(cx).is_ready() {
            self.tick();
        }

        if let Some(event) = self.events.pop() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }

        if let Some(peer) = self.peers_to_dial.pop() {
            let peer_id = peer.peer_id();
            let multiaddrs = peer.multiaddr();
            return Poll::Ready(ToSwarm::Dial {
                opts: DialOpts::peer_id(peer_id)
                    .condition(PeerCondition::Disconnected)
                    .addresses(multiaddrs)
                    .build(),
            });
        }

        if let Poll::Ready(Some(Ok(peer))) = self.peers_to_ping.poll_next_unpin(cx) {
            return Poll::Ready(ToSwarm::GenerateEvent(Event::Ping(peer)));
        }

        if let Poll::Ready(Some(Ok(peer))) = self.peers_to_status.poll_next_unpin(cx) {
            return Poll::Ready(ToSwarm::GenerateEvent(Event::Status(peer)));
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
