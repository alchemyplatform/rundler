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
    collections::{HashMap, VecDeque},
    sync::{atomic::AtomicU64, Arc},
    task::{Context, Poll},
};

use libp2p::{
    core::Endpoint,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, PollParameters,
        THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
    Multiaddr, PeerId,
};
use tokio::sync::oneshot;
use tracing::error;

use super::{
    handler::{ConnectionConfig, Event as HandlerEvent, Handler, NotifyEvent},
    message::{Request, Response, ResponseError, ResponseResult},
};
use crate::network::{NetworkRequestId, PeerRequestId};

#[derive(Debug)]
pub(crate) enum Event {
    Request(PeerId, PeerRequestId, Request),
    Response(PeerId, NetworkRequestId, Result<Response, ResponseError>),
}

#[derive(Debug)]
pub(crate) struct Behaviour {
    network_config: ConnectionConfig,
    global_request_id: Arc<AtomicU64>,
    pending_events: VecDeque<ToSwarm<Event, NotifyEvent>>,
    // TODO time these out
    pending_inbound_responses: HashMap<PeerRequestId, oneshot::Sender<ResponseResult>>,
}

impl Behaviour {
    /// Create a new RPC behaviour
    pub(crate) fn new(network_config: ConnectionConfig) -> Self {
        Self {
            network_config,
            global_request_id: Arc::new(AtomicU64::new(0)),
            pending_events: VecDeque::new(),
            pending_inbound_responses: HashMap::new(),
        }
    }

    /// Send a request to a peer
    pub(crate) fn send_request(&mut self, peer: &PeerId, id: NetworkRequestId, request: Request) {
        self.pending_events.push_back(ToSwarm::NotifyHandler {
            peer_id: *peer,
            handler: NotifyHandler::Any,
            event: NotifyEvent::Request(id, request),
        });
    }

    /// Send a response to a peer
    pub(crate) fn send_response(&mut self, request_id: PeerRequestId, response: ResponseResult) {
        if let Some(sender) = self.pending_inbound_responses.remove(&request_id) {
            sender.send(response).unwrap_or_else(|e| {
                error!("Failed to send response to peer: {:?}", e);
            });
        };
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(
            self.network_config.clone(),
            Arc::clone(&self.global_request_id),
        ))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Handler::new(
            self.network_config.clone(),
            Arc::clone(&self.global_request_id),
        ))
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_, Self::ConnectionHandler>) {
        match event {
            FromSwarm::ConnectionEstablished(_) => {}
            FromSwarm::ConnectionClosed(_) => {}
            FromSwarm::AddressChange(_) => {}
            FromSwarm::DialFailure(_) => {}
            FromSwarm::ListenFailure(_) => {}
            FromSwarm::NewListener(_) => {}
            FromSwarm::NewListenAddr(_) => {}
            FromSwarm::ExpiredListenAddr(_) => {}
            FromSwarm::ListenerError(_) => {}
            FromSwarm::ListenerClosed(_) => {}
            FromSwarm::NewExternalAddrCandidate(_) => {}
            FromSwarm::ExternalAddrExpired(_) => {}
            FromSwarm::ExternalAddrConfirmed(_) => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            HandlerEvent::InboundRequest(request_id, request, sender) => {
                self.pending_inbound_responses.insert(request_id, sender);
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::Request(
                        peer_id, request_id, request,
                    )));
            }
            HandlerEvent::OutboundResponse(request_id, response) => {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::Response(
                        peer_id, request_id, response,
                    )));
            }
        }
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
        _params: &mut impl PollParameters,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}
