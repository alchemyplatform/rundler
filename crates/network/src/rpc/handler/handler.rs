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
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt, TryFutureExt};
use libp2p::swarm::{
    handler::{ConnectionEvent, FullyNegotiatedInbound, FullyNegotiatedOutbound},
    ConnectionHandler, ConnectionHandlerEvent, KeepAlive, SubstreamProtocol,
};
use tokio::sync::oneshot;
use tracing::{debug, error};

use super::{inbound::InboundProtocol, outbound::OutboundProtocol};
use crate::{
    network::{NetworkRequestId, PeerRequestId},
    rpc::message::{Request, ResponseResult},
};

const DEFAULT_MAX_CHUNK_SIZE: usize = 1024 * 1024;
const DEFAULT_TTFB_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration for the RPC connection
#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    /// Maximum chunk size to read in an RPC connection
    pub max_chunk_size: usize,
    /// Time to first byte timeout
    pub ttfb_timeout: Duration,
    /// Request timeout, resets between each chunk
    pub request_timeout: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_chunk_size: DEFAULT_MAX_CHUNK_SIZE,
            ttfb_timeout: DEFAULT_TTFB_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

type InboundRecvResult =
    Result<((PeerRequestId, Request), oneshot::Sender<ResponseResult>), oneshot::error::RecvError>;

pub(crate) struct Handler {
    network_config: ConnectionConfig,
    global_request_id: Arc<AtomicU64>,
    pending_inbound: FuturesUnordered<BoxFuture<'static, InboundRecvResult>>,
    outbound_queue: VecDeque<SubstreamProtocol<OutboundProtocol, NetworkRequestId>>,
    pending_events: VecDeque<Event>,
}

/// RPC handler error
#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {}

#[derive(Debug)]
pub(crate) enum Event {
    InboundRequest(PeerRequestId, Request, oneshot::Sender<ResponseResult>),
    OutboundResponse(NetworkRequestId, ResponseResult),
}

#[derive(Debug)]
pub(crate) enum NotifyEvent {
    Request(NetworkRequestId, Request),
}

impl ConnectionHandler for Handler {
    type FromBehaviour = NotifyEvent;
    type ToBehaviour = Event;
    type Error = Error;
    type InboundProtocol = InboundProtocol;
    type OutboundProtocol = OutboundProtocol;
    type InboundOpenInfo = PeerRequestId;
    type OutboundOpenInfo = NetworkRequestId;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        // TODO this method is called in various places in the swarm to get the underlying supported protocols
        // the constructed protocol is quickly thrown away.
        //
        // We should implement this such that it has no side-effects.
        // This was copied from request-response and is hot garbage.

        let (request_sender, request_receiver) = oneshot::channel();
        let (response_sender, response_receiver) = oneshot::channel();

        let peer_request_id = self.next_peer_request_id();

        self.pending_inbound.push(
            request_receiver
                .map_ok(move |rq| (rq, response_sender))
                .boxed(),
        );

        SubstreamProtocol::new(
            InboundProtocol {
                request_sender,
                response_receiver,
                network_config: self.network_config.clone(),
                request_id: peer_request_id,
            },
            peer_request_id,
        )
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        // TODO handle shutdowns
        KeepAlive::Yes
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::ToBehaviour,
            Self::Error,
        >,
    > {
        // Pending events
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }

        // handle inbound
        while let Poll::Ready(Some(result)) = self.pending_inbound.poll_next_unpin(cx) {
            if let Ok(((request_id, request), response_sender)) = result {
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                    Event::InboundRequest(request_id, request, response_sender),
                ));
            }
            // errors are handled in on_listen_upgrade_error
        }

        // handle outbound
        if let Some(substream) = self.outbound_queue.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: substream,
            });
        }

        Poll::Pending
    }

    fn on_behaviour_event(&mut self, event: NotifyEvent) {
        match event {
            NotifyEvent::Request(request_id, request) => {
                let substream = SubstreamProtocol::new(
                    OutboundProtocol {
                        request,
                        network_config: self.network_config.clone(),
                    },
                    request_id,
                );
                self.outbound_queue.push_back(substream);
            }
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            '_,
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                info: request_id,
                ..
            }) => self.on_fully_negotiated_inbound(request_id),
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: result,
                info: request_id,
            }) => self.on_fully_negotiated_outbound(request_id, result),
            ConnectionEvent::DialUpgradeError(e) => {
                // TODO handle this with peer manager
                error!("Dial upgrade error");
                panic!("Dial upgrade error unhandled {:?}", e.error)
            }
            ConnectionEvent::ListenUpgradeError(e) => {
                // TODO handle this with peer manager
                // could be timeouts on our end, so deal with error types
                error!("Listen upgrade error {:?}", e.error);
                panic!("Listen upgrade error unhandled")
            }
            ConnectionEvent::AddressChange(_) => {}
            ConnectionEvent::LocalProtocolsChange(_) => {}
            ConnectionEvent::RemoteProtocolsChange(_) => {}
        }
    }
}

impl Handler {
    pub(crate) fn new(network_config: ConnectionConfig, global_request_id: Arc<AtomicU64>) -> Self {
        Self {
            network_config,
            global_request_id,
            pending_inbound: FuturesUnordered::new(),
            outbound_queue: VecDeque::new(),
            pending_events: VecDeque::new(),
        }
    }

    fn next_peer_request_id(&self) -> PeerRequestId {
        PeerRequestId(self.global_request_id.fetch_add(1, Ordering::Relaxed))
    }

    fn on_fully_negotiated_inbound(&mut self, request_id: PeerRequestId) {
        debug!(
            "Inbound protocol fully negotiated. Request ID: {:?}",
            request_id
        );
    }

    fn on_fully_negotiated_outbound(
        &mut self,
        request_id: NetworkRequestId,
        result: ResponseResult,
    ) {
        debug!(
            "Outbound protocol fully negotiated. Request ID: {:?}",
            request_id
        );
        self.pending_events
            .push_back(Event::OutboundResponse(request_id, result));
    }
}
