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
use crate::rpc::message::{Request, ResponseResult};

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub max_chunk_size: usize,
    pub ttfb_timeout: Duration,
    pub request_timeout: Duration,
    pub connection_keep_alive: Duration,
}

type InboundRecvResult =
    Result<((RequestId, Request), oneshot::Sender<ResponseResult>), oneshot::error::RecvError>;

pub(crate) struct Handler {
    network_config: NetworkConfig,
    global_request_id: Arc<AtomicU64>,
    pending_inbound: FuturesUnordered<BoxFuture<'static, InboundRecvResult>>,
    outbound_queue: VecDeque<SubstreamProtocol<OutboundProtocol, RequestId>>,
    pending_events: VecDeque<Event>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {}

#[derive(Debug)]
pub(crate) enum Event {
    InboundRequest(RequestId, Request, oneshot::Sender<ResponseResult>),
    OutboundResponse(RequestId, ResponseResult),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub u64);

#[derive(Debug)]
pub(crate) enum NotifyEvent {
    Request(RequestId, Request),
}

impl ConnectionHandler for Handler {
    type FromBehaviour = NotifyEvent;
    type ToBehaviour = Event;
    type Error = Error;
    type InboundProtocol = InboundProtocol;
    type OutboundProtocol = OutboundProtocol;
    type InboundOpenInfo = RequestId;
    type OutboundOpenInfo = RequestId;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        // TODO this method is called in various places in the swarm to get the underlying supported protocols
        // the constructed protocol is quickly thrown away.
        //
        // We should implement this such that it has no side-effects.
        // This was copied from request-response and is hot garbage.

        let (request_sender, request_receiver) = oneshot::channel();
        let (response_sender, response_receiver) = oneshot::channel();

        let request_id = self.next_request_id();

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
                request_id,
            },
            request_id,
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
            match result {
                Ok(((request_id, request), response_sender)) => {
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        Event::InboundRequest(request_id, request, response_sender),
                    ))
                }
                Err(_) => {
                    // errors are handled in on_listen_upgrade_error
                }
            }
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
    pub fn new(network_config: NetworkConfig, global_request_id: Arc<AtomicU64>) -> Self {
        Self {
            network_config,
            global_request_id,
            pending_inbound: FuturesUnordered::new(),
            outbound_queue: VecDeque::new(),
            pending_events: VecDeque::new(),
        }
    }

    fn next_request_id(&self) -> RequestId {
        RequestId(self.global_request_id.fetch_add(1, Ordering::Relaxed))
    }

    fn on_fully_negotiated_inbound(&mut self, request_id: RequestId) {
        debug!(
            "Inbound protocol fully negotiated. Request ID: {:?}",
            request_id
        );
    }

    fn on_fully_negotiated_outbound(&mut self, request_id: RequestId, result: ResponseResult) {
        debug!(
            "Outbound protocol fully negotiated. Request ID: {:?}",
            request_id
        );
        self.pending_events
            .push_back(Event::OutboundResponse(request_id, result));
    }
}
