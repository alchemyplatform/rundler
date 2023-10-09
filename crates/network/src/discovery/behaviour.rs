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
    pin::Pin,
    task::{Context, Poll},
};

use discv5::{
    enr::{CombinedKey, NodeId},
    Discv5, Discv5ConfigBuilder, Discv5Error, Discv5Event, Enr, ListenConfig, QueryError,
};
use futures::Future;
use libp2p::{
    core::Endpoint,
    swarm::{
        dummy::ConnectionHandler, ConnectionDenied, ConnectionId, DialFailure, FromSwarm,
        NetworkBehaviour, PollParameters, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
    Multiaddr, PeerId,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::{Config, Error, Result as NetworkResult};

#[derive(Debug)]
pub struct DiscoveredPeers {
    pub peers: Vec<Enr>,
}

type QueryFuture = Pin<Box<dyn Future<Output = Result<Vec<Enr>, QueryError>>>>;

pub struct Behaviour {
    discv5: Discv5,
    query_fut: Option<QueryFuture>,
    event_stream: mpsc::Receiver<Discv5Event>,
}

impl Behaviour {
    pub async fn new(config: &Config, enr: Enr, enr_key: CombinedKey) -> NetworkResult<Self> {
        let listen_config =
            ListenConfig::from_ip(config.listen_address.ip(), config.listen_address.port() + 1);
        debug!("Discv5 listening on {:?}", listen_config);

        let discv5_config = Discv5ConfigBuilder::new(listen_config).build();
        let mut discv5 = Discv5::new(enr, enr_key, discv5_config)
            .map_err(|e| Error::Discovery(Discv5Error::Custom(e)))?;

        for bootnode in config.bootnodes.iter() {
            discv5
                .add_enr(bootnode.clone())
                .map_err(|e| Error::Discovery(Discv5Error::Custom(e)))?;
        }

        discv5.start().await.map_err(Error::Discovery)?;
        let event_stream = discv5.event_stream().await.map_err(Error::Discovery)?;

        Ok(Self {
            discv5,
            query_fut: None,
            event_stream,
        })
    }

    pub fn start_query(&mut self, num_peers: usize) {
        if self.query_fut.is_some() {
            return;
        }

        let predicate = |enr: &Enr| enr.tcp4().is_some() || enr.tcp6().is_some();

        info!("Starting discovery query");
        self.query_fut = Some(Box::pin(self.discv5.find_node_predicate(
            NodeId::random(),
            Box::new(predicate),
            num_peers,
        )));
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = ConnectionHandler;
    type ToSwarm = DiscoveredPeers;

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

    // TODO manage banned peers

    // TODO manage ENR updates

    fn on_swarm_event(&mut self, event: FromSwarm<Self::ConnectionHandler>) {
        if let FromSwarm::DialFailure(DialFailure { peer_id, error, .. }) = event {
            debug!("Dial failure to peer {:?}: {:?}", peer_id, error);
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: THandlerOutEvent<Self>,
    ) {
        // Do nothing
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        _params: &mut impl PollParameters,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(fut) = &mut self.query_fut {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(peers)) => {
                    self.query_fut = None;
                    return Poll::Ready(ToSwarm::GenerateEvent(DiscoveredPeers { peers }));
                }
                Poll::Ready(Err(e)) => {
                    self.query_fut = None;
                    error!("Query error: {:?}", e);
                }
                Poll::Pending => {}
            }
        }

        while let Poll::Ready(Some(event)) = self.event_stream.poll_recv(cx) {
            // These aren't currently useful, peers are discovered in queries
            match event {
                Discv5Event::Discovered(e) => debug!("Discovered peers in event: {:?}", e),
                e => debug!("Discovery event: {:?}", e),
            }
        }

        Poll::Pending
    }
}
