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

use futures::{future::BoxFuture, FutureExt, SinkExt, StreamExt};
use libp2p::{core::UpgradeInfo, InboundUpgrade, Stream};
use tokio::sync::oneshot;
use tokio_io_timeout::TimeoutStream;
use tokio_util::{codec::Framed, compat::FuturesAsyncReadCompatExt};
use tracing::info;

use super::{codec, serde, ConnectionConfig};
use crate::{
    network::PeerRequestId,
    rpc::{
        message::{Request, ResponseResult},
        protocol::{self, Encoding, Protocol, ProtocolError},
    },
};

#[derive(Debug)]
pub(crate) struct InboundProtocol {
    pub(crate) request_sender: oneshot::Sender<(PeerRequestId, Request)>,
    pub(crate) response_receiver: oneshot::Receiver<ResponseResult>,
    pub(crate) network_config: ConnectionConfig,
    pub(crate) request_id: PeerRequestId,
}

impl UpgradeInfo for InboundProtocol {
    type Info = Protocol;
    type InfoIter = Vec<Protocol>;

    fn protocol_info(&self) -> Self::InfoIter {
        protocol::supported_protocols()
    }
}

impl InboundUpgrade<Stream> for InboundProtocol {
    type Output = ();
    type Error = ProtocolError;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, socket: Stream, info: Self::Info) -> Self::Future {
        let codec = match info.encoding {
            Encoding::SSZSnappy => {
                codec::InboundCodec::new(info.clone(), self.network_config.max_chunk_size)
            }
        };

        let socket = socket.compat();
        let mut timed_socket = TimeoutStream::new(socket);
        timed_socket.set_read_timeout(Some(self.network_config.ttfb_timeout));
        let stream = Framed::new(Box::pin(timed_socket), codec);

        async move {
            let (request, mut stream) = match info.schema {
                // metadata requests don't have a body
                protocol::ProtocolSchema::MetadataV1 => (Request::Metadata, stream),
                _ => {
                    match tokio::time::timeout(
                        self.network_config.request_timeout,
                        stream.into_future(),
                    )
                    .await
                    {
                        Ok((Some(Ok(request)), stream)) => (request, stream),
                        Ok((Some(Err(e)), _)) => {
                            info!("Error decoding inbound request: {:?}", e);
                            return Err(ProtocolError::from(e));
                        }
                        Ok((None, _)) => return Err(ProtocolError::IncompleteStream),
                        Err(_) => return Err(ProtocolError::StreamTimeout),
                    }
                }
            };

            self.request_sender
                .send((self.request_id, request))
                .map_err(|_| {
                    ProtocolError::Internal("Failed to send request up to handler".into())
                })?;

            match self.response_receiver.await {
                Ok(response) => {
                    let chunks = serde::chunks_from_response(response)?;
                    for chunk in chunks {
                        stream.send(chunk).await?;
                    }
                    stream.close().await?;
                }
                Err(_) => return Err(ProtocolError::Internal("Failed to receive response".into())),
            }

            Ok(())
        }
        .boxed()
    }
}
