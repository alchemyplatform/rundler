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
use libp2p::{core::UpgradeInfo, OutboundUpgrade, Stream};
use tokio_io_timeout::TimeoutStream;
use tokio_util::{codec::Framed, compat::FuturesAsyncReadCompatExt};

use super::{codec, serde, ConnectionConfig};
use crate::{
    rpc::{
        message::{Request, ResponseResult},
        protocol::{self, Protocol, ProtocolError, ProtocolSchema},
    },
    types::Encoding,
};

#[derive(Debug)]
pub(crate) struct OutboundProtocol {
    pub(crate) request: Request,
    pub(crate) network_config: ConnectionConfig,
}

impl UpgradeInfo for OutboundProtocol {
    type Info = Protocol;
    type InfoIter = Vec<Protocol>;

    fn protocol_info(&self) -> Self::InfoIter {
        protocol::request_protocols(&self.request)
    }
}

impl OutboundUpgrade<Stream> for OutboundProtocol {
    type Output = ResponseResult;
    type Error = ProtocolError;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, socket: Stream, info: Self::Info) -> Self::Future {
        let codec = match info.encoding {
            Encoding::SSZSnappy => {
                codec::OutboundCodec::new(info.clone(), self.network_config.max_chunk_size)
            }
        };

        let socket = socket.compat();
        let mut timed_socket = TimeoutStream::new(socket);
        // TODO this should be set after the request is sent.
        timed_socket.set_read_timeout(Some(self.network_config.ttfb_timeout));

        let mut socket = Framed::new(Box::pin(timed_socket), codec);

        async move {
            let num_expected_response_chunks = self.request.num_expected_response_chunks();

            match info.schema {
                // nothing to send for metadata requests, just close
                ProtocolSchema::MetadataV1 => {}
                _ => socket.send(self.request).await?,
            }

            // close the sink portion of the socket
            socket.close().await?;

            let mut chunks = vec![];
            let mut socket = Some(socket);
            for _ in 0..num_expected_response_chunks {
                let to_consume = socket.take().unwrap();

                let (chunk, tail) = match tokio::time::timeout(
                    self.network_config.request_timeout,
                    to_consume.into_future(),
                )
                .await
                {
                    Ok((Some(Ok(item)), tail)) => (item, tail),
                    Ok((Some(Err(e)), _)) => return Err(ProtocolError::from(e)),
                    Ok((None, _)) => return Err(ProtocolError::IncompleteStream),
                    Err(_) => return Err(ProtocolError::StreamTimeout),
                };

                // short circuit on error
                if chunk.is_err() {
                    return Ok(serde::response_from_chunks(info.schema, vec![chunk]));
                }

                chunks.push(chunk);
                socket = Some(tail);
            }

            Ok(serde::response_from_chunks(info.schema, chunks))
        }
        .boxed()
    }
}
