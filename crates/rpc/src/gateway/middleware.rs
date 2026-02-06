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

//! Chain routing middleware for the gateway.

use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::{Request, Response, StatusCode};
use tower::{Layer, Service};

use super::error::GatewayError;

/// Extension type for storing the resolved chain ID in request extensions.
#[derive(Debug, Clone, Copy)]
pub struct ChainId(pub u64);

/// Layer that creates ChainRoutingMiddleware instances.
#[derive(Clone)]
pub struct ChainRoutingLayer {
    valid_chains: Arc<HashSet<u64>>,
}

impl ChainRoutingLayer {
    /// Creates a new ChainRoutingLayer with the given valid chain IDs.
    pub fn new(valid_chains: HashSet<u64>) -> Self {
        Self {
            valid_chains: Arc::new(valid_chains),
        }
    }
}

impl<S> Layer<S> for ChainRoutingLayer {
    type Service = ChainRoutingMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ChainRoutingMiddleware {
            inner,
            valid_chains: self.valid_chains.clone(),
        }
    }
}

/// Middleware that extracts chain ID from URL path and validates it.
///
/// Expected path format: `/v1/{chain_id}/`
#[derive(Clone)]
pub struct ChainRoutingMiddleware<S> {
    inner: S,
    valid_chains: Arc<HashSet<u64>>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ChainRoutingMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let valid_chains = self.valid_chains.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let path = req.uri().path().to_string();

            match parse_chain_path(&path) {
                Ok((chain_id, remaining_path)) => {
                    if !valid_chains.contains(&chain_id) {
                        return Ok(error_response(
                            StatusCode::NOT_FOUND,
                            &format!("Chain {} not found", chain_id),
                        ));
                    }

                    req.extensions_mut().insert(ChainId(chain_id));

                    let new_uri = rebuild_uri(&req, &remaining_path);
                    *req.uri_mut() = new_uri;

                    inner.call(req).await
                }
                Err(_) => {
                    // Path doesn't match /v1/{chain_id}/ format.
                    // Pass through (for /health, etc.)
                    inner.call(req).await
                }
            }
        })
    }
}

fn parse_chain_path(path: &str) -> Result<(u64, String), GatewayError> {
    let path_stripped = path.strip_prefix('/').unwrap_or(path);
    let mut parts = path_stripped.splitn(3, '/');

    let version = parts.next().ok_or_else(|| {
        GatewayError::InvalidPath("Invalid path format, use /v1/{chain_id}/".to_string())
    })?;

    if version != "v1" {
        return Err(GatewayError::InvalidPath(format!(
            "Unsupported API version '{}', use /v1/{{chain_id}}/",
            version
        )));
    }

    let chain_str = parts.next().ok_or_else(|| {
        GatewayError::InvalidPath("Missing chain ID in path, use /v1/{chain_id}/".to_string())
    })?;

    let chain_id = chain_str.parse::<u64>().map_err(|_| {
        GatewayError::InvalidPath(format!(
            "Invalid chain ID '{}', must be a number",
            chain_str
        ))
    })?;

    let remaining = parts.next().unwrap_or("");
    let remaining_path = if remaining.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", remaining)
    };

    Ok((chain_id, remaining_path))
}

fn rebuild_uri<B>(req: &Request<B>, new_path: &str) -> http::Uri {
    let mut builder = http::Uri::builder();

    if let Some(scheme) = req.uri().scheme() {
        builder = builder.scheme(scheme.clone());
    }

    if let Some(authority) = req.uri().authority() {
        builder = builder.authority(authority.clone());
    }

    let path_and_query = if let Some(query) = req.uri().query() {
        format!("{}?{}", new_path, query)
    } else {
        new_path.to_string()
    };

    builder
        .path_and_query(path_and_query)
        .build()
        .unwrap_or_else(|_| new_path.parse().unwrap_or_else(|_| "/".parse().unwrap()))
}

fn error_response<B: Default>(status: StatusCode, message: &str) -> Response<B> {
    let mut response = Response::new(B::default());
    *response.status_mut() = status;
    tracing::warn!("Gateway routing error: {} - {}", status, message);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_chain_path_valid() {
        let (chain_id, remaining) = parse_chain_path("/v1/1/").unwrap();
        assert_eq!(chain_id, 1);
        assert_eq!(remaining, "/");

        let (chain_id, remaining) = parse_chain_path("/v1/42161/").unwrap();
        assert_eq!(chain_id, 42161);
        assert_eq!(remaining, "/");

        let (chain_id, remaining) = parse_chain_path("/v1/1/some/path").unwrap();
        assert_eq!(chain_id, 1);
        assert_eq!(remaining, "/some/path");
    }

    #[test]
    fn test_parse_chain_path_invalid_version() {
        let result = parse_chain_path("/v2/1/");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_chain_path_missing_chain() {
        let result = parse_chain_path("/v1/");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_chain_path_invalid_chain_id() {
        let result = parse_chain_path("/v1/notanumber/");
        assert!(result.is_err());
    }
}
