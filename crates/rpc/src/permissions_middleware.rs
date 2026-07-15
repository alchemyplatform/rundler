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

//! Transport-level middleware that parses per-request user operation permissions from
//! HTTP headers and stores them in the request extensions for RPC handlers to read.
//!
//! The headers are only honored when permissions are enabled (Rundler sits behind a trusted
//! gateway). When disabled, the headers are ignored entirely. A malformed header — or only one
//! of the coupled sponsorship header pair — fails the request closed with `400 Bad Request`.

use futures_util::{FutureExt, future::BoxFuture};
use http::{Request as HttpRequest, Response as HttpResponse, StatusCode, header::CONTENT_TYPE};
use jsonrpsee::server::HttpBody;
use tower::{Layer, Service};

use crate::types::RpcPermissions;

/// Tower layer that installs the [`PermissionsHeaderMiddleware`].
#[derive(Clone)]
pub(crate) struct PermissionsHeaderLayer {
    enabled: bool,
}

impl PermissionsHeaderLayer {
    /// Create a new layer. When `enabled` is false the middleware is a pass-through.
    pub(crate) fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}

impl<S> Layer<S> for PermissionsHeaderLayer {
    type Service = PermissionsHeaderMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        PermissionsHeaderMiddleware {
            service,
            enabled: self.enabled,
        }
    }
}

/// Middleware that parses the `X-Rundler-*` permission headers into
/// [`RpcPermissions`] and inserts them into the request extensions.
#[derive(Clone)]
pub(crate) struct PermissionsHeaderMiddleware<S> {
    service: S,
    enabled: bool,
}

impl<S, RequestBody> Service<HttpRequest<RequestBody>> for PermissionsHeaderMiddleware<S>
where
    S: Service<HttpRequest<RequestBody>, Response = HttpResponse<HttpBody>>
        + Send
        + Sync
        + Clone
        + 'static,
    S::Future: Send,
    RequestBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, mut req: HttpRequest<RequestBody>) -> Self::Future {
        // `poll_ready` was driven on `self.service`, so take it and leave the fresh
        // (not-yet-ready) clone behind for the next call.
        let clone = self.service.clone();
        let mut svc = std::mem::replace(&mut self.service, clone);

        if self.enabled {
            match RpcPermissions::from_headers(req.headers()) {
                Ok(Some(perms)) => {
                    req.extensions_mut().insert(perms);
                }
                Ok(None) => {}
                Err(err) => {
                    // Fail closed: a malformed policy header must not silently fall through
                    // to defaults.
                    let resp = HttpResponse::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header(CONTENT_TYPE, "text/plain")
                        .body(HttpBody::from(err.to_string()))
                        .expect("failed to build bad request response");
                    return async move { Ok(resp) }.boxed();
                }
            }
        }

        async move { svc.call(req).await }.boxed()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use super::*;

    #[derive(Clone, Default)]
    struct RecordingService {
        saw_permissions: Arc<Mutex<Option<bool>>>,
        called: Arc<Mutex<bool>>,
    }

    impl Service<HttpRequest<()>> for RecordingService {
        type Response = HttpResponse<HttpBody>;
        type Error = Infallible;
        type Future = futures_util::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: HttpRequest<()>) -> Self::Future {
            *self.called.lock().unwrap() = true;
            *self.saw_permissions.lock().unwrap() =
                Some(req.extensions().get::<RpcPermissions>().is_some());
            futures_util::future::ready(Ok(HttpResponse::new(HttpBody::from("ok".to_string()))))
        }
    }

    fn request_with(headers: &[(&str, &str)]) -> HttpRequest<()> {
        let mut builder = HttpRequest::builder();
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

    #[tokio::test]
    async fn enabled_inserts_permissions_into_extensions() {
        let inner = RecordingService::default();
        let saw = inner.saw_permissions.clone();
        let mut svc = PermissionsHeaderLayer::new(true).layer(inner);

        let resp = svc
            .call(request_with(&[("x-rundler-trusted", "true")]))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(*saw.lock().unwrap(), Some(true));
    }

    #[tokio::test]
    async fn disabled_ignores_headers() {
        let inner = RecordingService::default();
        let saw = inner.saw_permissions.clone();
        let mut svc = PermissionsHeaderLayer::new(false).layer(inner);

        let resp = svc
            .call(request_with(&[("x-rundler-trusted", "true")]))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(*saw.lock().unwrap(), Some(false));
    }

    #[tokio::test]
    async fn no_headers_does_not_insert_permissions() {
        let inner = RecordingService::default();
        let saw = inner.saw_permissions.clone();
        let mut svc = PermissionsHeaderLayer::new(true).layer(inner);

        let resp = svc.call(request_with(&[])).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(*saw.lock().unwrap(), Some(false));
    }

    #[tokio::test]
    async fn malformed_header_returns_400_without_calling_inner() {
        let inner = RecordingService::default();
        let called = inner.called.clone();
        let mut svc = PermissionsHeaderLayer::new(true).layer(inner);

        let resp = svc
            .call(request_with(&[("x-rundler-trusted", "maybe")]))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!*called.lock().unwrap());
    }
}
