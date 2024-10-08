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

//! Middleware for recording metrics for gRPC requests.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project::pin_project;
use rundler_types::task::{
    metric_recorder::MethodSessionLogger,
    status_code::{get_http_status_from_code, HttpCode},
};
use tonic::codegen::http;
use tower::{Layer, Service};

/// A layer for recording metrics for gRPC requests.
#[derive(Debug, Clone)]
pub struct GrpcMetricsLayer {
    scope: String,
}

impl GrpcMetricsLayer {
    /// Create a new `GrpcMetricsLayer` middleware layer
    pub fn new(scope: String) -> Self {
        GrpcMetricsLayer { scope }
    }
}

impl<S> Layer<S> for GrpcMetricsLayer {
    type Service = GrpcMetrics<S>;

    fn layer(&self, service: S) -> Self::Service {
        GrpcMetrics::new(service, self.scope.clone())
    }
}

/// Service for recording metrics for gRPC requests.
#[derive(Clone, Debug)]
pub struct GrpcMetrics<S> {
    inner: S,
    scope: String,
}

impl<S> GrpcMetrics<S> {
    /// Create a new `GrpcMetrics` middleware service.
    pub fn new(inner: S, scope: String) -> Self {
        Self { inner, scope }
    }
}

impl<S, Body, ResBody> Service<http::Request<Body>> for GrpcMetrics<S>
where
    S: Service<http::Request<Body>, Response = http::Response<ResBody>> + Sync,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Our middleware doesn't care about backpressure so its ready as long
        // as the inner service is ready.
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let uri = request.uri().clone();
        let method_name = uri.path().split('/').last().unwrap_or("unknown");
        let method_logger = MethodSessionLogger::start(
            self.scope.clone(),
            method_name.to_string(),
            "grpc".to_string(),
        );
        ResponseFuture {
            response_future: self.inner.call(request),
            method_logger,
        }
    }
}

/// Future returned by the middleware.
// checkout: https://github.com/tower-rs/tower/blob/master/guides/building-a-middleware-from-scratch.md
// for details on the use of Pin here
#[pin_project]
pub struct ResponseFuture<F> {
    #[pin]
    response_future: F,

    method_logger: MethodSessionLogger,
}

impl<F, ResBody, Error> Future for ResponseFuture<F>
where
    F: Future<Output = Result<http::Response<ResBody>, Error>>,
{
    type Output = Result<http::Response<ResBody>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let res = this.response_future.poll(cx);
        match &res {
            Poll::Ready(result) => {
                this.method_logger.done();
                match result {
                    Ok(response) => {
                        let http_status = response.status();
                        this.method_logger
                            .record_http(get_http_status_from_code(http_status.as_u16()));
                    }
                    _ => {
                        this.method_logger.record_http(HttpCode::FiveHundreds);
                    }
                }
            }
            Poll::Pending => {}
        };

        res
    }
}
