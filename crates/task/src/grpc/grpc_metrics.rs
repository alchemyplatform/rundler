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
use rundler_types::task::{metrics::MethodSessionLogger, status_code::HttpCode};
use tonic::{codegen::http, Code};
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

impl<S, Body> Service<http::Request<Body>> for GrpcMetrics<S>
where
    S: Service<http::Request<Body>> + Sync,
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
        let mut method_logger = MethodSessionLogger::new(
            self.scope.clone(),
            method_name.to_string(),
            "grpc".to_string(),
        );
        method_logger.start();
        ResponseFuture {
            response_future: self.inner.call(request),
            method_logger: method_logger,
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

impl<F, Response, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response, E>>,
{
    type Output = Result<Response, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let res = this.response_future.poll(cx);
        match &res {
            Poll::Ready(response) => {
                this.method_logger.done();
                match response {
                    Ok(_) => {
                        this.method_logger.record_http(HttpCode::TwoHundreds);
                    }
                    Err(_) => {
                        // extract the error message form the error trait
                        this.method_logger.record_http(HttpCode::FiveHundreds);
                    }
                }
            }
            Poll::Pending => {}
        };

        res
    }
}
