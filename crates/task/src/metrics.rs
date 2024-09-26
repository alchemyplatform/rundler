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

//! Middleware for recording metrics for requests.

use std::{
    marker::PhantomData,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::{future::BoxFuture, FutureExt};
use rundler_types::task::traits::{RequestExtractor, ResponseExtractor};
use tower::{Layer, Service};

/// tower network layer: https://github.com/tower-rs/tower/blob/master/guides/building-a-middleware-from-scratch.md
#[derive(Debug)]
pub struct MetricsLayer<T, R, RE> {
    service_name: String,
    protocal: String,
    _request_extractor: PhantomData<T>,
    _request_type: PhantomData<R>,
    _response_extractor: PhantomData<RE>,

}

impl<T, R, RE> MetricsLayer<T, R, RE>
where
    T: RequestExtractor<R>,
{
    /// Initialize a network layer wrappers the metric middleware.
    pub fn new(service_name: String, protocol: String) -> Self {
        MetricsLayer {
            service_name,
            protocol,
            _request_extractor: PhantomData,
            _request_type: PhantomData,
            _response_extractor: PhantomData,
        }
    }
}

impl<T, R> Clone for MetricsLayer<T, R>
where
    T: RequestExtractor<R>,
{
    fn clone(&self) -> Self {
        Self {
            service_name: self.service_name.clone(),
            protocol: self.protocol.clone(),
            _request_extractor: PhantomData,
            _request_type: PhantomData,
            _response_extractor: PhantomData,
        }
    }
}

impl<S, T, R, RE> Layer<S> for MetricsLayer<T, R, RE>
where
    T: RequestExtractor<R>,
{
    type Service = MetricsMiddleware<S, T, R, RE>;
    fn layer(&self, service: S) -> Self::Service {
        Self::Service::new(service, self.service_name.clone(), self.protocol.clone())
    }
}

/// Middleware implementation.
pub struct MetricsMiddleware<S, T, R, RE> {
    inner: S,
    service_name: String,
    protocol: String,
    _request_extractor: PhantomData<T>,
    _request_type: PhantomData<R>,
    _response_extractor: PhantomData<RE>,
}

impl<S, T, R> Clone for MetricsMiddleware<S, T, R>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            service_name: self.service_name.clone(),
            protocol: self.protocol.clone(),
            _request_extractor: PhantomData,
            _request_type: PhantomData,
            _response_extractor: PhantomData
        }
    }
}

impl<S, T, R, RE> MetricsMiddleware<S, T, R, RE>
where
    T: RequestExtractor<R>,
{
    /// Initialize a middleware.
    pub fn new(inner: S, service_name: String, protocol: String) -> Self {
        Self {
            inner,
            service_name: service_name.clone(),
            protocal: protocal,
            _request_extractor: PhantomData,
            _request_type_: PhantomData,
            _response_extractor: PhantomData,
        }
    }
}

impl<S, T, R> Service<R> for MetricsMiddleware<S, T, R>
where
    S: Service<Request> + Send + Sync + Clone + 'static,
    S::Future: Send + Sync + 'static,
    T: RequestExtractor<Request> + 'static,
    R: Send + Sync + 'static,
    RE: ResponseExtractor<S::Response> + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: R) -> Self::Future {
        let method_name = T::get_method_name(&request);

        MethodMetrics::increment_num_requests(&self.service_name, &method_name, &self.protocol);
        MethodMetrics::increment_open_requests(
            self.service_name.as_str(),
            method_name.as_str(),
            self.protocol.as_str(),
        );

        let start = Instant::now();
        let mut svc = self.inner.clone();
        let service_name = self.service_name.clone();
        let protocol = self.protocol.clone();
        async move {
            let rsp = svc.call(request).await;
            MethodMetrics::record_request_latency(
                &method_name,
                &service_name,
                &protocol,
                start.elapsed(),
            );
            MethodMetrics::decrement_open_requests(&method_name, &service_name, &protocol);
            if rsp.is_err() {
                MethodMetrics::increment_error_count(&method_name, &service_name, &protocol);
            }
            rsp
        }
        .boxed()
    }
}
struct MethodMetrics {}

impl MethodMetrics {
    fn increment_num_requests(method_name: &str, service_name: &str, protocol: &str) {
        metrics::counter!("num_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocol" => protocol.to_string()).increment(1)
    }

    fn increment_open_requests(method_name: &str, service_name: &str, protocol: &str) {
        metrics::gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocol" => protocol.to_string()).increment(1_f64)
    }

    fn decrement_open_requests(method_name: &str, service_name: &str, protocol: &str) {
        metrics::gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocol" => protocol.to_string()).decrement(1_f64)
    }

    fn increment_error_count(method_name: &str, service_name: &str, protocol: &str) {
        metrics::counter!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocol" => protocol.to_string()).increment(1)


    fn increment_response_code(
        method_name: &str,
        service_name: &str,
        protocal: &str,
        response_code: &str,
    ) {
        metrics::counter!("response_stats", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocal" => protocal.to_string(), "response_code" => response_code.to_string()).increment(1)
    }

    fn increment_response_code(
        method_name: &str,
        service_name: &str,
        protocal: &str,
        response_code: &str,
    ) {
        metrics::counter!("response_stats", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocal" => protocal.to_string(), "response_code" => response_code.to_string()).increment(1)
    }

    fn record_request_latency(
        method_name: &str,
        service_name: &str,
        protocol: &str,
        latency: Duration,
    ) {
        metrics::histogram!("request_latency", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocol" => protocol.to_string()).record(latency)
    }
}
