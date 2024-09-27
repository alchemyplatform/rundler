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
use rundler_types::task::traits::RequestExtractor;
use tower::{Layer, Service};

/// tower network layer: https://github.com/tower-rs/tower/blob/master/guides/building-a-middleware-from-scratch.md
#[derive(Debug)]
pub struct MetricsLayer<T, R> {
    service_name: String,
    protocal: String,
    _request_extractor: PhantomData<T>,
    _request_type: PhantomData<R>,
}

impl<T, R> MetricsLayer<T, R>
where
    T: RequestExtractor<R>,
{
    /// Initialize a network layer wrappers the metric middleware.
    pub fn new(service_name: String, protocal: String) -> Self {
        MetricsLayer {
            service_name,
            protocal,
            _request_extractor: PhantomData,
            _request_type: PhantomData,
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
            protocal: self.protocal.clone(),
            _request_extractor: PhantomData,
            _request_type: PhantomData,
        }
    }
}

impl<S, T, R> Layer<S> for MetricsLayer<T, R>
where
    T: RequestExtractor<R>,
{
    type Service = MetricsMiddleware<S, T, R>;

    fn layer(&self, service: S) -> Self::Service {
        Self::Service::new(service, self.service_name.clone(), self.protocal.clone())
    }
}

/// Middleware implementation.
pub struct MetricsMiddleware<S, T, R> {
    inner: S,
    service_name: String,
    protocol: String,
    _request_extractor: PhantomData<T>,
    _request_type: PhantomData<R>,
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
        }
    }
}

impl<S, T, R> MetricsMiddleware<S, T, R>
where
    T: RequestExtractor<R>,
{
    /// Initialize a middleware.
    pub fn new(inner: S, service_name: String, protocol: String) -> Self {
        Self {
            inner,
            service_name: service_name.clone(),
            protocol,
            _request_extractor: PhantomData,
            _request_type: PhantomData,
        }
    }
}

impl<S, T, R> Service<R> for MetricsMiddleware<S, T, R>
where
    S: Service<R> + Send + Clone + 'static,
    S::Future: Send + 'static,
    T: RequestExtractor<R> + 'static,
    R: Send + 'static,
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
        let protocal = self.protocol.clone();
        async move {
            let rsp = svc.call(request).await;
            MethodMetrics::record_request_latency(
                &method_name,
                &service_name,
                &protocal,
                start.elapsed(),
            );
            MethodMetrics::decrement_open_requests(&method_name, &service_name, &protocal);
            if rsp.is_err() {
                MethodMetrics::increment_error_count(&method_name, &service_name, &protocal);
            }
            rsp
        }
        .boxed()
    }
}

#[derive(Clone)]
struct MethodMetrics {}

impl MethodMetrics {
    fn increment_num_requests(method_name: &str, service_name: &str, protocal: &str) {
        metrics::counter!("num_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocal" => protocal.to_string()).increment(1)
    }

    fn increment_open_requests(method_name: &str, service_name: &str, protocal: &str) {
        metrics::gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocal" => protocal.to_string()).increment(1_f64)
    }

    fn decrement_open_requests(method_name: &str, service_name: &str, protocal: &str) {
        metrics::gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocal" => protocal.to_string()).decrement(1_f64)
    }

    fn increment_error_count(method_name: &str, service_name: &str, protocal: &str) {
        metrics::counter!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocal" => protocal.to_string()).increment(1)
    }

    fn record_request_latency(
        method_name: &str,
        service_name: &str,
        protocal: &str,
        latency: Duration,
    ) {
        metrics::histogram!("request_latency", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocal" => protocal.to_string()).record(latency)
    }
}
