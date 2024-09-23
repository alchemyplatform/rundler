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
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::{future::BoxFuture, FutureExt};
use tower::{Layer, Service};

/// Trait to expose request method name.
pub trait RequestInfo {
    /// Get method name.
    fn get_method_name(&self) -> String;
}

/// tower network layer: https://github.com/tower-rs/tower/blob/master/guides/building-a-middleware-from-scratch.md
#[derive(Debug, Clone)]
pub struct MetricsLayer {
    service_name: String,
    protocal: String,
}


impl MetricsLayer {
    /// Initialize a network layer wrappers the metric middleware.
    pub fn new(service_name: String, protocal: String) -> Self {
        MetricsLayer {
            service_name,
            protocal,
        }
    }
}

impl<S> Layer<S> for MetricsLayer 
{
    type Service = MetricsMiddleware<S>;
    fn layer(&self, service: S) -> Self::Service {
        MetricsMiddleware::new(service, self.service_name.clone(), self.protocal.clone())
    }
}

/// Middleware implementation.
pub struct MetricsMiddleware<S> {
    inner: S,
    service_name: String,
    protocal: String,
}

impl<S> MetricsMiddleware<S> 
{
    /// Initialize a middleware.
    pub fn new(inner: S, service_name: String, protocal: String) -> Self {
        Self {
            inner: inner,
            service_name: service_name.clone(),
            protocal: protocal,
        }
    }
}

impl<S, Request> Service<Request> for MetricsMiddleware<S>
where
    S: Service<Request> + Send + Sync + Clone + 'static,
    S::Future : Send + Sync + 'static,
    Request: RequestInfo + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(& mut self, request: Request) -> Self::Future {
        let method_name = request.get_method_name();
        MethodMetrics::increment_num_requests(self.service_name.as_str(), method_name.as_str(), self.protocal.as_str());
        MethodMetrics::increment_open_requests(self.service_name.as_str(), method_name.as_str(), self.protocal.as_str());

        let start = Instant::now();
        let mut svc = self.inner.clone();
        let service_name = self.service_name.clone();
        let protocal = self.protocal.clone();
        async move {
            let rsp = svc.call(request).await;
            MethodMetrics::record_request_latency(method_name.as_str(), service_name.as_str(), protocal.as_str(), start.elapsed());
            MethodMetrics::decrement_open_requests(method_name.as_str(), service_name.as_str(), protocal.as_str());
            if rsp.is_err() {
                MethodMetrics::increment_error_count(method_name.as_str(), service_name.as_str(), protocal.as_str());
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

    fn decrement_open_requests( method_name: &str, service_name: &str, protocal: &str) {
        metrics::gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocal" => protocal.to_string()).decrement(1_f64)
    }

    fn increment_error_count( method_name: &str, service_name: &str, protocal: &str) {
        metrics::counter!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocal" => protocal.to_string()).increment(1)
    }

    fn record_request_latency( method_name: &str, service_name: &str, protocal: &str, latency: Duration) {
        metrics::histogram!("request_latency", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocal" => protocal.to_string()).record(latency)
    }
}
