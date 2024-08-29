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
    collections::HashMap,
    time::{Duration, Instant},
};

use futures_util::{future::BoxFuture, FutureExt};
use jsonrpsee::{server::middleware::rpc::RpcServiceT, types::Request, MethodResponse, Methods};
use metrics::{Counter, Gauge, Histogram};
use tower::Layer;

#[derive(Clone)]
pub(crate) struct RpcMetricsMiddlewareLayer {
    metrics: RpcMetrics,
}

impl RpcMetricsMiddlewareLayer {
    pub(crate) fn new(methods: &Methods) -> Self {
        Self {
            metrics: RpcMetrics::new(methods),
        }
    }
}

impl<S> Layer<S> for RpcMetricsMiddlewareLayer {
    type Service = RpcMetricsMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        RpcMetricsMiddleware {
            service,
            metrics: self.metrics.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct RpcMetricsMiddleware<S> {
    service: S,
    metrics: RpcMetrics,
}

impl<'a, S> RpcServiceT<'a> for RpcMetricsMiddleware<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'static,
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let method_metrics = self
            .metrics
            .method_metrics
            .get(req.method.as_ref())
            .unwrap()
            .clone();

        method_metrics.increment_open_requests();
        method_metrics.increment_num_requests();
        let start = Instant::now();
        let svc = self.service.clone();

        async move {
            let rp = svc.call(req).await;

            method_metrics.record_request_latency(start.elapsed());
            method_metrics.decrement_open_requests();
            if rp.is_error() {
                method_metrics.increment_error_count();
            }

            rp
        }
        .boxed()
    }
}

#[derive(Clone)]
struct RpcMetrics {
    method_metrics: HashMap<&'static str, MethodMetrics>,
}

impl RpcMetrics {
    fn new(methods: &Methods) -> Self {
        Self {
            method_metrics: HashMap::from_iter(
                methods
                    .method_names()
                    .map(|name| (name, MethodMetrics::new(name))),
            ),
        }
    }
}

#[derive(Clone)]
struct MethodMetrics {
    num_requests: Counter,
    open_requests: Gauge,
    error_count: Counter,
    request_latency: Histogram,
}

impl MethodMetrics {
    fn new(method_name: &str) -> Self {
        Self {
            num_requests: metrics::counter!("rpc_num_requests", "method_name" => method_name.to_string()),
            open_requests: metrics::gauge!("rpc_open_requests", "method_name" => method_name.to_string()),
            error_count: metrics::counter!("rpc_error_count", "method_name" => method_name.to_string()),
            request_latency: metrics::histogram!(
                "rpc_request_latency",
                "method_name" => method_name.to_string()
            ),
        }
    }

    fn increment_num_requests(&self) {
        self.num_requests.increment(1);
    }

    fn increment_open_requests(&self) {
        self.open_requests.increment(1);
    }

    fn decrement_open_requests(&self) {
        self.open_requests.decrement(1);
    }

    fn increment_error_count(&self) {
        self.error_count.increment(1);
    }

    fn record_request_latency(&self, latency: Duration) {
        self.request_latency.record(latency);
    }
}
