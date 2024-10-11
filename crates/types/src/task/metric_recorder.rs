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
use std::time::Instant;

use metrics::{Counter, Gauge, Histogram};
use metrics_derive::Metrics;

use super::status_code::{HttpCode, RpcCode};

/// method logger to log one method invoke session.
pub struct MethodSessionLogger {
    start_time: Instant,
    service_name: String,
    method_name: String,
    protocol: String,
    method_metric: MethodMetrics,
}

#[derive(Metrics)]
#[metrics(scope = "rpc_stats")]
pub(crate) struct MethodMetrics {
    #[metric(describe = "total count of requests.")]
    num_requests: Counter,

    #[metric(describe = "the number of opening requests.")]
    open_requests: Gauge,

    #[metric(describe = "the distribution of request latency.")]
    request_latency: Histogram,
}

#[derive(Metrics)]
#[metrics(scope = "rpc_stats")]
pub(crate) struct MethodStatusMetrics {
    #[metric(describe = "the count of http response status.")]
    http_response_status: Counter,

    #[metric(describe = "the count of rpc response status.")]
    rpc_response_status: Counter,
}

impl MethodSessionLogger {
    /// create a session logger.
    pub fn new(service_name: String, method_name: String, protocol: String) -> Self {
        Self {
            start_time: Instant::now(),
            method_name: method_name.clone(),
            service_name: service_name.clone(),
            protocol: protocol.clone(),
            method_metric: MethodMetrics::new_with_labels(&[
                ("method_name", method_name),
                ("service_name", service_name),
                ("protocol", protocol),
            ]),
        }
    }

    /// start the session. time will be initialized.
    pub fn start(service_name: String, method_name: String, protocol: String) -> Self {
        let logger = Self::new(service_name, method_name, protocol);
        logger.method_metric.num_requests.increment(1);
        logger.method_metric.open_requests.increment(1);
        logger
    }

    /// record a rpc status code.
    pub fn record_rpc(&self, rpc_code: RpcCode) {
        MethodStatusMetrics::new_with_labels(&[
            ("method_name", self.method_name.clone()),
            ("service_name", self.service_name.clone()),
            ("protocol", self.protocol.clone()),
            ("status_code", rpc_code.to_string()),
        ])
        .rpc_response_status
        .increment(1);
    }

    /// record a http status code.
    pub fn record_http(&self, http_code: HttpCode) {
        MethodStatusMetrics::new_with_labels(&[
            ("method_name", self.method_name.clone()),
            ("service_name", self.service_name.clone()),
            ("protocol", self.protocol.clone()),
            ("status_code", http_code.to_string()),
        ])
        .http_response_status
        .increment(1);
    }

    /// end of the session. Record the session duration.
    pub fn done(&self) {
        self.method_metric.open_requests.decrement(1);
        self.method_metric
            .request_latency
            .record(self.start_time.elapsed().as_millis() as f64);
    }
}
