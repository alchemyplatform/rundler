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

use futures_util::{future::BoxFuture, FutureExt};
use http::{Request as httpRequest, Response as httpResponse};
use jsonrpsee::{
    server::middleware::rpc::RpcServiceT,
    types::{ErrorCode, Request},
    MethodResponse,
};
use rundler_types::task::{
    metric_recorder::MethodSessionLogger,
    status_code::{get_http_status_from_code, HttpCode, RpcCode},
};
use tower::{Layer, Service};

#[derive(Clone)]
pub(crate) struct RpcMetricsMiddlewareLayer {
    service_name: String,
}

impl RpcMetricsMiddlewareLayer {
    pub(crate) fn new(service_name: String) -> Self {
        Self { service_name }
    }
}

impl<S> Layer<S> for RpcMetricsMiddlewareLayer {
    type Service = RpcMetricsMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        RpcMetricsMiddleware {
            service,
            service_name: self.service_name.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct RpcMetricsMiddleware<S> {
    service: S,
    service_name: String,
}

impl<'a, S> RpcServiceT<'a> for RpcMetricsMiddleware<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'static,
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let method_logger = MethodSessionLogger::start(
            self.service_name.clone(),
            req.method_name().to_string(),
            "rpc".to_string(),
        );
        let svc = self.service.clone();

        async move {
            let rp = svc.call(req).await;
            method_logger.done();

            if rp.is_success() {
                method_logger.record_http(HttpCode::TwoHundreds);
                method_logger.record_rpc(RpcCode::Success);
            } else if let Some(error) = rp.as_error_code() {
                let error_code: ErrorCode = error.into();
                let rpc_code = match error_code {
                    ErrorCode::ParseError => RpcCode::ParseError,
                    ErrorCode::OversizedRequest => RpcCode::InvalidRequest,
                    ErrorCode::InvalidRequest => RpcCode::InvalidRequest,
                    ErrorCode::MethodNotFound => RpcCode::MethodNotFound,
                    ErrorCode::ServerIsBusy => RpcCode::ResourceExhausted,
                    ErrorCode::InvalidParams => RpcCode::InvalidParams,
                    ErrorCode::InternalError => RpcCode::InternalError,
                    ErrorCode::ServerError(_) => RpcCode::ServerError,
                };
                method_logger.record_rpc(rpc_code);
            } else {
                method_logger.record_rpc(RpcCode::Other);
            }

            rp
        }
        .boxed()
    }
}

#[derive(Clone)]
pub(crate) struct HttpMetricMiddlewareLayer {
    service_name: String,
}

impl HttpMetricMiddlewareLayer {
    pub(crate) fn new(service_name: String) -> Self {
        Self { service_name }
    }
}

impl<S> Layer<S> for HttpMetricMiddlewareLayer {
    type Service = HttpMetricMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        HttpMetricMiddleware {
            service,
            service_name: self.service_name.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct HttpMetricMiddleware<S> {
    service: S,
    service_name: String,
}

impl<S, R, ResBody> Service<httpRequest<R>> for HttpMetricMiddleware<S>
where
    S: Service<httpRequest<R>, Response = httpResponse<ResBody>> + Send + Sync + Clone + 'static,
    R: 'static,
    S::Future: Send,
    R: Send,
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

    fn call(&mut self, req: httpRequest<R>) -> Self::Future {
        let method_logger = MethodSessionLogger::new(
            self.service_name.clone(),
            "jsonrpc-method".to_string(),
            "http".to_string(),
        );
        let mut svc = self.service.clone();
        async move {
            let rp = svc.call(req).await;
            let http_status = rp.as_ref().ok().map(|rp| rp.status());
            if let Some(status_code) = http_status {
                method_logger.record_http(get_http_status_from_code(status_code.as_u16()));
            }
            rp
        }
        .boxed()
    }
}
