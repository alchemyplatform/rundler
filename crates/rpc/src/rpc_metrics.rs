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
use jsonrpsee::{
    server::middleware::rpc::RpcServiceT,
    types::{ErrorCode, Request},
    MethodResponse,
};
use rundler_types::task::{
    metric_recorder::MethodSessionLogger,
    status_code::{HttpCode, RpcCode},
};
use tower::Layer;

#[derive(Clone)]
pub(crate) struct RpcMetricsMiddlewareLayer {
    service_name: String,
}

impl RpcMetricsMiddlewareLayer {
    pub(crate) fn new(service_name: String) -> Self {
        Self {
            service_name: service_name,
        }
    }
}

impl<S> Layer<S> for RpcMetricsMiddlewareLayer {
    type Service = RpcMetricsMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        RpcMetricsMiddleware {
            service: service,
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
        let mut method_logger = MethodSessionLogger::new(
            self.service_name.clone(),
            req.method_name().to_string(),
            "rpc".to_string(),
        );

        method_logger.start();
        let svc = self.service.clone();

        async move {
            let rp = svc.call(req).await;
            method_logger.done();

            if rp.is_success() {
                method_logger.record_http(HttpCode::TwoHundreds);
                method_logger.record_rpc(RpcCode::Success);
            } else {
                if let Some(error) = rp.as_error_code() {
                    let error_code: ErrorCode = error.into();
                    let (http_code, rpc_code) = match error_code {
                        ErrorCode::ParseError => (HttpCode::FourHundreds, RpcCode::ParseError),
                        ErrorCode::OversizedRequest => {
                            (HttpCode::FourHundreds, RpcCode::InvalidRequest)
                        }
                        ErrorCode::InvalidRequest => {
                            (HttpCode::FourHundreds, RpcCode::InvalidRequest)
                        }
                        ErrorCode::MethodNotFound => {
                            (HttpCode::FourHundreds, RpcCode::MethodNotFound)
                        }
                        ErrorCode::ServerIsBusy => {
                            (HttpCode::FiveHundreds, RpcCode::ResourceExhausted)
                        }
                        ErrorCode::InvalidParams => {
                            (HttpCode::FourHundreds, RpcCode::InvalidParams)
                        }
                        ErrorCode::InternalError => {
                            (HttpCode::FiveHundreds, RpcCode::InternalError)
                        }
                        ErrorCode::ServerError(_) => (HttpCode::FiveHundreds, RpcCode::ServerError),
                    };
                    method_logger.record_http(http_code);
                    method_logger.record_rpc(rpc_code);
                } else {
                    method_logger.record_http(HttpCode::FiveHundreds);
                    method_logger.record_rpc(RpcCode::Other);
                }
            }

            rp
        }
        .boxed()
    }
}
