// Code adapted from https://github.com/gakonst/ethers-rs/blob/master/ethers-providers/src/rpc/transports/http.rs
// and https://github.com/gakonst/ethers-rs/blob/master/ethers-providers/src/rpc/transports/common.rs
// Due to lack of reqwest_middleware::ClientWithMiddleware support

use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use ethers::{
    providers::{HttpClientError, JsonRpcClient, JsonRpcError},
    types::U256,
};
use reqwest_middleware::ClientWithMiddleware;
use serde::{
    de::{self, DeserializeOwned, MapAccess, Unexpected, Visitor},
    Deserialize, Serialize,
};
use serde_json::value::RawValue;
use tonic::async_trait;
use url::Url;

#[derive(Debug)]
pub struct MiddlewareProvider {
    id: AtomicU64,
    url: Url,
    client: ClientWithMiddleware,
}

#[async_trait]
impl JsonRpcClient for MiddlewareProvider {
    type Error = HttpClientError;

    async fn request<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, HttpClientError> {
        let next_id = self.id.fetch_add(1, Ordering::SeqCst);
        let payload = Request::new(next_id, method, params);

        let res = self
            .client
            .post(self.url.as_ref())
            .json(&payload)
            .send()
            .await
            .map_err(|e| match e {
                reqwest_middleware::Error::Middleware(err) => {
                    HttpClientError::JsonRpcError(JsonRpcError {
                        code: jsonrpsee::types::error::INTERNAL_ERROR_CODE.into(),
                        message: jsonrpsee::types::error::INTERNAL_ERROR_MSG.to_string(),
                        data: Some(serde_json::Value::String(err.to_string())),
                    })
                }
                reqwest_middleware::Error::Reqwest(err) => HttpClientError::ReqwestError(err),
            })?;

        let body = res.bytes().await?;

        let raw = match serde_json::from_slice(&body) {
            Ok(Response::Success { result, .. }) => result.to_owned(),
            Ok(Response::Error { error, .. }) => return Err(error.into()),
            Ok(_) => {
                let err = HttpClientError::SerdeJson {
                    err: serde::de::Error::custom("unexpected notification over HTTP transport"),
                    text: String::from_utf8_lossy(&body).to_string(),
                };
                return Err(err);
            }
            Err(err) => {
                return Err(HttpClientError::SerdeJson {
                    err,
                    text: String::from_utf8_lossy(&body).to_string(),
                })
            }
        };

        let res = serde_json::from_str(raw.get()).map_err(|err| HttpClientError::SerdeJson {
            err,
            text: raw.to_string(),
        })?;

        Ok(res)
    }
}

impl MiddlewareProvider {
    pub fn new_with_client(url: impl Into<Url>, client: ClientWithMiddleware) -> Self {
        Self {
            id: AtomicU64::new(1),
            client,
            url: url.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
/// A JSON-RPC request
pub struct Request<'a, T> {
    id: u64,
    jsonrpc: &'a str,
    method: &'a str,
    params: T,
}

impl<'a, T> Request<'a, T> {
    /// Creates a new JSON RPC request
    pub fn new(id: u64, method: &'a str, params: T) -> Self {
        Self {
            id,
            jsonrpc: "2.0",
            method,
            params,
        }
    }
}

/// A JSON-RPC response
#[derive(Debug)]
pub enum Response<'a> {
    Success { id: u64, result: &'a RawValue },
    Error { id: u64, error: JsonRpcError },
    Notification { method: &'a str, params: Params<'a> },
}

#[derive(Deserialize, Debug)]
pub struct Params<'a> {
    pub subscription: U256,
    #[serde(borrow)]
    pub result: &'a RawValue,
}

// FIXME: ideally, this could be auto-derived as an untagged enum, but due to
// https://github.com/serde-rs/serde/issues/1183 this currently fails
impl<'de: 'a, 'a> Deserialize<'de> for Response<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ResponseVisitor<'a>(&'a ());
        impl<'de: 'a, 'a> Visitor<'de> for ResponseVisitor<'a> {
            type Value = Response<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid jsonrpc 2.0 response object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut jsonrpc = false;

                // response & error
                let mut id = None;
                // only response
                let mut result = None;
                // only error
                let mut error = None;
                // only notification
                let mut method = None;
                let mut params = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "jsonrpc" => {
                            if jsonrpc {
                                return Err(de::Error::duplicate_field("jsonrpc"));
                            }

                            let value = map.next_value()?;
                            if value != "2.0" {
                                return Err(de::Error::invalid_value(
                                    Unexpected::Str(value),
                                    &"2.0",
                                ));
                            }

                            jsonrpc = true;
                        }
                        "id" => {
                            if id.is_some() {
                                return Err(de::Error::duplicate_field("id"));
                            }

                            let value: u64 = map.next_value()?;
                            id = Some(value);
                        }
                        "result" => {
                            if result.is_some() {
                                return Err(de::Error::duplicate_field("result"));
                            }

                            let value: &RawValue = map.next_value()?;
                            result = Some(value);
                        }
                        "error" => {
                            if error.is_some() {
                                return Err(de::Error::duplicate_field("error"));
                            }

                            let value: JsonRpcError = map.next_value()?;
                            error = Some(value);
                        }
                        "method" => {
                            if method.is_some() {
                                return Err(de::Error::duplicate_field("method"));
                            }

                            let value: &str = map.next_value()?;
                            method = Some(value);
                        }
                        "params" => {
                            if params.is_some() {
                                return Err(de::Error::duplicate_field("params"));
                            }

                            let value: Params = map.next_value()?;
                            params = Some(value);
                        }
                        key => {
                            return Err(de::Error::unknown_field(
                                key,
                                &["id", "jsonrpc", "result", "error", "params", "method"],
                            ))
                        }
                    }
                }

                // jsonrpc version must be present in all responses
                if !jsonrpc {
                    return Err(de::Error::missing_field("jsonrpc"));
                }

                match (id, result, error, method, params) {
                    (Some(id), Some(result), None, None, None) => {
                        Ok(Response::Success { id, result })
                    }
                    (Some(id), None, Some(error), None, None) => Ok(Response::Error { id, error }),
                    (None, None, None, Some(method), Some(params)) => {
                        Ok(Response::Notification { method, params })
                    }
                    _ => Err(de::Error::custom(
                        "response must be either a success/error or notification object",
                    )),
                }
            }
        }

        deserializer.deserialize_map(ResponseVisitor(&()))
    }
}
