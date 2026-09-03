use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_json_rpc::{RequestPacket, ResponsePacket, RpcError};
use alloy_transport::{BoxFuture, TransportError, TransportErrorKind};
use metrics::{Counter, Gauge};
use metrics_derive::Metrics;
use tower::{Layer, Service};

use super::CLIENT_TIMEOUT_ERROR;

#[derive(Metrics)]
#[metrics(scope = "provider_fallback")]
struct PriorityFallbackMetrics {
    #[metric(describe = "index of the currently active RPC endpoint")]
    active_endpoint: Gauge,
    #[metric(describe = "total number of times an RPC fallback endpoint was activated")]
    activations: Counter,
    #[metric(describe = "total number of times the primary RPC endpoint was restored")]
    recoveries: Counter,
    #[metric(describe = "total transport errors that caused an RPC fallback attempt")]
    transport_errors: Counter,
}

#[derive(Debug)]
struct PriorityFallbackState {
    active_endpoint: AtomicUsize,
    degraded_since_secs: AtomicU64,
}

impl Default for PriorityFallbackState {
    fn default() -> Self {
        Self {
            active_endpoint: AtomicUsize::new(0),
            degraded_since_secs: AtomicU64::new(0),
        }
    }
}

/// Routes transport failures to ordered fallback endpoints while keeping JSON-RPC errors on the
/// endpoint that returned them.
#[derive(Debug, Clone)]
pub(crate) struct PriorityFallbackLayer {
    recovery_interval: Duration,
}

impl PriorityFallbackLayer {
    pub(crate) const fn new(recovery_interval: Duration) -> Self {
        Self { recovery_interval }
    }
}

impl<S> Layer<Vec<S>> for PriorityFallbackLayer
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError>
        + Send
        + Clone
        + 'static,
    S::Future: Send,
{
    type Service = PriorityFallbackService<S>;

    fn layer(&self, endpoints: Vec<S>) -> Self::Service {
        PriorityFallbackService::new(endpoints, self.recovery_interval)
    }
}

#[derive(Clone)]
pub(crate) struct PriorityFallbackService<S> {
    endpoints: Arc<Vec<S>>,
    recovery_interval: Duration,
    state: Arc<PriorityFallbackState>,
    metrics: Arc<PriorityFallbackMetrics>,
}

impl<S> PriorityFallbackService<S> {
    fn new(endpoints: Vec<S>, recovery_interval: Duration) -> Self {
        assert!(
            !endpoints.is_empty(),
            "at least one RPC endpoint is required"
        );
        let metrics = PriorityFallbackMetrics::default();
        metrics.active_endpoint.set(0.0);
        Self {
            endpoints: Arc::new(endpoints),
            recovery_interval,
            state: Arc::new(PriorityFallbackState::default()),
            metrics: Arc::new(metrics),
        }
    }

    fn first_endpoint(&self) -> usize {
        let active = self.state.active_endpoint.load(Ordering::Acquire);
        if active == 0 {
            return 0;
        }

        let degraded_since = self.state.degraded_since_secs.load(Ordering::Acquire);
        if now_secs().saturating_sub(degraded_since) >= self.recovery_interval.as_secs() {
            0
        } else {
            active
        }
    }

    fn record_success(&self, endpoint: usize) {
        let previous = self.state.active_endpoint.swap(endpoint, Ordering::AcqRel);
        self.metrics.active_endpoint.set(endpoint as f64);

        if endpoint == 0 {
            self.state.degraded_since_secs.store(0, Ordering::Release);
            if previous != 0 {
                self.metrics.recoveries.increment(1);
                tracing::info!(
                    previous_endpoint = previous,
                    "Restored primary RPC endpoint"
                );
            }
        } else if previous != endpoint {
            self.state
                .degraded_since_secs
                .store(now_secs(), Ordering::Release);
            self.metrics.activations.increment(1);
            tracing::warn!(
                previous_endpoint = previous,
                active_endpoint = endpoint,
                "Activated fallback RPC endpoint"
            );
        }
    }

    fn record_failure(&self, endpoint: usize) {
        self.metrics.transport_errors.increment(1);
        if endpoint == 0 && self.state.active_endpoint.load(Ordering::Acquire) != 0 {
            self.state
                .degraded_since_secs
                .store(now_secs(), Ordering::Release);
        }
        // Provider errors can contain credential-bearing URLs, so identify only the endpoint index.
        tracing::warn!(endpoint, "RPC endpoint transport failed");
    }
}

impl<S> Service<RequestPacket> for PriorityFallbackService<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError>
        + Send
        + Sync
        + Clone
        + 'static,
    S::Future: Send,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let first = this.first_endpoint();
            let order = (first..this.endpoints.len()).chain(0..first);
            let mut last_error = None;

            for endpoint in order {
                let mut service = this.endpoints[endpoint].clone();
                match service.call(request.clone()).await {
                    Ok(response) => {
                        this.record_success(endpoint);
                        return Ok(response);
                    }
                    Err(error) => {
                        if !should_failover(&error) {
                            return Err(error);
                        }
                        this.record_failure(endpoint);
                        last_error = Some(error);
                    }
                }
            }

            Err(last_error.unwrap_or_else(|| {
                TransportErrorKind::custom_str("all RPC fallback endpoints failed")
            }))
        })
    }
}

fn should_failover(error: &TransportError) -> bool {
    match error {
        RpcError::Transport(_) => true,
        RpcError::LocalUsageError(error) => error.to_string() == CLIENT_TIMEOUT_ERROR,
        RpcError::ErrorResp(_)
        | RpcError::NullResp
        | RpcError::UnsupportedFeature(_)
        | RpcError::SerError(_)
        | RpcError::DeserError { .. } => false,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use alloy_json_rpc::{ErrorPayload, Id, Request, Response, ResponsePayload};
    use serde_json::value::RawValue;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn fails_over_on_transport_error_and_stays_on_fallback() {
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let primary = TestTransport::new(primary_calls.clone(), Behavior::TransportError);
        let fallback = TestTransport::new(fallback_calls.clone(), Behavior::Success);
        let mut service =
            PriorityFallbackLayer::new(Duration::from_secs(60)).layer(vec![primary, fallback]);

        service
            .ready()
            .await
            .unwrap()
            .call(request())
            .await
            .unwrap();
        service
            .ready()
            .await
            .unwrap()
            .call(request())
            .await
            .unwrap();

        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn does_not_fail_over_on_json_rpc_error() {
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let primary = TestTransport::new(primary_calls.clone(), Behavior::RpcError);
        let fallback = TestTransport::new(fallback_calls.clone(), Behavior::Success);
        let mut service =
            PriorityFallbackLayer::new(Duration::from_secs(60)).layer(vec![primary, fallback]);

        let response = service
            .ready()
            .await
            .unwrap()
            .call(request())
            .await
            .unwrap();

        assert!(response.is_error());
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn does_not_fail_over_on_local_usage_error() {
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let primary = TestTransport::new(primary_calls.clone(), Behavior::LocalUsageError);
        let fallback = TestTransport::new(fallback_calls.clone(), Behavior::Success);
        let mut service =
            PriorityFallbackLayer::new(Duration::from_secs(60)).layer(vec![primary, fallback]);

        let error = service
            .ready()
            .await
            .unwrap()
            .call(request())
            .await
            .unwrap_err();

        assert!(matches!(error, RpcError::LocalUsageError(_)));
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fails_over_on_client_timeout() {
        assert!(should_failover(&TransportError::local_usage_str(
            CLIENT_TIMEOUT_ERROR
        )));
    }

    #[tokio::test]
    async fn probes_primary_after_recovery_interval() {
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let primary = TestTransport::new(primary_calls.clone(), Behavior::FailOnce);
        let fallback = TestTransport::new(fallback_calls.clone(), Behavior::Success);
        let mut service = PriorityFallbackLayer::new(Duration::ZERO).layer(vec![primary, fallback]);

        service
            .ready()
            .await
            .unwrap()
            .call(request())
            .await
            .unwrap();
        service
            .ready()
            .await
            .unwrap()
            .call(request())
            .await
            .unwrap();

        assert_eq!(primary_calls.load(Ordering::SeqCst), 2);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
    }

    #[derive(Clone, Copy)]
    enum Behavior {
        Success,
        TransportError,
        RpcError,
        LocalUsageError,
        FailOnce,
    }

    #[derive(Clone)]
    struct TestTransport {
        calls: Arc<AtomicUsize>,
        behavior: Behavior,
    }

    impl TestTransport {
        fn new(calls: Arc<AtomicUsize>, behavior: Behavior) -> Self {
            Self { calls, behavior }
        }
    }

    impl Service<RequestPacket> for TestTransport {
        type Response = ResponsePacket;
        type Error = TransportError;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: RequestPacket) -> Self::Future {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let behavior = self.behavior;
            Box::pin(async move {
                match behavior {
                    Behavior::Success => Ok(success_packet()),
                    Behavior::TransportError => Err(TransportErrorKind::backend_gone()),
                    Behavior::RpcError => Ok(error_packet("execution reverted")),
                    Behavior::LocalUsageError => {
                        Err(TransportError::local_usage_str("invalid local request"))
                    }
                    Behavior::FailOnce if call == 0 => Err(TransportErrorKind::backend_gone()),
                    Behavior::FailOnce => Ok(success_packet()),
                }
            })
        }
    }

    fn request() -> RequestPacket {
        RequestPacket::Single(
            Request::new("eth_blockNumber", Id::Number(1), ())
                .serialize()
                .unwrap(),
        )
    }

    fn success_packet() -> ResponsePacket {
        ResponsePacket::Single(Response {
            id: Id::Number(1),
            payload: ResponsePayload::Success(
                RawValue::from_string("\"0x1\"".to_string()).unwrap(),
            ),
        })
    }

    fn error_packet(message: &str) -> ResponsePacket {
        ResponsePacket::Single(Response {
            id: Id::Number(1),
            payload: ResponsePayload::Failure(ErrorPayload {
                code: -32000,
                message: message.to_string().into(),
                data: None,
            }),
        })
    }
}
