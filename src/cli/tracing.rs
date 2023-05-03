//! Adopted from https://github.com/paradigmxyz/reth/blob/main/crates/tracing/src/lib.rs

use std::io;

use opentelemetry::{
    global,
    sdk::{propagation::TraceContextPropagator, trace, Resource},
    KeyValue,
};
use tracing::Subscriber;
pub use tracing::*;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    layer::SubscriberExt, prelude::*, registry::LookupSpan, EnvFilter, Layer, Registry,
};

type BoxedLayer<S> = Box<dyn Layer<S> + Send + Sync>;

pub fn init(layers: Vec<BoxedLayer<Registry>>) {
    tracing_subscriber::registry().with(layers).init();
}

pub fn otel_layer<S>() -> anyhow::Result<BoxedLayer<S>>
where
    S: Subscriber + Send + Sync,
    for<'a> S: LookupSpan<'a>,
{
    global::set_text_map_propagator(TraceContextPropagator::new());
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(opentelemetry_otlp::new_exporter().tonic())
        .with_trace_config(
            trace::config().with_resource(Resource::new(vec![KeyValue::new(
                "service.name",
                "rundler-service-staging",
            )])),
        )
        .install_batch(opentelemetry::runtime::Tokio)?;
    Ok(tracing_opentelemetry::OpenTelemetryLayer::new(tracer)
        .with_filter(EnvFilter::from_default_env())
        .boxed())
}

pub fn fmt_layer<S>(f: &Option<String>, json: bool) -> (BoxedLayer<S>, WorkerGuard)
where
    S: Subscriber + Send + Sync,
    for<'a> S: LookupSpan<'a>,
{
    let (appender, guard) = if let Some(log_file) = f {
        tracing_appender::non_blocking(tracing_appender::rolling::never(".", log_file))
    } else {
        tracing_appender::non_blocking(io::stdout())
    };

    let l = if json {
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(appender)
            .with_filter(EnvFilter::from_default_env())
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .pretty()
            .with_writer(appender)
            .with_filter(EnvFilter::from_default_env())
            .boxed()
    };
    (l, guard)
}
