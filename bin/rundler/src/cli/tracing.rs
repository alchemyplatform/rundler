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

use std::{io, sync::OnceLock};

use anyhow::Ok;
use opentelemetry::{
    global,
    trace::{Tracer, TracerProvider as _},
};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{logs::SdkLoggerProvider, trace::SdkTracerProvider, Resource};
pub use tracing::*;
use tracing::{subscriber, subscriber::Interest, Metadata, Subscriber};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_log::LogTracer;
use tracing_subscriber::{
    layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, FmtSubscriber, Layer, Registry,
};

use super::LogsArgs;

pub fn configure_logging(config: &LogsArgs) -> anyhow::Result<WorkerGuard> {
    let (appender, guard) = if let Some(log_file) = &config.file {
        tracing_appender::non_blocking(tracing_appender::rolling::never(".", log_file))
    } else {
        tracing_appender::non_blocking(io::stdout())
    };

    let subscriber_builder = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(appender);
    if config.json {
        subscriber::set_global_default(
            subscriber_builder
                .json()
                .finish()
                .with(TargetBlacklistLayer),
        )?;
    } else {
        subscriber::set_global_default(
            subscriber_builder
                .pretty()
                .finish()
                .with(TargetBlacklistLayer),
        )?;
    }

    // Redirect logs from external crates using `log` to the tracing subscriber
    LogTracer::init()?;

    Ok(guard)
}

fn get_resource() -> Resource {
    static RESOURCE: OnceLock<Resource> = OnceLock::new();
    RESOURCE
        .get_or_init(|| {
            Resource::builder()
                .with_service_name("basic-otlp-example-grpc")
                .build()
        })
        .clone()
}

fn init_logs() -> SdkLoggerProvider {
    let exporter = opentelemetry_stdout::LogExporter::default();

    SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(get_resource())
        .build()
}

fn init_traces() -> SdkTracerProvider {
    let exporter = opentelemetry_stdout::SpanExporter::default();

    // SpanExporter::builder()
    //     .with_http()
    //     .with_protocol(Protocol::HttpBinary) //can be changed to `Protocol::HttpJson` to export in JSON format
    //     .build()
    //     .expect("Failed to create trace exporter");

    SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(get_resource())
        .build()
}

pub fn config_log() -> anyhow::Result<()> {
    let logger_provider = init_logs();

    // Create a new OpenTelemetryTracingBridge using the above LoggerProvider.
    let otel_layer = OpenTelemetryTracingBridge::new(&logger_provider);

    let filter_otel = EnvFilter::new("info")
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("opentelemetry=off".parse().unwrap())
        .add_directive("tonic=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("reqwest=off".parse().unwrap());
    let otel_layer = otel_layer.with_filter(filter_otel);

    // Create a new tracing::Fmt layer to print the logs to stdout. It has a
    // default filter of `info` level and above, and `debug` and above for logs
    // from OpenTelemetry crates. The filter levels can be customized as needed.
    let filter_fmt = EnvFilter::new("info").add_directive("opentelemetry=debug".parse().unwrap());
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_thread_names(true)
        .with_filter(filter_fmt);

    // Initialize the tracing subscriber with the OpenTelemetry layer and the
    // Fmt layer.
    tracing_subscriber::registry()
        .with(otel_layer)
        .with(fmt_layer)
        .with(opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(_))
        .init();

    // At this point Logs (OTel Logs and Fmt Logs) are initialized, which will
    // allow internal-logs from Tracing/Metrics initializer to be captured.

    let tracer_provider = init_traces();
    // Set the global tracer provider using a clone of the tracer_provider.
    // Setting global tracer provider is required if other parts of the application
    // uses global::tracer() or global::tracer_with_version() to get a tracer.
    // Cloning simply creates a new reference to the same tracer provider. It is
    // important to hold on to the tracer_provider here, so as to invoke
    // shutdown on it when application ends.
    global::set_tracer_provider(tracer_provider.clone());

    Ok(())
}
pub fn configure_tracing() -> anyhow::Result<()> {
    config_log()
}
const BLACKLISTED_TARGETS: &[&str] = &["h2", "hyper", "tower::buffer"];

struct TargetBlacklistLayer;

impl<S: Subscriber> Layer<S> for TargetBlacklistLayer {
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        let matches_blacklist = BLACKLISTED_TARGETS
            .iter()
            .any(|target| metadata.target().starts_with(target));
        if matches_blacklist {
            Interest::never()
        } else {
            Interest::always()
        }
    }
}
