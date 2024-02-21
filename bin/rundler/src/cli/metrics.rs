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

use std::{net::SocketAddr, time::Duration};

use itertools::Itertools;
use metrics::gauge;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_process::Collector;
use metrics_util::layers::{PrefixLayer, Stack};

pub fn initialize<'a>(
    sample_interval_millis: u64,
    listen_addr: SocketAddr,
    tags: impl IntoIterator<Item = &'a String>,
) -> anyhow::Result<()> {
    let mut builder = PrometheusBuilder::new().with_http_listener(listen_addr);

    let tags: Vec<(&str, &str)> = tags
        .into_iter()
        .filter_map(|t| t.split('=').collect_tuple())
        .collect();
    for (k, v) in tags {
        builder = builder.add_global_label(k, v);
    }

    let (recorder, exporter) = builder.build()?;
    tokio::spawn(exporter);
    Stack::new(recorder)
        .push(PrefixLayer::new("rundler"))
        .install()?;

    tokio::spawn(async move {
        let collector = Collector::default();
        loop {
            collector.collect();
            tokio::time::sleep(Duration::from_millis(sample_interval_millis)).await;
        }
    });

    let handle = tokio::runtime::Handle::current();
    let frequency = std::time::Duration::from_millis(sample_interval_millis);
    let runtime_metrics = handle.metrics();
    let runtime_monitor = tokio_metrics::RuntimeMonitor::new(&handle);
    tokio::spawn(async move {
        for metrics in runtime_monitor.intervals() {
            collect_tokio(&runtime_metrics, metrics);
            tokio::time::sleep(frequency).await;
        }
    });

    Ok(())
}

const TOKIO_PREFIX: &str = "tokio_rt_";

fn collect_tokio(
    runtime_metrics: &tokio::runtime::RuntimeMetrics,
    worker_metrics: tokio_metrics::RuntimeMetrics,
) {
    gauge!(format!("{}num_workers", TOKIO_PREFIX)).set(runtime_metrics.num_workers() as f64);
    gauge!(format!("{}num_blocking_threads", TOKIO_PREFIX))
        .set(runtime_metrics.num_blocking_threads() as f64);
    gauge!(format!("{}active_tasks_count", TOKIO_PREFIX))
        .set(runtime_metrics.active_tasks_count() as f64);
    gauge!(format!("{}num_idle_blocking_threads", TOKIO_PREFIX))
        .set(runtime_metrics.num_idle_blocking_threads() as f64);
    gauge!(format!("{}blocking_queue_depth", TOKIO_PREFIX))
        .set(runtime_metrics.blocking_queue_depth() as f64);
    gauge!(format!("{}total_park_count", TOKIO_PREFIX)).set(worker_metrics.total_park_count as f64);
    gauge!(format!("{}max_park_count", TOKIO_PREFIX)).set(worker_metrics.max_park_count as f64);
    gauge!(format!("{}min_park_count", TOKIO_PREFIX)).set(worker_metrics.min_park_count as f64);
    gauge!(format!("{}mean_poll_duration", TOKIO_PREFIX))
        .set(worker_metrics.mean_poll_duration.as_secs_f64());
    gauge!(format!("{}mean_poll_duration_worker_min", TOKIO_PREFIX))
        .set(worker_metrics.mean_poll_duration_worker_min.as_secs_f64());
    gauge!(format!("{}mean_poll_duration_worker_max", TOKIO_PREFIX))
        .set(worker_metrics.mean_poll_duration_worker_max.as_secs_f64());
    gauge!(format!("{}total_noop_count", TOKIO_PREFIX)).set(worker_metrics.total_noop_count as f64);
    gauge!(format!("{}max_noop_count", TOKIO_PREFIX)).set(worker_metrics.max_noop_count as f64);
    gauge!(format!("{}min_noop_count", TOKIO_PREFIX)).set(worker_metrics.min_noop_count as f64);
    gauge!(format!("{}total_steal_count", TOKIO_PREFIX))
        .set(worker_metrics.total_steal_count as f64);
    gauge!(format!("{}max_steal_count", TOKIO_PREFIX),).set(worker_metrics.max_steal_count as f64);
    gauge!(format!("{}min_steal_count", TOKIO_PREFIX),).set(worker_metrics.min_steal_count as f64);
    gauge!(format!("{}total_steal_operations", TOKIO_PREFIX))
        .set(worker_metrics.total_steal_operations as f64);
    gauge!(format!("{}max_steal_operations", TOKIO_PREFIX))
        .set(worker_metrics.max_steal_operations as f64);
    gauge!(format!("{}min_steal_operations", TOKIO_PREFIX))
        .set(worker_metrics.min_steal_operations as f64);
    gauge!(format!("{}num_remote_schedules", TOKIO_PREFIX))
        .set(worker_metrics.num_remote_schedules as f64);
    gauge!(format!("{}total_local_schedule_count", TOKIO_PREFIX))
        .set(worker_metrics.total_local_schedule_count as f64);
    gauge!(format!("{}max_local_schedule_count", TOKIO_PREFIX),)
        .set(worker_metrics.max_local_schedule_count as f64);
    gauge!(format!("{}min_local_schedule_count", TOKIO_PREFIX),)
        .set(worker_metrics.min_local_schedule_count as f64);
    gauge!(format!("{}total_overflow_count", TOKIO_PREFIX))
        .set(worker_metrics.total_overflow_count as f64);
    gauge!(format!("{}max_overflow_count", TOKIO_PREFIX))
        .set(worker_metrics.max_overflow_count as f64);
    gauge!(format!("{}min_overflow_count", TOKIO_PREFIX),)
        .set(worker_metrics.min_overflow_count as f64);
    gauge!(format!("{}total_polls_count", TOKIO_PREFIX))
        .set(worker_metrics.total_polls_count as f64);
    gauge!(format!("{}max_polls_count", TOKIO_PREFIX)).set(worker_metrics.max_polls_count as f64);
    gauge!(format!("{}min_polls_count", TOKIO_PREFIX)).set(worker_metrics.min_polls_count as f64);
    gauge!(format!("{}total_busy_duration", TOKIO_PREFIX))
        .set(worker_metrics.total_busy_duration.as_secs_f64());
    gauge!(format!("{}max_busy_duration", TOKIO_PREFIX))
        .set(worker_metrics.max_busy_duration.as_secs_f64());
    gauge!(format!("{}min_busy_duration", TOKIO_PREFIX))
        .set(worker_metrics.min_busy_duration.as_secs_f64());
    gauge!(format!("{}injection_queue_depth", TOKIO_PREFIX))
        .set(worker_metrics.injection_queue_depth as f64);
    gauge!(format!("{}total_local_queue_depth", TOKIO_PREFIX))
        .set(worker_metrics.total_local_queue_depth as f64);
    gauge!(format!("{}max_local_queue_depth", TOKIO_PREFIX))
        .set(worker_metrics.max_local_queue_depth as f64);
    gauge!(format!("{}min_local_queue_depth", TOKIO_PREFIX))
        .set(worker_metrics.min_local_queue_depth as f64);
    gauge!(format!("{}budget_forced_yield_count", TOKIO_PREFIX))
        .set(worker_metrics.budget_forced_yield_count as f64);
    gauge!(format!("{}io_driver_ready_count", TOKIO_PREFIX))
        .set(worker_metrics.io_driver_ready_count as f64);
}
