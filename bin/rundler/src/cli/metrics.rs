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
use rundler_task::TaskSpawner;

pub fn initialize<'a, T: TaskSpawner>(
    task_spawner: &T,
    sample_interval_millis: u64,
    listen_addr: SocketAddr,
    tags: impl IntoIterator<Item = &'a String>,
    buckets: &[f64],
) -> anyhow::Result<()> {
    let mut builder = PrometheusBuilder::new().with_http_listener(listen_addr);

    let tags: Vec<(&str, &str)> = tags
        .into_iter()
        .filter_map(|t| t.split('=').collect_tuple())
        .collect();
    for (k, v) in tags {
        builder = builder.add_global_label(k, v);
    }

    builder = builder.set_buckets(buckets)?;

    let (recorder, exporter) = builder.build()?;
    task_spawner.spawn_critical(
        "metrics exporter",
        Box::pin(async move {
            if exporter.await.is_err() {
                tracing::error!("metrics exporter failed");
            }
        }),
    );
    let stack = Stack::new(recorder);
    stack.push(PrefixLayer::new("rundler")).install()?;

    task_spawner.spawn_critical(
        "metrics collector",
        Box::pin(async move {
            let collector = Collector::default();
            loop {
                collector.collect();
                tokio::time::sleep(Duration::from_millis(sample_interval_millis)).await;
            }
        }),
    );

    let handle = tokio::runtime::Handle::current();
    let frequency = std::time::Duration::from_millis(sample_interval_millis);
    let runtime_metrics = handle.metrics();
    let runtime_monitor = tokio_metrics::RuntimeMonitor::new(&handle);
    task_spawner.spawn_critical(
        "tokio metrics collector",
        Box::pin(async move {
            for metrics in runtime_monitor.intervals() {
                collect_tokio(&runtime_metrics, metrics);
                tokio::time::sleep(frequency).await;
            }
        }),
    );

    Ok(())
}

#[allow(dead_code)]
#[derive(Metrics)]
#[metrics(scope = "rundler_tokio_rt")]
struct TokioMetrics {
    #[metric(describe = "the total number of tokio wokers.")]
    num_workers: Gauge,
    #[metric(describe = "the number of blocking threads.")]
    num_blocking_threads: Gauge,
    #[metric(
        rename = "active_tasks_count",
        describe = "the number of active threads."
    )]
    num_alive_tasks: Gauge,
    #[metric(describe = "the number of idle threads.")]
    num_idle_blocking_threads: Gauge,
    #[metric(describe = "the number of tasks currently scheduled in the blocking thread pool.")]
    blocking_queue_depth: Gauge,
    #[metric(describe = "the number of times worker threads parked.")]
    total_park_count: Gauge,
    #[metric(describe = "the maximum number of times any worker thread parked.")]
    max_park_count: Gauge,
    #[metric(describe = "the minimum number of times any worker thread parked.")]
    min_park_count: Gauge,
    #[metric(describe = "the average duration of a single invocation of poll on a task.")]
    mean_poll_duration: Gauge,
    #[metric(
        describe = "the average duration of a single invocation of poll on a task on the worker with the lowest value."
    )]
    mean_poll_duration_worker_min: Gauge,
    #[metric(
        describe = "the average duration of a single invocation of poll on a task on the worker with the highest value."
    )]
    mean_poll_duration_worker_max: Gauge,

    #[metric(
        describe = "the number of times worker threads unparked but performed no work before parking again."
    )]
    total_noop_count: Gauge,
    #[metric(
        describe = "the maximum number of times any worker thread unparked but performed no work before parking again."
    )]
    max_noop_count: Gauge,
    #[metric(
        describe = "the minimum number of times any worker thread unparked but performed no work before parking again."
    )]
    min_noop_count: Gauge,

    #[metric(describe = "the number of tasks worker threads stole from another worker thread.")]
    total_steal_count: Gauge,
    #[metric(
        describe = "the maximum number of times any worker thread unparked but performed no work before parking again."
    )]
    max_steal_count: Gauge,
    #[metric(
        describe = "the minimum number of times any worker thread unparked but performed no work before parking again."
    )]
    min_steal_count: Gauge,

    #[metric(
        describe = "the number of times worker threads stole tasks from another worker thread."
    )]
    total_steal_operations: Gauge,
    #[metric(
        describe = "the maximum number of any worker thread stole tasks from another worker thread."
    )]
    max_steal_operations: Gauge,
    #[metric(
        describe = "the maximum number of any worker thread stole tasks from another worker thread."
    )]
    min_steal_operations: Gauge,

    #[metric(describe = "the number of tasks scheduled from outside of the runtime.")]
    num_remote_schedules: Gauge,

    #[metric(describe = "the number of tasks scheduled from worker threads.")]
    total_local_schedule_count: Gauge,
    #[metric(describe = "the maximum number of tasks scheduled from any one worker thread.")]
    max_local_schedule_count: Gauge,
    #[metric(describe = "the minimum number of tasks scheduled from any one worker thread.")]
    min_local_schedule_count: Gauge,

    #[metric(describe = "the number of times worker threads saturated their local queues.")]
    total_overflow_count: Gauge,
    #[metric(describe = "the maximum number of times any one worker saturated its local queue.")]
    max_overflow_count: Gauge,
    #[metric(describe = "the minimum number of times any one worker saturated its local queue.")]
    min_overflow_count: Gauge,

    #[metric(describe = "the number of tasks that have been polled across all worker threads.")]
    total_polls_count: Gauge,
    #[metric(describe = "the maximum number of tasks that have been polled in any worker thread.")]
    max_polls_count: Gauge,
    #[metric(describe = "the minimum number of tasks that have been polled in any worker thread.")]
    min_polls_count: Gauge,

    #[metric(describe = "the amount of time worker threads were busy.")]
    total_busy_duration: Gauge,
    #[metric(describe = "the maximum amount of time a worker thread was busy.")]
    max_busy_duration: Gauge,
    #[metric(describe = "the minimum amount of time a worker thread was busy.")]
    min_busy_duration: Gauge,

    #[metric(
        describe = "the number of tasks currently scheduled in the runtime's injection queue."
    )]
    injection_queue_depth: Gauge,
    #[metric(describe = "the total number of tasks currently scheduled in workers' local queues.")]
    total_local_queue_depth: Gauge,
    #[metric(
        describe = "the maximum number of tasks currently scheduled any worker's local queue."
    )]
    max_local_queue_depth: Gauge,
    #[metric(
        describe = "the minimum number of tasks currently scheduled any worker's local queue."
    )]
    min_local_queue_depth: Gauge,

    #[metric(
        describe = "the number of times that tasks have been forced to yield back to the scheduler after exhausting their task budgets."
    )]
    budget_forced_yield_count: Gauge,
    #[metric(describe = "the number of ready events processed by the runtime’s I/O driver.")]
    io_driver_ready_count: Gauge,
}

macro_rules! log_rm_metric {
    ($tm:ident, $rm:ident, $metric_name:ident) => {
        $tm.$metric_name.set($rm.$metric_name() as f64);
    };
}

macro_rules! log_wm_metric {
    ($tm:ident, $wm:ident, $metric_name:ident) => {
        $tm.$metric_name.set($wm.$metric_name as f64);
    };
    ($tm:ident, $wm:ident, $metric_name:ident, $converter:ident) => {
        $tm.$metric_name.set($wm.$metric_name.$converter() as f64);
    };
}

fn collect_tokio(
    runtime_metrics: &tokio::runtime::RuntimeMetrics,
    worker_metrics: tokio_metrics::RuntimeMetrics,
) {
    gauge!(format!("{}num_workers", TOKIO_PREFIX)).set(runtime_metrics.num_workers() as f64);
    gauge!(format!("{}num_blocking_threads", TOKIO_PREFIX))
        .set(runtime_metrics.num_blocking_threads() as f64);
    gauge!(format!("{}active_tasks_count", TOKIO_PREFIX))
        .set(runtime_metrics.num_alive_tasks() as f64);
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
