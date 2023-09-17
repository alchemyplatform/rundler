//! Utilities for retrying operations.

use std::{future::Future, time::Duration};

use rand::Rng;
use tokio::time;
use tracing::warn;

/// Options for retrying an operation using exponential backoff
/// with jitter.
#[derive(Clone, Copy, Debug)]
pub struct RetryOpts {
    /// Maximum number of attempts to make.
    pub max_attempts: u64,
    /// The first retry is immediately after the first failure (plus jitter).
    /// The next retry after that will wait this long.
    pub min_nonzero_wait: Duration,
    /// The maximum amount of time to wait between retries.
    pub max_wait: Duration,
    /// The maximum amount of jitter to add to the wait time.
    pub max_jitter: Duration,
}

impl Default for RetryOpts {
    fn default() -> Self {
        UnlimitedRetryOpts::default().to_retry_opts_with_max_attempts(10)
    }
}

/// Retry a function using exponential backoff with jitter.
pub async fn with_retries<Func, Fut, Out, Err>(
    description: &str,
    func: Func,
    opts: RetryOpts,
) -> Result<Out, Err>
where
    Func: Fn() -> Fut,
    Fut: Future<Output = Result<Out, Err>>,
{
    let mut next_wait = Duration::ZERO;
    let mut last_error: Option<Err> = None;
    for attempt_number in 1..=opts.max_attempts {
        match func().await {
            Ok(out) => return Ok(out),
            Err(error) => {
                last_error = Some(error);
                warn!("Failed to {description} (attempt {attempt_number})");
            }
        }
        // Grab a new rng each iteration because we can't hold it across awaits.
        let jitter = rand::thread_rng().gen_range(Duration::ZERO..opts.max_jitter);
        time::sleep(next_wait + jitter).await;
        next_wait = (2 * next_wait).clamp(opts.min_nonzero_wait, opts.max_wait);
    }
    Err(last_error.unwrap())
}

/// Special case of `RetryOpts` where the number of attempts is unlimited.
#[derive(Clone, Copy, Debug)]
pub struct UnlimitedRetryOpts {
    /// The first retry is immediately after the first failure (plus jitter).
    pub min_nonzero_wait: Duration,
    /// The maximum amount of time to wait between retries.
    pub max_wait: Duration,
    /// The maximum amount of jitter to add to the wait time.
    pub max_jitter: Duration,
}

impl Default for UnlimitedRetryOpts {
    fn default() -> Self {
        Self {
            min_nonzero_wait: Duration::from_secs(1),
            max_wait: Duration::from_secs(10),
            max_jitter: Duration::from_secs(1),
        }
    }
}

impl UnlimitedRetryOpts {
    fn to_retry_opts_with_max_attempts(self, max_attempts: u64) -> RetryOpts {
        RetryOpts {
            max_attempts,
            min_nonzero_wait: self.min_nonzero_wait,
            max_wait: self.max_wait,
            max_jitter: self.max_jitter,
        }
    }
}

/// Retry a function using exponential backoff with jitter with unlimited retries.
pub async fn with_unlimited_retries<Func, Fut, Out, Err>(
    description: &str,
    func: Func,
    opts: UnlimitedRetryOpts,
) -> Out
where
    Func: Fn() -> Fut,
    Fut: Future<Output = Result<Out, Err>>,
{
    let opts = opts.to_retry_opts_with_max_attempts(u64::MAX);
    with_retries(description, func, opts).await.ok().unwrap()
}
