use std::fmt::{Debug, Display};

use anyhow::{bail, Context};
use tracing::Level;

pub trait LogWithContext<T> {
    /// Used to log the original error and then wrap it in an anyhow::Error
    fn log_context<C>(self, context: C) -> Result<T, anyhow::Error>
    where
        C: Display + Send + Sync + 'static;

    /// used to log the original error and then wrap it in an anyhow::Error while
    /// lazy evaluating the context
    fn log_with_context<C, F>(self, context: F) -> Result<T, anyhow::Error>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;
}

pub trait LogOnError {
    /// This will log an error if there is one, but will preserve the original error type
    fn log_on_error<C>(self, context: C) -> Self
    where
        C: Display + Send + Sync + 'static;

    /// This will log at the given level if there is an error, but will preserve the original error type
    fn log_on_error_level<C>(self, level: Level, context: C) -> Self
    where
        C: Display + Send + Sync + 'static;
}

impl<T, E> LogWithContext<T> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn log_context<C>(self, context: C) -> Result<T, anyhow::Error>
    where
        C: Display + Send + Sync + 'static,
    {
        match self {
            Ok(ok) => Ok(ok),
            Err(error) => {
                tracing::error!("{context}: {error:?}");

                Err(error).context(context)
            }
        }
    }

    fn log_with_context<C, F>(self, context: F) -> Result<T, anyhow::Error>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Ok(ok) => Ok(ok),
            Err(error) => {
                let context = context();
                tracing::error!("{context}: {error:?}");

                Err(error).context(context)
            }
        }
    }
}

impl<T, E> LogOnError for Result<T, E>
where
    E: Debug,
{
    fn log_on_error<C>(self, context: C) -> Result<T, E>
    where
        C: Display + Send + Sync + 'static,
    {
        self.log_on_error_level(Level::ERROR, context)
    }

    fn log_on_error_level<C>(self, level: Level, context: C) -> Result<T, E>
    where
        C: Display + Send + Sync + 'static,
    {
        match self {
            Err(error) => {
                log_at_level(level, &format!("{context}: {error:?}"));
                Err(error)
            }
            _ => self,
        }
    }
}

impl<T> LogWithContext<T> for Option<T> {
    fn log_context<C>(self, context: C) -> Result<T, anyhow::Error>
    where
        C: Display + Send + Sync + 'static,
    {
        match self {
            Some(ok) => Ok(ok),
            None => {
                tracing::error!("{context}");
                bail!("{context}")
            }
        }
    }

    fn log_with_context<C, F>(self, context: F) -> Result<T, anyhow::Error>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Some(ok) => Ok(ok),
            None => {
                let context = context();
                tracing::error!("{context}");
                bail!("{context}")
            }
        }
    }
}

impl<T> LogOnError for Option<T> {
    fn log_on_error<C>(self, context: C) -> Self
    where
        C: Display + Send + Sync + 'static,
    {
        self.log_on_error_level(Level::ERROR, context)
    }

    fn log_on_error_level<C>(self, level: Level, context: C) -> Self
    where
        C: Display + Send + Sync + 'static,
    {
        if self.is_none() {
            log_at_level(level, &format!("{context}"));
        }

        self
    }
}

fn log_at_level(level: Level, s: &str) {
    match level {
        Level::TRACE => tracing::trace!(s),
        Level::DEBUG => tracing::debug!(s),
        Level::INFO => tracing::info!(s),
        Level::WARN => tracing::warn!(s),
        Level::ERROR => tracing::error!(s),
    }
}
