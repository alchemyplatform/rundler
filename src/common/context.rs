use std::{convert::Infallible, fmt::Display};

use anyhow::{bail, Context};

pub trait LogWithContext<T, E> {
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

    /// This will log an error if there is one, but will preserve the original error type
    fn log_on_error<C>(self, context: C) -> Self
    where
        C: Display + Send + Sync + 'static;
}

impl<T, E> LogWithContext<T, E> for Result<T, E>
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

    fn log_on_error<C>(self, context: C) -> Result<T, E>
    where
        C: Display + Send + Sync + 'static,
    {
        match self {
            Err(error) => {
                tracing::error!("{context}: {error:?}");
                Err(error)
            }
            _ => self,
        }
    }
}

impl<T> LogWithContext<T, Infallible> for Option<T> {
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

    fn log_on_error<C>(self, context: C) -> Self
    where
        C: Display + Send + Sync + 'static,
    {
        if self.is_none() {
            tracing::error!("{context}");
        }

        self
    }
}
