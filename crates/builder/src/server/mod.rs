mod local;
mod remote;

use async_trait::async_trait;
use ethers::types::{Address, H256};
pub use local::{LocalBuilderBuilder, LocalBuilderHandle};
#[cfg(feature = "test-utils")]
use mockall::automock;
use parse_display::Display;
pub(crate) use remote::spawn_remote_builder_server;
pub use remote::RemoteBuilderClient;
use serde::{Deserialize, Serialize};

/// Builder server errors
#[derive(Debug, thiserror::Error)]
pub enum BuilderServerError {
    /// Builder returned an unexpected response type for the given request
    #[error("Unexpected response from BuilderServer")]
    UnexpectedResponse,
    /// Internal errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Builder server result
pub type BuilderResult<T> = std::result::Result<T, BuilderServerError>;

/// Builder server
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait]
pub trait BuilderServer: Send + Sync + 'static {
    /// Get the supported entry points of this builder
    async fn get_supported_entry_points(&self) -> BuilderResult<Vec<Address>>;

    /// Trigger the builder to send a bundle now, used for debugging.
    ///
    /// Bundling mode must be set to `Manual`, or this will error
    async fn debug_send_bundle_now(&self) -> BuilderResult<H256>;

    /// Set the bundling mode
    async fn debug_set_bundling_mode(&self, mode: BundlingMode) -> BuilderResult<()>;
}

/// Builder bundling mode
#[derive(Display, Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[display(style = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum BundlingMode {
    /// Manual bundling mode for debugging.
    ///
    /// Bundles will only be sent when `debug_send_bundle_now` is called.
    Manual,
    /// Auto bundling mode for normal operation.
    ///
    /// Bundles will be sent automatically.
    Auto,
}
