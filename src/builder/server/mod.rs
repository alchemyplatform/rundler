mod local;
mod remote;

use ethers::types::{Address, H256};
pub use local::{
    client::LocalBuilderClient,
    server::{spawn_local_builder_server, ServerRequest as LocalBuilderServerRequest},
};
#[cfg(test)]
use mockall::automock;
pub use remote::{client::connect_remote_builder_client, server::spawn_remote_builder_server};
use tonic::async_trait;

use super::BundlingMode;

#[derive(Debug, thiserror::Error)]
pub enum BuilderServerError {
    #[error("Unexpected response from BuilderServer")]
    UnexpectedResponse,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Error = BuilderServerError;
pub type BuilderResult<T> = std::result::Result<T, Error>;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait BuilderClient: Send + Sync + 'static {
    async fn get_supported_entry_points(&self) -> BuilderResult<Vec<Address>>;

    async fn debug_send_bundle_now(&self) -> BuilderResult<H256>;

    async fn debug_set_bundling_mode(&self, mode: BundlingMode) -> BuilderResult<()>;
}
