mod error;
mod local;
mod remote;

use std::pin::Pin;

pub use error::PoolServerError;
use ethers::types::{Address, H256};
use futures_util::Stream;
pub use local::{LocalPoolBuilder, LocalPoolHandle};
#[cfg(test)]
use mockall::automock;
pub use remote::{spawn_remote_mempool_server, RemotePoolClient};
use tonic::async_trait;

use super::{mempool::PoolOperation, Reputation};
use crate::common::types::{Entity, UserOperation};

pub type PoolResult<T> = std::result::Result<T, PoolServerError>;

#[derive(Clone, Debug)]
pub struct NewHead {
    pub block_hash: H256,
    pub block_number: u64,
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait PoolServer: Send + Sync + 'static {
    async fn get_supported_entry_points(&self) -> PoolResult<Vec<Address>>;

    async fn add_op(&self, entry_point: Address, op: UserOperation) -> PoolResult<H256>;

    async fn get_ops(&self, entry_point: Address, max_ops: u64) -> PoolResult<Vec<PoolOperation>>;

    async fn remove_ops(&self, entry_point: Address, ops: Vec<H256>) -> PoolResult<()>;

    async fn remove_entities(&self, entry_point: Address, entities: Vec<Entity>) -> PoolResult<()>;

    async fn debug_clear_state(&self) -> PoolResult<()>;

    async fn debug_dump_mempool(&self, entry_point: Address) -> PoolResult<Vec<PoolOperation>>;

    async fn debug_set_reputations(
        &self,
        entry_point: Address,
        reputations: Vec<Reputation>,
    ) -> PoolResult<()>;

    async fn debug_dump_reputation(&self, entry_point: Address) -> PoolResult<Vec<Reputation>>;

    async fn subscribe_new_heads(&self) -> PoolResult<Pin<Box<dyn Stream<Item = NewHead> + Send>>>;
}
