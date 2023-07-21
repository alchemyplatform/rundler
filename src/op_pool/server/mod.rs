#![allow(dead_code)]
#![allow(unused_imports)]
mod error;
mod local;
mod remote;

pub use error::PoolServerError;
use ethers::types::{Address, H256};
pub use local::{spawn_local_mempool_server, LocalPoolClient, ServerRequest};
#[cfg(test)]
use mockall::automock;
pub use remote::{connect_remote_pool_client, spawn_remote_mempool_server, RemotePoolClient};
use tokio::sync::mpsc;
use tonic::async_trait;

use super::{mempool::PoolOperation, Reputation};
use crate::{
    common::types::{Entity, UserOperation},
    op_pool::LocalPoolServerRequest,
};

pub type Error = error::PoolServerError;
pub type PoolResult<T> = std::result::Result<T, Error>;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait PoolClient: Send + Sync + 'static {
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
}

#[derive(Debug)]
pub enum PoolClientMode {
    Local {
        sender: mpsc::Sender<LocalPoolServerRequest>,
    },
    Remote {
        url: String,
    },
}
