#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
//! Mempool implementation for the Rundler.

mod chain;

mod emit;
pub use emit::OpPoolEvent as PoolEvent;

mod mempool;
pub use mempool::{MempoolError, PoolConfig, PoolOperation, Reputation, ReputationStatus};

mod server;
#[cfg(feature = "test-utils")]
pub use server::MockPoolServer;
pub use server::{
    LocalPoolBuilder, LocalPoolHandle, PoolResult, PoolServer, PoolServerError, RemotePoolClient,
};

mod task;
pub use task::{Args as PoolTaskArgs, PoolTask};
