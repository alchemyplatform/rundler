#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
//! JSON-RPC server for the Rundler.

mod debug;
pub use debug::DebugApiClient;

mod error;

mod eth;
pub use eth::{EthApiClient, EthApiSettings};

mod health;
mod metrics;

mod rundler;
pub use rundler::RundlerApiClient;

mod task;
pub use task::{Args as RpcTaskArgs, RpcTask};

mod types;
pub use types::{RichUserOperation, RpcUserOperation, UserOperationReceipt};
