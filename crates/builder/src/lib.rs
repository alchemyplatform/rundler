#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
//! Bundle builder implementation for the Rundler.

mod bundle_proposer;
mod bundle_sender;

mod emit;
pub use emit::BuilderEvent;

mod sender;

mod server;
pub use server::{
    BuilderResult, BuilderServer, BuilderServerError, BundlingMode, LocalBuilderBuilder,
    LocalBuilderHandle, RemoteBuilderClient,
};

mod signer;

mod task;
pub use task::{Args as BuilderTaskArgs, BuilderTask};

mod transaction_tracker;
