#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]

//! Rundler providers
//! A provider is a type that provides access to blockchain data and functions

mod ethers;

mod traits;
pub use traits::{
    AggregatorOut, AggregatorSimOut, EntryPoint, HandleOpsOut, Provider, ProviderError,
    ProviderResult,
};
#[cfg(any(test, feature = "test-utils"))]
pub use traits::{MockEntryPoint, MockProvider};
