// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

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
    ProviderResult, StakeManager,
};
#[cfg(any(test, feature = "test-utils"))]
pub use traits::{MockEntryPoint, MockProvider, MockStakeManager};
