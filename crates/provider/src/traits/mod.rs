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

//! Traits for the provider module.

mod error;
pub use error::ProviderError;

mod entry_point;
pub use entry_point::*;

mod provider;
#[cfg(feature = "test-utils")]
pub use provider::MockProvider;
pub use provider::{Provider, ProviderResult};
#[cfg(feature = "test-utils")]
pub(crate) mod test_utils;
