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

use ethers::types::{Address, H256};
#[cfg(feature = "test-utils")]
use mockall::automock;

use super::{error::BuilderError, types::BundlingMode};

/// Builder result
pub type BuilderResult<T> = std::result::Result<T, BuilderError>;

/// Builder
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait Builder: Send + Sync + 'static {
    /// Get the supported entry points of this builder
    async fn get_supported_entry_points(&self) -> BuilderResult<Vec<Address>>;

    /// Trigger the builder to send a bundle now, used for debugging.
    ///
    /// Bundling mode must be set to `Manual`, or this will error
    async fn debug_send_bundle_now(&self) -> BuilderResult<(H256, u64)>;

    /// Set the bundling mode
    async fn debug_set_bundling_mode(&self, mode: BundlingMode) -> BuilderResult<()>;
}
