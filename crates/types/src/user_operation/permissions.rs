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

use alloy_primitives::U256;

/// User operation permissions
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserOperationPermissions {
    /// Whether the user operation is trusted, allowing the bundler to skip untrusted simulation
    pub trusted: bool,
    /// The maximum number of user operations allowed for a sender in the mempool
    pub max_allowed_in_pool_for_sender: Option<usize>,
    /// The allowed percentage of underpriced fees that is accepted into the pool
    pub underpriced_accept_pct: Option<u32>,
    /// The allowed percentage of fees underpriced that is bundled
    pub underpriced_bundle_pct: Option<u32>,
    /// Bundler sponsorship settings
    pub bundler_sponsorship: Option<BundlerSponsorship>,
}

/// Bundler sponsorship settings
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundlerSponsorship {
    /// The maximum cost the bundler is willing to pay for the user operation in WEI
    pub max_cost: U256,
    /// The valid until timestamp of the sponsorship
    pub valid_until: u64,
}
