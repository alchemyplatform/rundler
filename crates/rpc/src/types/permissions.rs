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

use alloy_primitives::U64;
use rundler_types::{chain::ChainSpec, UserOperationPermissions};
use serde::{Deserialize, Serialize};

use super::FromRpc;

/// User operation permissions
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcUserOperationPermissions {
    /// Whether the user operation is trusted, allowing the bundler to skip untrusted simulation
    #[serde(default)]
    pub(crate) trusted: bool,
    /// The maximum sender allowed in the pool
    #[serde(default)]
    pub(crate) max_allowed_in_pool_for_sender: Option<U64>,
    /// The allowed percentage of underpriced fees that is accepted into the pool
    #[serde(default)]
    pub(crate) underpriced_accept_pct: Option<U64>,
    /// The allowed percentage of fees underpriced that is bundled
    #[serde(default)]
    pub(crate) underpriced_bundle_pct: Option<U64>,
}

impl FromRpc<RpcUserOperationPermissions> for UserOperationPermissions {
    fn from_rpc(rpc: RpcUserOperationPermissions, _chain_spec: &ChainSpec) -> Self {
        UserOperationPermissions {
            trusted: rpc.trusted,
            max_allowed_in_pool_for_sender: rpc.max_allowed_in_pool_for_sender.map(|c| c.to()),
            underpriced_accept_pct: rpc.underpriced_accept_pct.map(|c| c.to()),
            underpriced_bundle_pct: rpc.underpriced_bundle_pct.map(|c| c.to()),
        }
    }
}
