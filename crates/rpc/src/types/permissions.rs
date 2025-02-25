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
}

impl FromRpc<RpcUserOperationPermissions> for UserOperationPermissions {
    fn from_rpc(rpc: RpcUserOperationPermissions, _chain_spec: &ChainSpec) -> Self {
        UserOperationPermissions {
            trusted: rpc.trusted,
        }
    }
}
