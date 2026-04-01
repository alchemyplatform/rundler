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

use std::{fmt, str::FromStr};

use alloy_primitives::{B256, U256, keccak256};
use alloy_sol_types::SolValue;
use parse_display::Display;
use serde::{Deserialize, Serialize};

use crate::authorization::Eip7702Auth;

/// Builder bundling mode
#[derive(Display, Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[display(style = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum BundlingMode {
    /// Manual bundling mode for debugging.
    ///
    /// Bundles will only be sent when `debug_send_bundle_now` is called.
    Manual,
    /// Auto bundling mode for normal operation.
    ///
    /// Bundles will be sent automatically.
    Auto,
}

/// Unique identifier for a sponsored delegation request.
///
/// Computed as `keccak256(abi.encode(chainId, delegateAddress, nonce, yParity, r, s))`,
/// matching how user operation hashes are derived from their exact payload.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct DelegationId(B256);

impl DelegationId {
    /// Derive an ID from a signed EIP-7702 authorization by hashing its payload.
    ///
    /// Computes `keccak256(abi.encode(chainId, delegateAddress, nonce, yParity, r, s))`.
    /// This is infallible and does not require recovering the signer.
    pub fn from_auth(auth: &Eip7702Auth) -> Self {
        let encoded = (
            auth.chain_id,
            auth.address,
            auth.nonce,
            U256::from(auth.y_parity()),
            auth.r(),
            auth.s(),
        )
            .abi_encode();
        Self(keccak256(encoded))
    }
}

impl fmt::Display for DelegationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for DelegationId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<B256>()
            .map(Self)
            .map_err(|e| anyhow::anyhow!("invalid delegation ID '{}': {e}", s))
    }
}

impl From<DelegationId> for B256 {
    fn from(id: DelegationId) -> Self {
        id.0
    }
}

impl From<B256> for DelegationId {
    fn from(hash: B256) -> Self {
        Self(hash)
    }
}

/// Status of a sponsored delegation request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DelegationStatus {
    /// The delegation transaction has been submitted and is waiting to be mined.
    Pending,
    /// The delegation transaction has been mined.
    Mined {
        /// Hash of the mined transaction.
        tx_hash: B256,
    },
    /// The delegation ID is not recognized (never submitted, or pruned after mining).
    Unknown,
}
