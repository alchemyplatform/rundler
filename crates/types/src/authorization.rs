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
//! 7702 authorization list suport.

use std::ops::Deref;

use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_primitives::{Address, U256};
use rundler_utils::random::random_bytes_array;
use serde::{Deserialize, Serialize};

/// authorization tuple for 7702 txn support
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip7702Auth {
    #[serde(flatten)]
    inner: SignedAuthorization,
}

impl Default for Eip7702Auth {
    fn default() -> Self {
        Self {
            inner: SignedAuthorization::new_unchecked(
                Authorization {
                    chain_id: U256::ZERO,
                    address: Address::ZERO,
                    nonce: 0,
                },
                0,
                U256::ZERO,
                U256::ZERO,
            ),
        }
    }
}

impl From<SignedAuthorization> for Eip7702Auth {
    fn from(value: SignedAuthorization) -> Self {
        Eip7702Auth { inner: value }
    }
}

impl From<Eip7702Auth> for SignedAuthorization {
    fn from(value: Eip7702Auth) -> Self {
        value.inner
    }
}

impl Deref for Eip7702Auth {
    type Target = SignedAuthorization;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Eip7702Auth {
    /// Genreate a random filled Eip7702Auth entity.
    pub fn random_fill(&self) -> Eip7702Auth {
        Self {
            inner: SignedAuthorization::new_unchecked(
                Authorization {
                    chain_id: self.chain_id,
                    address: self.address,
                    nonce: u64::from_le_bytes(random_bytes_array::<8, 4>()),
                },
                27,
                U256::from_le_bytes(random_bytes_array::<32, 8>()),
                U256::from_le_bytes(random_bytes_array::<32, 8>()),
            ),
        }
    }

    /// Generate a maxfilled Eip7702Auth entity.
    pub fn max_fill(&self) -> Eip7702Auth {
        Self {
            inner: SignedAuthorization::new_unchecked(
                Authorization {
                    chain_id: self.chain_id,
                    address: self.address,
                    nonce: u64::MAX,
                },
                27,
                U256::MAX,
                U256::MAX,
            ),
        }
    }

    /// validate a Eip7702Auth's signature.
    pub fn validate(&self, signer: Address) -> anyhow::Result<()> {
        match self.recover_authority() {
            Ok(address) => {
                if address == signer {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Invalid signature for EIP-7702 authorization tuple - expected {:?} recovered {:?}", signer, address))
                }
            }
            Err(e) => Err(anyhow::anyhow!(e.to_string())),
        }
    }

    /// Create from chain id and address, for the fill methods.
    pub fn from_chain_id_and_address(chain_id: u64, address: Address) -> Self {
        Self {
            inner: SignedAuthorization::new_unchecked(
                Authorization {
                    chain_id: U256::from(chain_id),
                    address,
                    nonce: 0,
                },
                0,
                U256::ZERO,
                U256::ZERO,
            ),
        }
    }
}
