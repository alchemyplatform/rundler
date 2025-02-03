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

use alloy_eips::eip7702::SignedAuthorization;
use alloy_primitives::{Address, U256};
use rand::{self, RngCore};
use serde::{Deserialize, Serialize};

/// authorization tuple for 7702 txn support
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Eip7702Auth {
    /// The chain ID of the authorization.
    pub chain_id: u64,
    /// The address of the authorization.
    pub address: Address,
    /// The nonce for the authorization.
    pub nonce: u64,
    /// signed authorizzation tuple.
    pub y_parity: u8,
    /// signed authorizzation tuple.
    pub r: U256,
    /// signed authorizzation tuple.
    pub s: U256,
}

impl From<Eip7702Auth> for alloy_eips::eip7702::SignedAuthorization {
    fn from(value: Eip7702Auth) -> Self {
        let authorization = alloy_eips::eip7702::Authorization {
            chain_id: value.chain_id,
            address: value.address,
            nonce: value.nonce,
        };

        SignedAuthorization::new_unchecked(authorization, value.y_parity, value.r, value.s)
    }
}

pub(crate) fn random_bytes_array<const ARR_SIZE: usize, const FILL_SIZE: usize>() -> [u8; ARR_SIZE]
{
    let mut bytes = [0_u8; ARR_SIZE];
    rand::thread_rng().fill_bytes(&mut bytes[..FILL_SIZE]);
    bytes
}

impl Eip7702Auth {
    /// Genreate a random filled Eip7702Auth entity.
    pub fn random_fill() -> Eip7702Auth {
        Self {
            chain_id: u64::from_le_bytes(random_bytes_array::<8, 4>()),
            address: Address::random(),
            nonce: u64::from_le_bytes(random_bytes_array::<8, 4>()),
            y_parity: 27,
            r: U256::from_le_bytes(random_bytes_array::<64, 32>()),
            s: U256::from_le_bytes(random_bytes_array::<64, 32>()),
        }
    }
    /// Generate a maxfilled Eip7702Auth entity.
    pub fn max_fill() -> Eip7702Auth {
        Self {
            chain_id: u64::MAX,
            address: Address::repeat_byte(0xf),
            nonce: u64::MAX,
            y_parity: 27,
            r: U256::MAX,
            s: U256::MAX,
        }
    }

    /// validate a Eip7702Auth's signature.
    pub fn validate(&self) -> anyhow::Result<()> {
        let signed_auth = SignedAuthorization::from(self.clone());
        match signed_auth.recover_authority() {
            Ok(address) => {
                if address == self.address {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Invalid Signature"))
                }
            }
            Err(e) => Err(anyhow::anyhow!(e.to_string())),
        }
    }
}
