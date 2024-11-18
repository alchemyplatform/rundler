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

use alloy_primitives::{Address, Parity, Signature, U256};
use serde::{Deserialize, Serialize};

/// authorization tuple for 7702 txn support
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Authorization {
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

impl From<Authorization> for alloy_eips::eip7702::SignedAuthorization {
    fn from(value: Authorization) -> Self {
        let authorization = alloy_eips::eip7702::Authorization {
            chain_id: U256::from(value.chain_id),
            address: value.address,
            nonce: value.nonce,
        };
        let signature = Signature::new(value.r, value.s, Parity::Eip155(value.y_parity.into()));
        authorization.into_signed(signature)
    }
}
