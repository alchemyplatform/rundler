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
use serde::{Deserialize, Serialize};

/// On-chain state that the state-gas part of pre-verification gas depends on.
///
/// Under EIP-8037 some gas the EntryPoint does not meter depends on account state: re-creating
/// a zero deposit slot after metering, and the account and code creation of an EIP-7702
/// authorization. Unknown values (`None`) are priced as the worst case.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PvgState {
    /// Whether the sender's EntryPoint deposit is zero. Only matters for operations without a
    /// paymaster, where the sender pays and its deposit receives the refund.
    pub sender_deposit_is_zero: Option<bool>,
    /// State of the EIP-7702 authority (the sender). Only matters for operations with an
    /// authorization tuple.
    pub authority: Option<AuthorityState>,
}

impl PvgState {
    /// State with nothing known; every state-dependent term is priced as its worst case
    pub fn unknown() -> Self {
        Self::default()
    }
}

/// State of an EIP-7702 authority account before its authorization is applied
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityState {
    /// The account does not exist (no nonce, balance or code)
    Missing,
    /// The account exists but has no code
    NoCode,
    /// The account already has code (an existing delegation)
    HasCode,
}

impl AuthorityState {
    /// Derives the authority state from the account's code, nonce and balance
    pub fn from_account(code: &[u8], nonce: u64, balance: U256) -> Self {
        if !code.is_empty() {
            Self::HasCode
        } else if nonce > 0 || !balance.is_zero() {
            Self::NoCode
        } else {
            Self::Missing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_state_from_account() {
        assert_eq!(
            AuthorityState::from_account(&[], 0, U256::ZERO),
            AuthorityState::Missing
        );
        assert_eq!(
            AuthorityState::from_account(&[], 1, U256::ZERO),
            AuthorityState::NoCode
        );
        assert_eq!(
            AuthorityState::from_account(&[], 0, U256::from(1)),
            AuthorityState::NoCode
        );
        assert_eq!(
            AuthorityState::from_account(&[0xef, 0x01, 0x00], 0, U256::ZERO),
            AuthorityState::HasCode
        );
    }
}
