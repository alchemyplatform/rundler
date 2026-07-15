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

//! Utilities for 7702 authorization tuples

use alloy_primitives::{Address, FixedBytes, fixed_bytes};
use alloy_rpc_types_eth::state::{AccountOverride, StateOverride};

/// EIP-7702 delegation designator prefix
const DELEGATION_PREFIX: FixedBytes<3> = fixed_bytes!("ef0100");

/// Apply a [7702](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7702.md)
/// overrides to `StateOverride`.
pub fn apply_7702_overrides(
    state_override: &mut StateOverride,
    sender: Address,
    eip7702_auth_address: Address,
) {
    state_override.entry(sender).or_insert({
        let code: FixedBytes<23> = DELEGATION_PREFIX.concat_const(eip7702_auth_address.into());

        AccountOverride {
            code: Some((code).into()),
            ..Default::default()
        }
    });
}

/// Extract the delegate address from an EIP-7702 delegation designator
/// (`0xef0100 ‖ address`). Returns `None` for any other code, including empty.
pub fn eip7702_delegate_from_code(code: &[u8]) -> Option<Address> {
    let delegate = code.strip_prefix(DELEGATION_PREFIX.as_slice())?;
    (delegate.len() == Address::len_bytes()).then(|| Address::from_slice(delegate))
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;

    use super::*;

    #[test]
    fn test_eip7702_delegate_from_code() {
        let delegate = address!("0x1234567890123456789012345678901234567890");
        let code = [DELEGATION_PREFIX.as_slice(), delegate.as_slice()].concat();
        assert_eq!(eip7702_delegate_from_code(&code), Some(delegate));

        // empty code
        assert_eq!(eip7702_delegate_from_code(&[]), None);
        // wrong prefix
        let code = [&[0xef, 0x01, 0x01][..], delegate.as_slice()].concat();
        assert_eq!(eip7702_delegate_from_code(&code), None);
        // truncated delegate
        assert_eq!(eip7702_delegate_from_code(&code[..22]), None);
        // trailing bytes
        let code = [DELEGATION_PREFIX.as_slice(), delegate.as_slice(), &[0x00]].concat();
        assert_eq!(eip7702_delegate_from_code(&code), None);
    }
}
