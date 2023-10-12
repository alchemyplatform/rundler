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

use ethers::types::{Address, U256};
use rundler_types::UserOperation;
use ssz_derive::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub(crate) struct UserOperationSsz {
    sender: Vec<u8>,
    nonce: U256,
    init_code: Vec<u8>,
    call_data: Vec<u8>,
    call_gas_limit: U256,
    verification_gas_limit: U256,
    pre_verification_gas: U256,
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
    paymaster_and_data: Vec<u8>,
    signature: Vec<u8>,
}

impl From<UserOperation> for UserOperationSsz {
    fn from(uo: UserOperation) -> Self {
        Self {
            sender: uo.sender.as_bytes().to_vec(),
            nonce: uo.nonce,
            init_code: uo.init_code.to_vec(),
            call_data: uo.call_data.to_vec(),
            call_gas_limit: uo.call_gas_limit,
            verification_gas_limit: uo.verification_gas_limit,
            pre_verification_gas: uo.pre_verification_gas,
            max_fee_per_gas: uo.max_fee_per_gas,
            max_priority_fee_per_gas: uo.max_priority_fee_per_gas,
            paymaster_and_data: uo.paymaster_and_data.to_vec(),
            signature: uo.signature.to_vec(),
        }
    }
}

impl TryFrom<UserOperationSsz> for UserOperation {
    type Error = &'static str;

    fn try_from(uo_ssz: UserOperationSsz) -> Result<Self, Self::Error> {
        if uo_ssz.sender.len() != 20 {
            return Err("invalid sender bytes");
        }

        Ok(Self {
            sender: Address::from_slice(&uo_ssz.sender),
            nonce: uo_ssz.nonce,
            init_code: uo_ssz.init_code.into(),
            call_data: uo_ssz.call_data.into(),
            call_gas_limit: uo_ssz.call_gas_limit,
            verification_gas_limit: uo_ssz.verification_gas_limit,
            pre_verification_gas: uo_ssz.pre_verification_gas,
            max_fee_per_gas: uo_ssz.max_fee_per_gas,
            max_priority_fee_per_gas: uo_ssz.max_priority_fee_per_gas,
            paymaster_and_data: uo_ssz.paymaster_and_data.into(),
            signature: uo_ssz.signature.into(),
        })
    }
}

/// The encoding of a protocol.
///
/// Currently only SSZSnappy is supported.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Encoding {
    SSZSnappy,
}
