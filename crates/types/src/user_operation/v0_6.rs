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

use ethers::{
    abi::{encode, AbiEncode, Token},
    types::{Address, Bytes, H256, U256},
    utils::keccak256,
};
use strum::IntoEnumIterator;

use super::{GasOverheads, UserOperationId};
pub use crate::contracts::v0_6::shared_types::{UserOperation, UserOpsPerAggregator};
use crate::entity::{Entity, EntityType};

impl UserOperation {
    /// asdf
    pub fn hash(&self, entry_point: Address, chain_id: u64) -> H256 {
        keccak256(encode(&[
            Token::FixedBytes(keccak256(self.pack_for_hash()).to_vec()),
            Token::Address(entry_point),
            Token::Uint(chain_id.into()),
        ]))
        .into()
    }

    /// asdf
    pub fn id(&self) -> UserOperationId {
        UserOperationId {
            sender: self.sender,
            nonce: self.nonce,
        }
    }

    /// asdf
    pub fn factory(&self) -> Option<Address> {
        Self::get_address_from_field(&self.init_code)
    }

    /// asdf
    pub fn paymaster(&self) -> Option<Address> {
        Self::get_address_from_field(&self.paymaster_and_data)
    }

    /// asdf
    pub fn max_gas_cost(&self) -> U256 {
        let mul = if self.paymaster().is_some() { 3 } else { 1 };
        self.max_fee_per_gas
            * (self.pre_verification_gas + self.call_gas_limit + self.verification_gas_limit * mul)
    }

    /// asdf
    pub fn heap_size(&self) -> usize {
        self.init_code.len()
            + self.call_data.len()
            + self.paymaster_and_data.len()
            + self.signature.len()
    }

    /// asdf
    pub fn entities(&'_ self) -> Vec<Entity> {
        EntityType::iter()
            .filter_map(|entity| {
                self.entity_address(entity)
                    .map(|address| Entity::new(entity, address))
            })
            .collect()
    }

    /// asdf
    pub fn total_verification_gas_limit(&self) -> U256 {
        let mul = if self.paymaster().is_some() { 2 } else { 1 };
        self.verification_gas_limit * mul
    }

    /// asdf
    pub fn calc_static_pre_verification_gas(&self, include_fixed_gas_overhead: bool) -> U256 {
        let ov = GasOverheads::default();
        let encoded_op = self.clone().encode();
        let length_in_words = encoded_op.len() / 32; // size of packed user op is always a multiple of 32 bytes
        let call_data_cost: U256 = encoded_op
            .iter()
            .map(|&x| {
                if x == 0 {
                    ov.zero_byte
                } else {
                    ov.non_zero_byte
                }
            })
            .reduce(|a, b| a + b)
            .unwrap_or_default();

        call_data_cost
            + ov.per_user_op
            + ov.per_user_op_word * length_in_words
            + (if include_fixed_gas_overhead {
                ov.transaction_gas_overhead
            } else {
                0.into()
            })
    }

    fn get_address_from_field(data: &Bytes) -> Option<Address> {
        if data.len() < 20 {
            None
        } else {
            Some(Address::from_slice(&data[..20]))
        }
    }

    fn pack_for_hash(&self) -> Bytes {
        let hash_init_code = keccak256(self.init_code.clone());
        let hash_call_data = keccak256(self.call_data.clone());
        let hash_paymaster_and_data = keccak256(self.paymaster_and_data.clone());

        encode(&[
            Token::Address(self.sender),
            Token::Uint(self.nonce),
            Token::FixedBytes(hash_init_code.to_vec()),
            Token::FixedBytes(hash_call_data.to_vec()),
            Token::Uint(self.call_gas_limit),
            Token::Uint(self.verification_gas_limit),
            Token::Uint(self.pre_verification_gas),
            Token::Uint(self.max_fee_per_gas),
            Token::Uint(self.max_priority_fee_per_gas),
            Token::FixedBytes(hash_paymaster_and_data.to_vec()),
        ])
        .into()
    }

    fn entity_address(&self, entity: EntityType) -> Option<Address> {
        match entity {
            EntityType::Account => Some(self.sender),
            EntityType::Paymaster => self.paymaster(),
            EntityType::Factory => self.factory(),
            EntityType::Aggregator => None,
        }
    }
}

impl From<UserOperation> for super::UserOperation {
    fn from(op: UserOperation) -> Self {
        super::UserOperation::V0_6(op)
    }
}

#[cfg(test)]
mod tests {

    use ethers::types::{Bytes, U256};

    use super::*;

    #[test]
    fn test_hash_zeroed() {
        // Testing a user operation hash against the hash generated by the
        // entrypoint contract getUserOpHash() function with entrypoint address
        // at 0x66a15edcc3b50a663e72f1457ffd49b9ae284ddc and chain ID 1337.
        //
        // UserOperation = {
        //     sender: '0x0000000000000000000000000000000000000000',
        //     nonce: 0,
        //     initCode: '0x',
        //     callData: '0x',
        //     callGasLimit: 0,
        //     verificationGasLimit: 0,
        //     preVerificationGas: 0,
        //     maxFeePerGas: 0,
        //     maxPriorityFeePerGas: 0,
        //     paymasterAndData: '0x',
        //     signature: '0x',
        //   }
        //
        // Hash: 0xdca97c3b49558ab360659f6ead939773be8bf26631e61bb17045bb70dc983b2d
        let operation = UserOperation {
            sender: "0x0000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
            nonce: U256::zero(),
            init_code: Bytes::default(),
            call_data: Bytes::default(),
            call_gas_limit: U256::zero(),
            verification_gas_limit: U256::zero(),
            pre_verification_gas: U256::zero(),
            max_fee_per_gas: U256::zero(),
            max_priority_fee_per_gas: U256::zero(),
            paymaster_and_data: Bytes::default(),
            signature: Bytes::default(),
        };
        let entry_point = "0x66a15edcc3b50a663e72f1457ffd49b9ae284ddc"
            .parse()
            .unwrap();
        let chain_id = 1337;
        let hash = operation.hash(entry_point, chain_id);
        assert_eq!(
            hash,
            "0xdca97c3b49558ab360659f6ead939773be8bf26631e61bb17045bb70dc983b2d"
                .parse()
                .unwrap()
        );
    }

    #[test]
    fn test_hash() {
        // Testing a user operation hash against the hash generated by the
        // entrypoint contract getUserOpHash() function with entrypoint address
        // at 0x66a15edcc3b50a663e72f1457ffd49b9ae284ddc and chain ID 1337.
        //
        // UserOperation = {
        //     sender: '0x1306b01bc3e4ad202612d3843387e94737673f53',
        //     nonce: 8942,
        //     initCode: '0x6942069420694206942069420694206942069420',
        //     callData: '0x0000000000000000000000000000000000000000080085',
        //     callGasLimit: 10000,
        //     verificationGasLimit: 100000,
        //     preVerificationGas: 100,
        //     maxFeePerGas: 99999,
        //     maxPriorityFeePerGas: 9999999,
        //     paymasterAndData:
        //       '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        //     signature:
        //       '0xda0929f527cded8d0a1eaf2e8861d7f7e2d8160b7b13942f99dd367df4473a',
        //   }
        //
        // Hash: 0x484add9e4d8c3172d11b5feb6a3cc712280e176d278027cfa02ee396eb28afa1
        let operation = UserOperation {
            sender: "0x1306b01bc3e4ad202612d3843387e94737673f53"
                .parse()
                .unwrap(),
            nonce: 8942.into(),
            init_code: "0x6942069420694206942069420694206942069420"
                .parse()
                .unwrap(),
            call_data: "0x0000000000000000000000000000000000000000080085"
                .parse()
                .unwrap(),
            call_gas_limit: 10000.into(),
            verification_gas_limit: 100000.into(),
            pre_verification_gas: 100.into(),
            max_fee_per_gas: 99999.into(),
            max_priority_fee_per_gas: 9999999.into(),
            paymaster_and_data:
                "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .parse()
                    .unwrap(),
            signature: "0xda0929f527cded8d0a1eaf2e8861d7f7e2d8160b7b13942f99dd367df4473a"
                .parse()
                .unwrap(),
        };
        let entry_point = "0x66a15edcc3b50a663e72f1457ffd49b9ae284ddc"
            .parse()
            .unwrap();
        let chain_id = 1337;
        let hash = operation.hash(entry_point, chain_id);
        assert_eq!(
            hash,
            "0x484add9e4d8c3172d11b5feb6a3cc712280e176d278027cfa02ee396eb28afa1"
                .parse()
                .unwrap()
        );
    }

    #[test]
    fn test_get_address_from_field() {
        let paymaster_and_data: Bytes =
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .parse()
                .unwrap();
        let address = UserOperation::get_address_from_field(&paymaster_and_data).unwrap();
        assert_eq!(
            address,
            "0x0123456789abcdef0123456789abcdef01234567"
                .parse()
                .unwrap()
        );
    }
}
