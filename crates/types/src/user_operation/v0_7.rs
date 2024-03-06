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
    abi::{encode, Token},
    types::{Address, Bytes, H256, U128, U256},
    utils::keccak256,
};

use super::UserOperationId;
use crate::{contracts::v0_7::shared_types::PackedUserOperation, Entity};

/// User Operation
///
/// Offchain version, must be packed before sending onchain
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserOperation {
    pub sender: Address,
    pub nonce: U256,
    pub factory: Option<Address>,
    pub factory_data: Bytes,
    pub call_data: Bytes,
    pub call_gas_limit: U128,
    pub verification_gas_limit: U128,
    pub pre_verification_gas: U256,
    pub max_priority_fee_per_gas: U128,
    pub max_fee_per_gas: U128,
    pub paymaster: Option<Address>,
    pub paymaster_verification_gas_limit: U128,
    pub paymaster_post_op_gas_limit: U128,
    pub paymaster_data: Bytes,
    pub signature: Bytes,
    hash: H256,
    packed: PackedUserOperation,
}

impl UserOperation {
    pub fn hash(&self, _entry_point: Address, _chain_id: u64) -> H256 {
        self.hash
    }

    pub fn id(&self) -> UserOperationId {
        UserOperationId {
            sender: self.sender,
            nonce: self.nonce,
        }
    }

    pub fn paymaster(&self) -> Option<Address> {
        self.paymaster
    }

    pub fn factory(&self) -> Option<Address> {
        self.factory
    }

    pub fn max_gas_cost(&self) -> U256 {
        U256::from(self.max_fee_per_gas)
            * (self.pre_verification_gas
                + self.call_gas_limit
                + self.verification_gas_limit
                + self.paymaster_verification_gas_limit
                + self.paymaster_post_op_gas_limit)
    }

    pub fn entities(&self) -> Vec<Entity> {
        let mut ret = vec![Entity::account(self.sender)];
        if let Some(factory) = self.factory {
            ret.push(Entity::factory(factory));
        }
        if let Some(paymaster) = self.paymaster {
            ret.push(Entity::paymaster(paymaster));
        }
        ret
    }

    pub fn heap_size(&self) -> usize {
        unimplemented!()
    }

    pub fn total_verification_gas_limit(&self) -> U256 {
        U256::from(self.verification_gas_limit) + U256::from(self.paymaster_verification_gas_limit)
    }

    /// asdf
    pub fn calc_static_pre_verification_gas(&self, include_fixed_gas_overhead: bool) -> U256 {
        todo!()
    }

    pub fn pack(self) -> PackedUserOperation {
        self.packed
    }
}

impl From<UserOperation> for super::UserOperation {
    fn from(op: UserOperation) -> Self {
        super::UserOperation::V0_7(op)
    }
}

pub struct UserOperationBuilder {
    // required fields for hash
    entry_point: Address,
    chain_id: u64,

    // required fields
    required: UserOperationRequiredFields,

    // optional fields
    factory: Option<Address>,
    factory_data: Bytes,
    paymaster: Option<Address>,
    paymaster_verification_gas_limit: U128,
    paymaster_post_op_gas_limit: U128,
    paymaster_data: Bytes,
}

pub struct UserOperationRequiredFields {
    sender: Address,
    nonce: U256,
    call_data: Bytes,
    call_gas_limit: U128,
    verification_gas_limit: U128,
    pre_verification_gas: U256,
    max_priority_fee_per_gas: U128,
    max_fee_per_gas: U128,
    signature: Bytes,
}

impl UserOperationBuilder {
    pub fn new(entry_point: Address, chain_id: u64, required: UserOperationRequiredFields) -> Self {
        Self {
            entry_point,
            chain_id,
            required,
            factory: None,
            factory_data: Bytes::new(),
            paymaster: None,
            paymaster_verification_gas_limit: U128::zero(),
            paymaster_post_op_gas_limit: U128::zero(),
            paymaster_data: Bytes::new(),
        }
    }

    pub fn factory(mut self, factory: Address, factory_data: Bytes) -> Self {
        self.factory = Some(factory);
        self.factory_data = factory_data;
        self
    }

    pub fn paymaster(
        mut self,
        paymaster: Address,
        paymaster_verification_gas_limit: U128,
        paymaster_post_op_gas_limit: U128,
        paymaster_data: Bytes,
    ) -> Self {
        self.paymaster = Some(paymaster);
        self.paymaster_verification_gas_limit = paymaster_verification_gas_limit;
        self.paymaster_post_op_gas_limit = paymaster_post_op_gas_limit;
        self.paymaster_data = paymaster_data;
        self
    }

    pub fn build(self) -> UserOperation {
        let uo = UserOperation {
            sender: self.required.sender,
            nonce: self.required.nonce,
            factory: self.factory,
            factory_data: self.factory_data,
            call_data: self.required.call_data,
            call_gas_limit: self.required.call_gas_limit,
            verification_gas_limit: self.required.verification_gas_limit,
            pre_verification_gas: self.required.pre_verification_gas,
            max_priority_fee_per_gas: self.required.max_priority_fee_per_gas,
            max_fee_per_gas: self.required.max_fee_per_gas,
            paymaster: self.paymaster,
            paymaster_verification_gas_limit: self.paymaster_verification_gas_limit,
            paymaster_post_op_gas_limit: self.paymaster_post_op_gas_limit,
            paymaster_data: self.paymaster_data,
            signature: self.required.signature,
            hash: H256::zero(),
            packed: PackedUserOperation::default(),
        };

        let packed = pack_user_operation(uo.clone());
        let hash = hash_packed_user_operation(packed.clone(), self.entry_point, self.chain_id);

        UserOperation { hash, packed, ..uo }
    }
}

fn pack_user_operation(uo: UserOperation) -> PackedUserOperation {
    let init_code = if let Some(factory) = uo.factory {
        let mut init_code = factory.as_bytes().to_vec();
        init_code.extend_from_slice(&uo.factory_data);
        Bytes::from(init_code)
    } else {
        Bytes::new()
    };

    let account_gas_limits = concat_128(
        uo.verification_gas_limit.low_u128().to_le_bytes(),
        uo.call_gas_limit.low_u128().to_le_bytes(),
    );

    let gas_fees = concat_128(
        uo.max_priority_fee_per_gas.low_u128().to_le_bytes(),
        uo.max_fee_per_gas.low_u128().to_le_bytes(),
    );

    let paymaster_and_data = if let Some(paymaster) = uo.paymaster {
        let mut paymaster_and_data = paymaster.as_bytes().to_vec();
        paymaster_and_data
            .extend_from_slice(&uo.paymaster_verification_gas_limit.low_u128().to_le_bytes());
        paymaster_and_data
            .extend_from_slice(&uo.paymaster_post_op_gas_limit.low_u128().to_le_bytes());
        paymaster_and_data.extend_from_slice(&uo.paymaster_data);
        Bytes::from(paymaster_and_data)
    } else {
        Bytes::new()
    };

    PackedUserOperation {
        sender: uo.sender,
        nonce: uo.nonce,
        init_code,
        call_data: uo.call_data,
        account_gas_limits,
        pre_verification_gas: uo.pre_verification_gas,
        gas_fees,
        paymaster_and_data,
        signature: uo.signature,
    }
}

fn hash_packed_user_operation(
    puo: PackedUserOperation,
    entry_point: Address,
    chain_id: u64,
) -> H256 {
    let hash_init_code = keccak256(puo.init_code.clone());
    let hash_call_data = keccak256(puo.call_data.clone());
    let hash_paymaster_and_data = keccak256(puo.paymaster_and_data.clone());

    let encoded: Bytes = encode(&[
        Token::Address(puo.sender),
        Token::Uint(puo.nonce),
        Token::FixedBytes(hash_init_code.to_vec()),
        Token::FixedBytes(hash_call_data.to_vec()),
        Token::FixedBytes(puo.account_gas_limits.to_vec()),
        Token::Uint(puo.pre_verification_gas),
        Token::FixedBytes(puo.gas_fees.to_vec()),
        Token::FixedBytes(hash_paymaster_and_data.to_vec()),
    ])
    .into();

    let hashed = keccak256(encoded);

    keccak256(encode(&[
        Token::FixedBytes(hashed.to_vec()),
        Token::Address(entry_point),
        Token::Uint(chain_id.into()),
    ]))
    .into()
}

fn concat_128(a: [u8; 16], b: [u8; 16]) -> [u8; 32] {
    std::array::from_fn(|i| {
        if let Some(i) = i.checked_sub(a.len()) {
            b[i]
        } else {
            a[i]
        }
    })
}
