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

use super::{UserOperation as UserOperationTrait, UserOperationId, UserOperationVariant};
use crate::{contracts::v0_7::shared_types::PackedUserOperation, Entity, GasOverheads};

const ENTRY_POINT_INNER_GAS_OVERHEAD: U256 = U256([10_000, 0, 0, 0]);

/// User Operation for Entry Point v0.7
///
/// Offchain version, must be packed before sending onchain
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserOperation {
    /*
     * Required fields
     */
    /// Sender
    pub sender: Address,
    /// Semi-abstracted nonce
    ///
    /// The first 192 bits are the nonce key, the last 64 bits are the nonce value
    pub nonce: U256,
    /// Calldata
    pub call_data: Bytes,
    /// Call gas limit
    pub call_gas_limit: U128,
    /// Verification gas limit
    pub verification_gas_limit: U128,
    /// Pre-verification gas
    pub pre_verification_gas: U256,
    /// Max priority fee per gas
    pub max_priority_fee_per_gas: U128,
    /// Max fee per gas
    pub max_fee_per_gas: U128,
    /// Signature
    pub signature: Bytes,
    /*
     * Optional fields
     */
    /// Factory, populated if deploying a new sender contract
    pub factory: Option<Address>,
    /// Factory data
    pub factory_data: Bytes,
    /// Paymaster, populated if using a paymaster
    pub paymaster: Option<Address>,
    /// Paymaster verification gas limit
    pub paymaster_verification_gas_limit: U128,
    /// Paymaster post-op gas limit
    pub paymaster_post_op_gas_limit: U128,
    /// Paymaster data
    pub paymaster_data: Bytes,
    /*
     * Cached fields, not part of the UO
     */
    // The hash of the user operation
    hash: H256,
    // The packed user operation
    packed: PackedUserOperation,
    // The gas cost of the calldata
    calldata_gas_cost: U256,
}

impl UserOperationTrait for UserOperation {
    type OptionalGas = UserOperationOptionalGas;

    fn hash(&self, _entry_point: Address, _chain_id: u64) -> H256 {
        self.hash
    }

    fn id(&self) -> UserOperationId {
        UserOperationId {
            sender: self.sender,
            nonce: self.nonce,
        }
    }

    fn sender(&self) -> Address {
        self.sender
    }

    fn paymaster(&self) -> Option<Address> {
        self.paymaster
    }

    fn factory(&self) -> Option<Address> {
        self.factory
    }

    fn max_gas_cost(&self) -> U256 {
        U256::from(self.max_fee_per_gas)
            * (self.pre_verification_gas
                + self.call_gas_limit
                + self.verification_gas_limit
                + self.paymaster_verification_gas_limit
                + self.paymaster_post_op_gas_limit)
    }

    fn entities(&self) -> Vec<Entity> {
        let mut ret = vec![Entity::account(self.sender)];
        if let Some(factory) = self.factory {
            ret.push(Entity::factory(factory));
        }
        if let Some(paymaster) = self.paymaster {
            ret.push(Entity::paymaster(paymaster));
        }
        ret
    }

    fn heap_size(&self) -> usize {
        self.packed.heap_size()
            + self.call_data.len()
            + self.signature.len()
            + self.factory_data.len()
            + self.paymaster_data.len()
    }

    fn max_fee_per_gas(&self) -> U256 {
        U256::from(self.max_fee_per_gas)
    }

    fn max_priority_fee_per_gas(&self) -> U256 {
        U256::from(self.max_priority_fee_per_gas)
    }

    fn pre_verification_gas(&self) -> U256 {
        self.pre_verification_gas
    }

    fn call_gas_limit(&self) -> U256 {
        U256::from(self.call_gas_limit)
    }

    fn verification_gas_limit(&self) -> U256 {
        U256::from(self.verification_gas_limit)
    }

    fn total_verification_gas_limit(&self) -> U256 {
        U256::from(self.verification_gas_limit) + U256::from(self.paymaster_verification_gas_limit)
    }

    fn calc_static_pre_verification_gas(&self, include_fixed_gas_overhead: bool) -> U256 {
        let ov = GasOverheads::default();
        self.calldata_gas_cost
            + (if include_fixed_gas_overhead {
                ov.transaction_gas_overhead
            } else {
                0.into()
            })
    }

    fn required_pre_execution_buffer(&self) -> U256 {
        // See EntryPoint::innerHandleOp
        //
        // Overhead prior to execution of the user operation is required to be
        // At least the call gas limit, plus the paymaster post-op gas limit, plus
        // a static overhead of 10K gas.
        //
        // To handle the 63/64ths rule also need to add a buffer of 1/63rd of that total*
        ENTRY_POINT_INNER_GAS_OVERHEAD
            + U256::from(self.paymaster_post_op_gas_limit)
            + (U256::from(64)
                * (U256::from(self.call_gas_limit)
                    + U256::from(self.paymaster_post_op_gas_limit)
                    + ENTRY_POINT_INNER_GAS_OVERHEAD)
                / U256::from(63))
    }

    fn clear_signature(&mut self) {
        // TODO: repack and rehash
        self.signature = Bytes::new();
    }
}

impl UserOperation {
    /// Packs the user operation to its offchain representation
    pub fn pack(self) -> PackedUserOperation {
        self.packed
    }

    /// Returns a reference to the packed user operation
    pub fn packed(&self) -> &PackedUserOperation {
        &self.packed
    }
}

impl From<UserOperationVariant> for UserOperation {
    /// Converts a UserOperationVariant to a UserOperation 0.7
    ///
    /// # Panics
    ///
    /// Panics if the variant is not v0.7. This is for use in contexts
    /// where the variant is known to be v0.7.
    fn from(value: UserOperationVariant) -> Self {
        value.into_v0_7().expect("Expected UserOperationV0_7")
    }
}

impl From<UserOperation> for super::UserOperationVariant {
    fn from(op: UserOperation) -> Self {
        super::UserOperationVariant::V0_7(op)
    }
}

/// User Operation with optional gas for Entry Point v0.7
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserOperationOptionalGas {
    /*
     * Required fields
     */
    /// Sender
    pub sender: Address,
    /// Semi-abstracted nonce
    pub nonce: U256,
    /// Calldata
    pub call_data: Bytes,
    /// Signature, typically a dummy value for optional gas
    pub signature: Bytes,
    /*
     * Optional fields
     */
    /// Call gas limit
    pub call_gas_limit: Option<U128>,
    /// Verification gas limit
    pub verification_gas_limit: Option<U128>,
    /// Pre-verification gas
    pub pre_verification_gas: Option<U256>,
    /// Max priority fee per gas
    pub max_priority_fee_per_gas: Option<U128>,
    /// Max fee per gas
    pub max_fee_per_gas: Option<U128>,
    /// Factory
    pub factory: Option<Address>,
    /// Factory data
    pub factory_data: Bytes,
    /// Paymaster
    pub paymaster: Option<Address>,
    /// Paymaster verification gas limit
    pub paymaster_verification_gas_limit: Option<U128>,
    /// Paymaster post-op gas limit
    pub paymaster_post_op_gas_limit: Option<U128>,
    /// Paymaster data
    pub paymaster_data: Bytes,
}

/// Builder for UserOperation
///
/// Used to create a v0.7 while ensuring all required fields and grouped fields are present
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

/// Required fields for UserOperation v0.7
pub struct UserOperationRequiredFields {
    /// Sender
    pub sender: Address,
    /// Semi-abstracted nonce
    pub nonce: U256,
    /// Calldata
    pub call_data: Bytes,
    /// Call gas limit
    pub call_gas_limit: U128,
    /// Verification gas limit
    pub verification_gas_limit: U128,
    /// Pre-verification gas
    pub pre_verification_gas: U256,
    /// Max priority fee per gas
    pub max_priority_fee_per_gas: U128,
    /// Max fee per gas
    pub max_fee_per_gas: U128,
    /// Signature
    pub signature: Bytes,
}

impl UserOperationBuilder {
    /// Creates a new builder
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

    /// Sets the factory and factory data
    pub fn factory(mut self, factory: Address, factory_data: Bytes) -> Self {
        self.factory = Some(factory);
        self.factory_data = factory_data;
        self
    }

    /// Sets the paymaster and associated fields
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

    /// Builds the UserOperation
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
            calldata_gas_cost: U256::zero(),
        };

        let packed = pack_user_operation(uo.clone());
        let hash = hash_packed_user_operation(&packed, self.entry_point, self.chain_id);
        let calldata_gas_cost = super::op_calldata_gas_cost(packed.clone());

        UserOperation {
            hash,
            packed,
            calldata_gas_cost,
            ..uo
        }
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

fn unpack_user_operation(puo: PackedUserOperation) -> UserOperation {
    let mut factory = None;
    let mut factory_data = Bytes::new();
    let mut paymaster = None;
    let mut paymaster_verification_gas_limit = U128::zero();
    let mut paymaster_post_op_gas_limit = U128::zero();
    let mut paymaster_data = Bytes::new();

    if !puo.init_code.is_empty() {
        factory = Some(Address::from_slice(&puo.init_code));
        factory_data = Bytes::from_iter(&puo.init_code[20..]);
    }

    if !puo.paymaster_and_data.is_empty() {
        paymaster = Some(Address::from_slice(&puo.paymaster_and_data));
        paymaster_verification_gas_limit = U128::from_big_endian(&puo.paymaster_and_data[20..36]);
        paymaster_post_op_gas_limit = U128::from_big_endian(&puo.paymaster_and_data[36..52]);
        paymaster_data = Bytes::from_iter(&puo.paymaster_and_data[52..]);
    }

    UserOperation {
        sender: puo.sender,
        nonce: puo.nonce,
        call_data: puo.call_data.clone(),
        call_gas_limit: U128::from_big_endian(&puo.account_gas_limits[..16]),
        verification_gas_limit: U128::from_big_endian(&puo.account_gas_limits[16..]),
        pre_verification_gas: puo.pre_verification_gas,
        max_priority_fee_per_gas: U128::from_big_endian(&puo.gas_fees[..16]),
        max_fee_per_gas: U128::from_big_endian(&puo.gas_fees[16..]),
        signature: puo.signature.clone(),
        factory,
        factory_data,
        paymaster,
        paymaster_verification_gas_limit,
        paymaster_post_op_gas_limit,
        paymaster_data,
        calldata_gas_cost: super::op_calldata_gas_cost(puo.clone()),
        packed: puo,
        hash: H256::zero(),
    }
}

fn hash_packed_user_operation(
    puo: &PackedUserOperation,
    entry_point: Address,
    chain_id: u64,
) -> H256 {
    let hash_init_code = keccak256(&puo.init_code);
    let hash_call_data = keccak256(&puo.call_data);
    let hash_paymaster_and_data = keccak256(&puo.paymaster_and_data);

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

impl PackedUserOperation {
    /// Unpacks the user operation to its offchain representation
    pub fn unpack(self, entry_point: Address, chain_id: u64) -> UserOperation {
        let hash = hash_packed_user_operation(&self, entry_point, chain_id);
        let unpacked = unpack_user_operation(self.clone());
        UserOperation { hash, ..unpacked }
    }

    fn heap_size(&self) -> usize {
        self.init_code.len() + self.call_data.len() + self.paymaster_and_data.len()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethers::utils::hex::{self, FromHex};

    use super::*;

    #[test]
    fn test_pack_unpack() {
        let builder = UserOperationBuilder::new(
            Address::zero(),
            1,
            UserOperationRequiredFields {
                sender: Address::zero(),
                nonce: 0.into(),
                call_data: Bytes::new(),
                call_gas_limit: 0.into(),
                verification_gas_limit: 0.into(),
                pre_verification_gas: 0.into(),
                max_priority_fee_per_gas: 0.into(),
                max_fee_per_gas: 0.into(),
                signature: Bytes::new(),
            },
        );

        let uo = builder.build();
        let packed = uo.clone().pack();
        let unpacked = packed.unpack(Address::zero(), 1);

        assert_eq!(uo, unpacked);
    }

    #[test]
    fn test_hash() {
        // From https://sepolia.etherscan.io/tx/0x51c1f40ce6e997a54b39a0eb783e472c2afa4ed3f2f11f97986f7f3a347b9d50
        let entry_point = Address::from_str("0x0000000071727De22E5E9d8BAf0edAc6f37da032").unwrap();
        let chain_id = 11155111;

        let puo = PackedUserOperation {
            sender: Address::from_str("0xb292Cf4a8E1fF21Ac27C4f94071Cd02C022C414b").unwrap(),
            nonce: U256::from("0xF83D07238A7C8814A48535035602123AD6DBFA63000000000000000000000001"),
            init_code: Bytes::from_hex("0x").unwrap(),
            call_data: Bytes::from_hex("0xe9ae5c530000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001d8b292cf4a8e1ff21ac27c4f94071cd02c022c414b00000000000000000000000000000000000000000000000000000000000000009517e29f0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000ad6330089d9a1fe89f4020292e1afe9969a5a2fc00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000001518000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018e2fbe8980000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000800000000000000000000000002372912728f93ab3daaaebea4f87e6e28476d987000000000000000000000000000000000000000000000000002386f26fc10000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            account_gas_limits: hex::decode("0x000000000000000000000000000114fc0000000000000000000000000012c9b5")
                .unwrap()
                .try_into()
                .unwrap(),
            pre_verification_gas: U256::from(48916),
            gas_fees: hex::decode("0x000000000000000000000000524121000000000000000000000000109a4a441a")
                .unwrap()
                .try_into()
                .unwrap(),
            paymaster_and_data: Bytes::from_hex("0x").unwrap(),
            signature: Bytes::from_hex("0x3c7bfe22c9c2ef8994a9637bcc4df1741c5dc0c25b209545a7aeb20f7770f351479b683bd17c4d55bc32e2a649c8d2dff49dcfcc1f3fd837bcd88d1e69a434cf1c").unwrap(),
        };

        let hash =
            H256::from_str("0xe486401370d145766c3cf7ba089553214a1230d38662ae532c9b62eb6dadcf7e")
                .unwrap();
        let uo = puo.unpack(entry_point, chain_id);
        assert_eq!(uo.hash(entry_point, chain_id), hash);
    }

    #[test]
    fn test_builder() {
        let entry_point = Address::zero();
        let chain_id = 1;

        let factory_address = Address::random();
        let paymaster_address = Address::random();

        let uo = UserOperationBuilder::new(
            entry_point,
            chain_id,
            UserOperationRequiredFields {
                sender: Address::zero(),
                nonce: 0.into(),
                call_data: Bytes::new(),
                call_gas_limit: 0.into(),
                verification_gas_limit: 0.into(),
                pre_verification_gas: 0.into(),
                max_priority_fee_per_gas: 0.into(),
                max_fee_per_gas: 0.into(),
                signature: Bytes::new(),
            },
        )
        .factory(factory_address, Bytes::new())
        .paymaster(paymaster_address, 10.into(), 20.into(), Bytes::new())
        .build();

        assert_eq!(uo.factory, Some(factory_address));
        assert_eq!(uo.paymaster, Some(paymaster_address));
        assert_eq!(uo.paymaster_verification_gas_limit, 10.into());
        assert_eq!(uo.paymaster_post_op_gas_limit, 20.into());
    }
}
