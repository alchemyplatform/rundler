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

use alloy_primitives::{ruint::FromUintError, Address, Bytes, FixedBytes, B256, U256};
use alloy_sol_types::{sol, SolValue};
use rundler_contracts::v0_7::PackedUserOperation;

use super::{
    random_bytes, random_bytes_array, UserOperation as UserOperationTrait, UserOperationId,
    UserOperationVariant,
};
use crate::{authorization::Authorization, chain::ChainSpec, Entity, EntryPointVersion};

/// Gas overhead required by the entry point contract for the inner call
pub const ENTRY_POINT_INNER_GAS_OVERHEAD: u128 = 10_000;

/// Number of bytes in the fixed size portion of an ABI encoded user operation
/// sender = 32 bytes
/// nonce = 32 bytes
/// init_code = 32 bytes + 32 bytes for the length + var bytes
/// call_data = 32 bytes + 32 bytes for the length + var bytes
/// account_gas_limits = 32 bytes
/// pre_verification_gas = 32 bytes
/// gas_fees = 32 bytes
/// paymaster_and_data = 32 bytes + 32 bytes for the length + var bytes
/// signature = 32 bytes + 32 bytes for the length + var bytes
///
/// 13 * 32 = 416
const ABI_ENCODED_USER_OPERATION_FIXED_LEN: usize = 416;

/// User Operation for Entry Point v0.7
///
/// Offchain version, must be packed before sending onchain
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive] // Prevent instantiation except with UserOperationBuilder
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
    pub call_gas_limit: u128,
    /// Verification gas limit
    pub verification_gas_limit: u128,
    /// Pre-verification gas
    pub pre_verification_gas: u128,
    /// Max priority fee per gas
    pub max_priority_fee_per_gas: u128,
    /// Max fee per gas
    pub max_fee_per_gas: u128,
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
    pub paymaster_verification_gas_limit: u128,
    /// Paymaster post-op gas limit
    pub paymaster_post_op_gas_limit: u128,
    /// Paymaster data
    pub paymaster_data: Bytes,
    /// eip 7702 - list of authorities.
    pub authorization_list: Vec<Authorization>,

    /*
     * Cached fields, not part of the UO
     */
    /// Entry point address
    pub entry_point: Address,
    /// Chain id
    pub chain_id: u64,
    /// The hash of the user operation
    pub hash: B256,
    /// The packed user operation
    pub packed: PackedUserOperation,
    /// The gas cost of the calldata
    pub calldata_gas_cost: u128,
}

impl UserOperationTrait for UserOperation {
    type OptionalGas = UserOperationOptionalGas;

    fn entry_point_version() -> EntryPointVersion {
        EntryPointVersion::V0_7
    }

    fn hash(&self, _entry_point: Address, _chain_id: u64) -> B256 {
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

    fn nonce(&self) -> U256 {
        self.nonce
    }

    fn paymaster(&self) -> Option<Address> {
        self.paymaster
    }

    fn factory(&self) -> Option<Address> {
        self.factory
    }

    fn call_data(&self) -> &Bytes {
        &self.call_data
    }

    fn max_gas_cost(&self) -> U256 {
        U256::from(
            self.max_fee_per_gas
                * (self.pre_verification_gas
                    + self.call_gas_limit
                    + self.verification_gas_limit
                    + self.paymaster_verification_gas_limit
                    + self.paymaster_post_op_gas_limit),
        )
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
        self.packed.callData.len()
            + self.packed.initCode.len()
            + self.packed.paymasterAndData.len()
            + self.call_data.len()
            + self.signature.len()
            + self.factory_data.len()
            + self.paymaster_data.len()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    fn max_priority_fee_per_gas(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    fn pre_verification_gas(&self) -> u128 {
        self.pre_verification_gas
    }

    fn call_gas_limit(&self) -> u128 {
        self.call_gas_limit
    }

    fn verification_gas_limit(&self) -> u128 {
        self.verification_gas_limit
    }

    fn total_verification_gas_limit(&self) -> u128 {
        self.verification_gas_limit + self.paymaster_verification_gas_limit
    }

    fn static_pre_verification_gas(&self, chain_spec: &ChainSpec) -> u128 {
        self.calldata_gas_cost
            + chain_spec.per_user_op_v0_7_gas()
            + (if self.factory.is_some() {
                chain_spec.per_user_op_deploy_overhead_gas()
            } else {
                0
            })
    }

    fn required_pre_execution_buffer(&self) -> u128 {
        // See EntryPoint::innerHandleOp
        //
        // Overhead prior to execution of the user operation is required to be
        // At least the call gas limit, plus the paymaster post-op gas limit, plus
        // a static overhead of 10K gas.
        //
        // To handle the 63/64ths rule also need to add a buffer of 1/63rd of that total*
        ENTRY_POINT_INNER_GAS_OVERHEAD
            + self.paymaster_post_op_gas_limit
            + (64
                * (self.call_gas_limit
                    + self.paymaster_post_op_gas_limit
                    + ENTRY_POINT_INNER_GAS_OVERHEAD)
                / 63)
    }

    fn clear_signature(&mut self) {
        self.signature = Bytes::new();
        self.packed = pack_user_operation(self.clone());
        self.hash = hash_packed_user_operation(&self.packed, self.entry_point, self.chain_id);
    }

    fn abi_encoded_size(&self) -> usize {
        ABI_ENCODED_USER_OPERATION_FIXED_LEN
            + super::byte_array_abi_len(&self.packed.initCode)
            + super::byte_array_abi_len(&self.packed.callData)
            + super::byte_array_abi_len(&self.packed.paymasterAndData)
            + super::byte_array_abi_len(&self.packed.signature)
    }

    fn authorization_list(&self) -> Vec<Authorization> {
        self.authorization_list.clone()
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

impl AsRef<UserOperation> for super::UserOperationVariant {
    /// # Panics
    ///
    /// Panics if the variant is not v0.7. This is for use in contexts
    /// where the variant is known to be v0.7.
    fn as_ref(&self) -> &UserOperation {
        match self {
            super::UserOperationVariant::V0_7(op) => op,
            _ => panic!("Expected UserOperationV0_7"),
        }
    }
}

impl AsMut<UserOperation> for super::UserOperationVariant {
    /// # Panics
    ///
    /// Panics if the variant is not v0.7. This is for use in contexts
    /// where the variant is known to be v0.7.
    fn as_mut(&mut self) -> &mut UserOperation {
        match self {
            super::UserOperationVariant::V0_7(op) => op,
            _ => panic!("Expected UserOperationV0_7"),
        }
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
    pub call_gas_limit: Option<u128>,
    /// Verification gas limit
    pub verification_gas_limit: Option<u128>,
    /// Pre-verification gas
    pub pre_verification_gas: Option<u128>,
    /// Max priority fee per gas
    pub max_priority_fee_per_gas: Option<u128>,
    /// Max fee per gas
    pub max_fee_per_gas: Option<u128>,
    /// Factory
    pub factory: Option<Address>,
    /// Factory data
    pub factory_data: Bytes,
    /// Paymaster
    pub paymaster: Option<Address>,
    /// Paymaster verification gas limit
    pub paymaster_verification_gas_limit: Option<u128>,
    /// Paymaster post-op gas limit
    pub paymaster_post_op_gas_limit: Option<u128>,
    /// Paymaster data
    pub paymaster_data: Bytes,
}

impl UserOperationOptionalGas {
    /// Fill in the optional and dummy fields of the user operation with values
    /// that will cause the maximum possible calldata gas cost.
    pub fn max_fill(&self, chain_spec: &ChainSpec) -> UserOperation {
        let max_4 = u32::MAX as u128;
        let max_8 = u64::MAX as u128;

        let mut builder = UserOperationBuilder::new(
            chain_spec,
            UserOperationRequiredFields {
                sender: self.sender,
                nonce: self.nonce,
                call_data: self.call_data.clone(),
                signature: vec![255_u8; self.signature.len()].into(),
                call_gas_limit: max_4,
                verification_gas_limit: max_4,
                pre_verification_gas: max_4,
                max_priority_fee_per_gas: max_8,
                max_fee_per_gas: max_8,
            },
        );

        if self.paymaster.is_some() {
            builder = builder.paymaster(
                self.paymaster.unwrap(),
                max_4,
                max_4,
                vec![255_u8; self.paymaster_data.len()].into(),
            );
        }
        if self.factory.is_some() {
            builder = builder.factory(
                self.factory.unwrap(),
                vec![255_u8; self.factory_data.len()].into(),
            );
        }

        builder.build()
    }

    /// Fill in the optional and dummy fields of the user operation with random values.
    ///
    /// When estimating pre-verification gas, specifically on networks that use
    /// compression algorithms on their data that they post to their data availability
    /// layer (like Arbitrum), it is important to make sure that the data that is
    /// random such that it compresses to a representative size.
    //
    /// Note that this will slightly overestimate the calldata gas needed as it uses
    /// the worst case scenario for the unknown gas values and paymaster_and_data.
    pub fn random_fill(&self, chain_spec: &ChainSpec) -> UserOperation {
        let mut builder = UserOperationBuilder::new(
            chain_spec,
            UserOperationRequiredFields {
                sender: self.sender,
                nonce: self.nonce,
                call_data: self.call_data.clone(),
                signature: random_bytes(self.signature.len()),
                call_gas_limit: u128::from_le_bytes(random_bytes_array::<16, 4>()),
                verification_gas_limit: u128::from_le_bytes(random_bytes_array::<16, 4>()),
                pre_verification_gas: u128::from_le_bytes(random_bytes_array::<16, 4>()),
                max_priority_fee_per_gas: u128::from_le_bytes(random_bytes_array::<16, 8>()),
                max_fee_per_gas: u128::from_le_bytes(random_bytes_array::<16, 8>()),
            },
        );

        if self.paymaster.is_some() {
            builder = builder.paymaster(
                self.paymaster.unwrap(),
                u128::from_le_bytes(random_bytes_array::<16, 4>()),
                u128::from_le_bytes(random_bytes_array::<16, 4>()),
                random_bytes(self.paymaster_data.len()),
            )
        }
        if self.factory.is_some() {
            builder = builder.factory(self.factory.unwrap(), random_bytes(self.factory_data.len()))
        }

        builder.build()
    }

    /// Convert into a builder for producing a full user operation.
    /// Fill in the optional fields of the user operation with default values if unset
    pub fn into_user_operation_builder(
        self,
        chain_spec: &ChainSpec,
        max_call_gas: u128,
        max_verification_gas: u128,
        max_paymaster_verification_gas: u128,
    ) -> UserOperationBuilder<'_> {
        // If unset or zero, default these to gas limits from settings
        // Cap their values to the gas limits from settings
        let cgl = super::default_if_none_or_equal(self.call_gas_limit, max_call_gas, 0);
        let vgl =
            super::default_if_none_or_equal(self.verification_gas_limit, max_verification_gas, 0);
        let pgl = super::default_if_none_or_equal(
            self.paymaster_verification_gas_limit,
            max_paymaster_verification_gas,
            0,
        );
        let pvg = super::default_if_none_or_equal(self.pre_verification_gas, max_call_gas, 0);

        let mut builder = UserOperationBuilder::new(
            chain_spec,
            UserOperationRequiredFields {
                sender: self.sender,
                nonce: self.nonce,
                call_data: self.call_data,
                signature: self.signature,
                call_gas_limit: cgl,
                verification_gas_limit: vgl,
                pre_verification_gas: pvg,
                // These are unused in gas estimation, so default to zero
                max_priority_fee_per_gas: self.max_priority_fee_per_gas.unwrap_or_default(),
                max_fee_per_gas: self.max_fee_per_gas.unwrap_or_default(),
            },
        );
        if let Some(factory) = self.factory {
            builder = builder.factory(factory, self.factory_data);
        }
        if let Some(paymaster) = self.paymaster {
            let paymaster_verification_gas_limit = pgl;
            // If the user doesn't supply a post op, assume unused and zero
            let paymaster_post_op_gas_limit = self.paymaster_post_op_gas_limit.unwrap_or_default();
            builder = builder.paymaster(
                paymaster,
                paymaster_verification_gas_limit,
                paymaster_post_op_gas_limit,
                self.paymaster_data,
            );
        }
        builder
    }

    /// Abi encoded size of the user operation (with its dummy fields)
    pub fn abi_encoded_size(&self) -> usize {
        let mut base = ABI_ENCODED_USER_OPERATION_FIXED_LEN
            + super::byte_array_abi_len(&self.call_data)
            + super::byte_array_abi_len(&self.signature);
        if self.factory.is_some() {
            base += super::byte_array_abi_len(&self.factory_data) + 32; // account for factory address
        }
        if self.paymaster.is_some() {
            base += super::byte_array_abi_len(&self.paymaster_data) + 64; // account for paymaster address and gas limits
        }

        base
    }
}

impl From<super::UserOperationOptionalGas> for UserOperationOptionalGas {
    /// # Panics
    ///
    /// Panics if the variant is not v0.7. This is for use in contexts
    /// where the variant is known to be v0.7.
    fn from(op: super::UserOperationOptionalGas) -> Self {
        match op {
            super::UserOperationOptionalGas::V0_7(op) => op,
            _ => panic!("Expected UserOperationOptionalGasV0_7"),
        }
    }
}

/// Builder for UserOperation
///
/// Used to create a v0.7 while ensuring all required fields and grouped fields are present
pub struct UserOperationBuilder<'a> {
    // chain spec
    chain_spec: &'a ChainSpec,

    // required fields
    required: UserOperationRequiredFields,

    // optional fields
    factory: Option<Address>,
    factory_data: Bytes,
    paymaster: Option<Address>,
    paymaster_verification_gas_limit: u128,
    paymaster_post_op_gas_limit: u128,
    paymaster_data: Bytes,
    packed_uo: Option<PackedUserOperation>,

    /// eip 7702 - list of authorities.
    authorization_list: Vec<Authorization>,
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
    pub call_gas_limit: u128,
    /// Verification gas limit
    pub verification_gas_limit: u128,
    /// Pre-verification gas
    pub pre_verification_gas: u128,
    /// Max priority fee per gas
    pub max_priority_fee_per_gas: u128,
    /// Max fee per gas
    pub max_fee_per_gas: u128,
    /// Signature
    pub signature: Bytes,
}

impl<'a> UserOperationBuilder<'a> {
    /// Creates a new builder
    pub fn new(chain_spec: &'a ChainSpec, required: UserOperationRequiredFields) -> Self {
        Self {
            chain_spec,
            required,
            factory: None,
            factory_data: Bytes::new(),
            paymaster: None,
            paymaster_verification_gas_limit: 0,
            paymaster_post_op_gas_limit: 0,
            paymaster_data: Bytes::new(),
            packed_uo: None,
            authorization_list: vec![],
        }
    }

    /// Creates a builder from a packed user operation
    pub fn from_packed(
        puo: PackedUserOperation,
        chain_spec: &'a ChainSpec,
    ) -> Result<Self, FromUintError<u128>> {
        let mut builder = UserOperationBuilder::new(
            chain_spec,
            UserOperationRequiredFields {
                sender: puo.sender,
                nonce: puo.nonce,
                call_data: puo.callData.clone(),
                call_gas_limit: u128_from_be_slice(&puo.accountGasLimits[16..]),
                verification_gas_limit: u128_from_be_slice(&puo.accountGasLimits[..16]),
                pre_verification_gas: puo.preVerificationGas.try_into()?,
                max_priority_fee_per_gas: u128_from_be_slice(&puo.gasFees[..16]),
                max_fee_per_gas: u128_from_be_slice(&puo.gasFees[16..]),
                signature: puo.signature.clone(),
            },
        );

        builder = builder.packed(puo.clone());

        if !puo.initCode.is_empty() {
            let factory = Address::from_slice(&puo.initCode[..20]);
            let factory_data = Bytes::from_iter(&puo.initCode[20..]);

            builder = builder.factory(factory, factory_data);
        }

        if !puo.paymasterAndData.is_empty() {
            let paymaster = Address::from_slice(&puo.paymasterAndData[..20]);
            let paymaster_verification_gas_limit =
                u128_from_be_slice(&puo.paymasterAndData[20..36]);
            let paymaster_post_op_gas_limit = u128_from_be_slice(&puo.paymasterAndData[36..52]);
            let paymaster_data = Bytes::from_iter(&puo.paymasterAndData[52..]);

            builder = builder.paymaster(
                paymaster,
                paymaster_verification_gas_limit,
                paymaster_post_op_gas_limit,
                paymaster_data,
            );
        }

        Ok(builder)
    }

    /// Creates a builder from an existing UO
    pub fn from_uo(uo: UserOperation, chain_spec: &'a ChainSpec) -> Self {
        Self {
            chain_spec,
            required: UserOperationRequiredFields {
                sender: uo.sender,
                nonce: uo.nonce,
                call_data: uo.call_data,
                call_gas_limit: uo.call_gas_limit,
                verification_gas_limit: uo.verification_gas_limit,
                pre_verification_gas: uo.pre_verification_gas,
                max_priority_fee_per_gas: uo.max_priority_fee_per_gas,
                max_fee_per_gas: uo.max_fee_per_gas,
                signature: uo.signature,
            },
            factory: uo.factory,
            factory_data: uo.factory_data,
            paymaster: uo.paymaster,
            paymaster_verification_gas_limit: uo.paymaster_verification_gas_limit,
            paymaster_post_op_gas_limit: uo.paymaster_post_op_gas_limit,
            paymaster_data: uo.paymaster_data,
            packed_uo: None,
            authorization_list: uo.authorization_list,
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
        paymaster_verification_gas_limit: u128,
        paymaster_post_op_gas_limit: u128,
        paymaster_data: Bytes,
    ) -> Self {
        self.paymaster = Some(paymaster);
        self.paymaster_verification_gas_limit = paymaster_verification_gas_limit;
        self.paymaster_post_op_gas_limit = paymaster_post_op_gas_limit;
        self.paymaster_data = paymaster_data;
        self
    }

    /// Sets the pre-verification gas
    pub fn pre_verification_gas(mut self, pre_verification_gas: u128) -> Self {
        self.required.pre_verification_gas = pre_verification_gas;
        self
    }

    /// Sets the verification gas limit
    pub fn verification_gas_limit(mut self, verification_gas_limit: u128) -> Self {
        self.required.verification_gas_limit = verification_gas_limit;
        self
    }

    /// Sets the call gas limit
    pub fn call_gas_limit(mut self, call_gas_limit: u128) -> Self {
        self.required.call_gas_limit = call_gas_limit;
        self
    }

    /// Sets the max fee per gas
    pub fn max_fee_per_gas(mut self, max_fee_per_gas: u128) -> Self {
        self.required.max_fee_per_gas = max_fee_per_gas;
        self
    }

    /// Sets the max priority fee per gas
    pub fn max_priority_fee_per_gas(mut self, max_priority_fee_per_gas: u128) -> Self {
        self.required.max_priority_fee_per_gas = max_priority_fee_per_gas;
        self
    }

    /// Sets the paymaster verification gas limit
    pub fn paymaster_verification_gas_limit(
        mut self,
        paymaster_verification_gas_limit: u128,
    ) -> Self {
        self.paymaster_verification_gas_limit = paymaster_verification_gas_limit;
        self
    }

    /// Sets the paymaster post-op gas limit
    pub fn paymaster_post_op_gas_limit(mut self, paymaster_post_op_gas_limit: u128) -> Self {
        self.paymaster_post_op_gas_limit = paymaster_post_op_gas_limit;
        self
    }

    /// Sets the packed user operation, if known beforehand
    pub fn packed(mut self, packed: PackedUserOperation) -> Self {
        self.packed_uo = Some(packed);
        self
    }

    /// Sets the authorization list
    pub fn authorization_list(mut self, authorization_list: Vec<Authorization>) -> Self {
        self.authorization_list = authorization_list;
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
            authorization_list: self.authorization_list,
            signature: self.required.signature,
            entry_point: self.chain_spec.entry_point_address_v0_7,
            chain_id: self.chain_spec.id,
            hash: B256::ZERO,
            packed: PackedUserOperation::default(),
            calldata_gas_cost: 0,
        };

        let packed = self
            .packed_uo
            .unwrap_or_else(|| pack_user_operation(uo.clone()));
        let hash = hash_packed_user_operation(
            &packed,
            self.chain_spec.entry_point_address_v0_7,
            self.chain_spec.id,
        );
        let calldata_gas_cost = super::op_calldata_gas_cost(
            packed.clone(),
            self.chain_spec.calldata_zero_byte_gas(),
            self.chain_spec.calldata_non_zero_byte_gas(),
            self.chain_spec.per_user_op_word_gas(),
        );

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
        let mut init_code = factory.to_vec();
        init_code.extend_from_slice(&uo.factory_data);
        Bytes::from(init_code)
    } else {
        Bytes::new()
    };

    let account_gas_limits = concat_u128_be(uo.verification_gas_limit, uo.call_gas_limit);
    let gas_fees = concat_u128_be(uo.max_priority_fee_per_gas, uo.max_fee_per_gas);

    let pvgl: [u8; 16] = uo.paymaster_verification_gas_limit.to_be_bytes();
    let pogl: [u8; 16] = uo.paymaster_post_op_gas_limit.to_be_bytes();
    let paymaster_and_data = if let Some(paymaster) = uo.paymaster {
        let mut paymaster_and_data = paymaster.to_vec();
        paymaster_and_data.extend_from_slice(&pvgl);
        paymaster_and_data.extend_from_slice(&pogl);
        paymaster_and_data.extend_from_slice(&uo.paymaster_data);
        Bytes::from(paymaster_and_data)
    } else {
        Bytes::new()
    };

    PackedUserOperation {
        sender: uo.sender,
        nonce: uo.nonce,
        initCode: init_code,
        callData: uo.call_data,
        accountGasLimits: FixedBytes::from(account_gas_limits),
        preVerificationGas: U256::from(uo.pre_verification_gas),
        gasFees: FixedBytes::from(gas_fees),
        paymasterAndData: paymaster_and_data,
        signature: uo.signature,
    }
}

fn u128_from_be_slice(input: &[u8]) -> u128 {
    let (int_bytes, _) = input.split_at(std::mem::size_of::<u128>());
    u128::from_be_bytes(int_bytes.try_into().unwrap())
}

sol! {
    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct UserOperationHashEncoded {
        bytes32 encodedHash;
        address entryPoint;
        uint256 chainId;
    }

    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct UserOperationPackedForHash {
        address sender;
        uint256 nonce;
        bytes32 hashInitCode;
        bytes32 hashCallData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes32 hashPaymasterAndData;
    }
}

fn hash_packed_user_operation(
    puo: &PackedUserOperation,
    entry_point: Address,
    chain_id: u64,
) -> B256 {
    let hash_init_code = alloy_primitives::keccak256(&puo.initCode);
    let hash_call_data = alloy_primitives::keccak256(&puo.callData);
    let hash_paymaster_and_data = alloy_primitives::keccak256(&puo.paymasterAndData);

    let packed_for_hash = UserOperationPackedForHash {
        sender: puo.sender,
        nonce: puo.nonce,
        hashInitCode: hash_init_code,
        hashCallData: hash_call_data,
        accountGasLimits: puo.accountGasLimits,
        preVerificationGas: puo.preVerificationGas,
        gasFees: puo.gasFees,
        hashPaymasterAndData: hash_paymaster_and_data,
    };

    let hashed = alloy_primitives::keccak256(packed_for_hash.abi_encode());

    let encoded = UserOperationHashEncoded {
        encodedHash: hashed,
        entryPoint: entry_point,
        chainId: U256::from(chain_id),
    };

    alloy_primitives::keccak256(encoded.abi_encode())
}

fn concat_u128_be(a: u128, b: u128) -> [u8; 32] {
    let a = a.to_be_bytes();
    let b = b.to_be_bytes();
    std::array::from_fn(|i| {
        if let Some(i) = i.checked_sub(a.len()) {
            b[i]
        } else {
            a[i]
        }
    })
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{address, b256, bytes, uint};

    use super::*;

    #[test]
    fn test_pack_unpack() {
        let cs = ChainSpec::default();
        let builder = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                sender: Address::ZERO,
                nonce: U256::ZERO,
                call_data: Bytes::new(),
                call_gas_limit: 0,
                verification_gas_limit: 0,
                pre_verification_gas: 0,
                max_priority_fee_per_gas: 0,
                max_fee_per_gas: 0,
                signature: Bytes::new(),
            },
        );

        let uo = builder.build();
        let packed = uo.clone().pack();
        let unpacked = UserOperationBuilder::from_packed(packed, &cs)
            .unwrap()
            .build();

        assert_eq!(uo, unpacked);
    }

    #[test]
    fn test_pack_unpack_2() {
        let cs = ChainSpec::default();
        let builder = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                sender: Address::ZERO,
                nonce: U256::ZERO,
                call_data: Bytes::new(),
                call_gas_limit: 0,
                verification_gas_limit: 0,
                pre_verification_gas: 0,
                max_priority_fee_per_gas: 0,
                max_fee_per_gas: 0,
                signature: Bytes::new(),
            },
        );
        let builder = builder
            .factory(Address::random(), "0xdeadbeef".parse().unwrap())
            .paymaster(Address::random(), 0, 0, Bytes::new());

        let uo = builder.build();
        let packed = uo.clone().pack();
        let unpacked = UserOperationBuilder::from_packed(packed, &cs)
            .unwrap()
            .build();

        assert_eq!(uo, unpacked);
    }

    #[test]
    fn test_hash() {
        // From https://sepolia.etherscan.io/tx/0x51c1f40ce6e997a54b39a0eb783e472c2afa4ed3f2f11f97986f7f3a347b9d50
        let cs = ChainSpec {
            id: 11155111,
            ..Default::default()
        };

        let puo = PackedUserOperation {
            sender: address!("b292Cf4a8E1fF21Ac27C4f94071Cd02C022C414b"),
            nonce: uint!(0xF83D07238A7C8814A48535035602123AD6DBFA63000000000000000000000001_U256),
            initCode: Bytes::default(),
            callData: bytes!("e9ae5c530000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001d8b292cf4a8e1ff21ac27c4f94071cd02c022c414b00000000000000000000000000000000000000000000000000000000000000009517e29f0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000ad6330089d9a1fe89f4020292e1afe9969a5a2fc00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000001518000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018e2fbe8980000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000800000000000000000000000002372912728f93ab3daaaebea4f87e6e28476d987000000000000000000000000000000000000000000000000002386f26fc10000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            accountGasLimits: b256!("000000000000000000000000000114fc0000000000000000000000000012c9b5"),
            preVerificationGas: U256::from(48916),
            gasFees: b256!("000000000000000000000000524121000000000000000000000000109a4a441a"),
            paymasterAndData: Bytes::default(),
            signature: bytes!("3c7bfe22c9c2ef8994a9637bcc4df1741c5dc0c25b209545a7aeb20f7770f351479b683bd17c4d55bc32e2a649c8d2dff49dcfcc1f3fd837bcd88d1e69a434cf1c"),
        };

        let hash = b256!("e486401370d145766c3cf7ba089553214a1230d38662ae532c9b62eb6dadcf7e");
        let uo = UserOperationBuilder::from_packed(puo, &cs).unwrap().build();
        assert_eq!(uo.hash(cs.entry_point_address_v0_7, cs.id), hash);
    }

    #[test]
    fn test_builder() {
        let factory_address = Address::random();
        let paymaster_address = Address::random();
        let cs = ChainSpec::default();

        let uo = UserOperationBuilder::new(
            &cs,
            UserOperationRequiredFields {
                sender: Address::ZERO,
                nonce: U256::ZERO,
                call_data: Bytes::new(),
                call_gas_limit: 0,
                verification_gas_limit: 0,
                pre_verification_gas: 0,
                max_priority_fee_per_gas: 0,
                max_fee_per_gas: 0,
                signature: Bytes::new(),
            },
        )
        .factory(factory_address, Bytes::new())
        .paymaster(paymaster_address, 10, 20, Bytes::new())
        .build();

        assert_eq!(uo.factory, Some(factory_address));
        assert_eq!(uo.paymaster, Some(paymaster_address));
        assert_eq!(uo.paymaster_verification_gas_limit, 10);
        assert_eq!(uo.paymaster_post_op_gas_limit, 20);
    }
}
