mod entry_point_like;
mod provider_like;
mod timestamp;
mod validation_results;
mod violations;

use std::{
    collections::{btree_map, BTreeMap},
    fmt::Display,
    str::FromStr,
};

use anyhow::bail;
pub use entry_point_like::*;
use ethers::{
    abi::{encode, Token},
    types::{Address, Bytes, H256, U256},
    utils::{keccak256, to_checksum},
};
use parse_display::Display;
pub use provider_like::*;
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use strum::EnumIter;
pub use timestamp::*;
pub use validation_results::*;
pub use violations::*;

pub use crate::common::contracts::shared_types::UserOperation;

/// Unique identifier for a user operation from a given sender
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserOperationId {
    sender: Address,
    nonce: U256,
}

impl UserOperation {
    /// Hash a user operation with the given entry point and chain ID.
    ///
    /// The hash is used to uniquely identify a user operation in the entry point.
    /// It does not include the signature field.
    pub fn op_hash(&self, entry_point: Address, chain_id: u64) -> H256 {
        keccak256(encode(&[
            Token::FixedBytes(keccak256(self.pack()).to_vec()),
            Token::Address(entry_point),
            Token::Uint(chain_id.into()),
        ]))
        .into()
    }

    /// Get the unique identifier for this user operation from its sender
    pub fn id(&self) -> UserOperationId {
        UserOperationId {
            sender: self.sender,
            nonce: self.nonce,
        }
    }

    pub fn factory(&self) -> Option<Address> {
        Self::get_address_from_field(&self.init_code)
    }

    pub fn paymaster(&self) -> Option<Address> {
        Self::get_address_from_field(&self.paymaster_and_data)
    }

    /// Extracts an address from the beginning of a data field
    /// Useful to extract the paymaster address from paymaster_and_data
    /// and the factory address from init_code
    pub fn get_address_from_field(data: &Bytes) -> Option<Address> {
        if data.len() < 20 {
            None
        } else {
            Some(Address::from_slice(&data[..20]))
        }
    }

    pub fn pack(&self) -> Bytes {
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

    pub fn max_gas_cost(&self) -> U256 {
        let max_gas = self.call_gas_limit + self.verification_gas_limit + self.pre_verification_gas;
        max_gas * self.max_fee_per_gas
    }
}

#[derive(Display, Debug, Clone, Ord, Copy, Eq, PartialEq, EnumIter, PartialOrd)]
#[display(style = "lowercase")]
pub enum EntityType {
    Account,
    Paymaster,
    Aggregator,
    Factory,
}

impl EntityType {
    pub fn to_str(&self) -> &'static str {
        match self {
            EntityType::Account => "account",
            EntityType::Paymaster => "paymaster",
            EntityType::Aggregator => "aggregator",
            EntityType::Factory => "factory",
        }
    }
}

impl FromStr for EntityType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "account" => Ok(EntityType::Account),
            "paymaster" => Ok(EntityType::Paymaster),
            "aggregator" => Ok(EntityType::Aggregator),
            "factory" => Ok(EntityType::Factory),
            _ => bail!("Invalid entity type: {s}"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Entity {
    pub kind: EntityType,
    pub address: Address,
}

impl Entity {
    pub fn new(kind: EntityType, address: Address) -> Self {
        Self { kind, address }
    }

    pub fn account(address: Address) -> Self {
        Self::new(EntityType::Account, address)
    }

    pub fn paymaster(address: Address) -> Self {
        Self::new(EntityType::Paymaster, address)
    }

    pub fn aggregator(address: Address) -> Self {
        Self::new(EntityType::Aggregator, address)
    }

    pub fn factory(address: Address) -> Self {
        Self::new(EntityType::Factory, address)
    }
}

impl Display for Entity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:?}", self.kind, to_checksum(&self.address, None))
    }
}

impl Serialize for Entity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut e = serializer.serialize_struct("Entity", 1)?;
        e.serialize_field(self.kind.to_str(), &to_checksum(&self.address, None))?;
        e.end()
    }
}

#[derive(Display, Debug, Clone, Copy, Eq, PartialEq, EnumIter, Serialize, Deserialize)]
#[display(style = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum BundlingMode {
    Manual,
    Auto,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ExpectedStorage(BTreeMap<Address, BTreeMap<H256, H256>>);

impl ExpectedStorage {
    pub fn merge(&mut self, other: &Self) -> anyhow::Result<()> {
        for (&address, other_values_by_slot) in &other.0 {
            let values_by_slot = self.0.entry(address).or_default();
            for (&slot, &value) in other_values_by_slot {
                match values_by_slot.entry(slot) {
                    btree_map::Entry::Occupied(mut entry) => {
                        if *entry.get() != value {
                            bail!(
                                "a storage slot was read with a different value from multiple ops. Address: {address:?}, slot: {slot}, first value seen: {value}, second value seen: {}",
                                entry.get(),
                            );
                        }
                        entry.insert(value);
                    }
                    btree_map::Entry::Vacant(entry) => {
                        entry.insert(value);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
        let hash = operation.op_hash(entry_point, chain_id);
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
        let hash = operation.op_hash(entry_point, chain_id);
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
