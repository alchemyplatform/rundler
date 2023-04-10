mod timestamp;
mod validation_results;
mod violations;

use std::str::FromStr;

use anyhow::bail;
use ethers::{
    abi::{encode, Token},
    types::{Address, Bytes, U256},
};
use parse_display::Display;
use serde::{Deserialize, Serialize};
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
        let mut packed = encode(&[
            Token::Address(self.sender),
            Token::Uint(self.nonce),
            Token::Bytes(self.init_code.to_vec()),
            Token::Bytes(self.call_data.to_vec()),
            Token::Uint(self.call_gas_limit),
            Token::Uint(self.verification_gas_limit),
            Token::Uint(self.pre_verification_gas),
            Token::Uint(self.max_fee_per_gas),
            Token::Uint(self.max_priority_fee_per_gas),
            Token::Bytes(self.paymaster_and_data.to_vec()),
            // Packed user operation does not include the signature, zero it out
            // and then truncate the size entry at end (32 bytes)
            Token::Bytes(vec![]),
        ]);
        // Remove the signature size entry at the end
        packed.truncate(packed.len() - 32);
        packed.into()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ExpectedStorageSlot {
    pub address: Address,
    pub slot: U256,
    pub value: U256,
}

#[derive(Display, Debug, Clone, Ord, Copy, Eq, PartialEq, EnumIter, PartialOrd)]
#[display(style = "lowercase")]
pub enum Entity {
    Account,
    Paymaster,
    Aggregator,
    Factory,
}

impl FromStr for Entity {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "account" => Ok(Entity::Account),
            "paymaster" => Ok(Entity::Paymaster),
            "aggregator" => Ok(Entity::Aggregator),
            "factory" => Ok(Entity::Factory),
            _ => bail!("Invalid entity: {s}"),
        }
    }
}

#[derive(Display, Debug, Clone, Copy, Eq, PartialEq, EnumIter, Serialize, Deserialize)]
#[display(style = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum BundlingMode {
    Manual,
    Auto,
}

#[cfg(test)]
mod tests {
    use super::*;

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
