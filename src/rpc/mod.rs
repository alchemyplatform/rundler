mod debug;
mod eth;
mod health;
mod metrics;
mod run;

use anyhow::bail;
use ethers::{
    types::{Address, Bytes, Log, TransactionReceipt, H160, H256, U256},
    utils::to_checksum,
};
pub use run::*;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use strum;

use crate::common::{
    gas,
    protos::{
        op_pool::{Reputation, ReputationStatus},
        ProtoBytes,
    },
    types::UserOperation,
};

/// API namespace
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumString)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum ApiNamespace {
    Eth,
    Debug,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcAddress(H160);

impl Serialize for RpcAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&to_checksum(&self.0, None))
    }
}

impl<'de> Deserialize<'de> for RpcAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let address = Address::deserialize(deserializer)?;
        Ok(RpcAddress(address))
    }
}

impl From<RpcAddress> for Address {
    fn from(rpc_addr: RpcAddress) -> Self {
        rpc_addr.0
    }
}

impl From<Address> for RpcAddress {
    fn from(addr: Address) -> Self {
        RpcAddress(addr)
    }
}

/// User operation definition for RPC
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcUserOperation {
    sender: RpcAddress,
    nonce: U256,
    init_code: Bytes,
    call_data: Bytes,
    call_gas_limit: U256,
    verification_gas_limit: U256,
    pre_verification_gas: U256,
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
    paymaster_and_data: Bytes,
    signature: Bytes,
}

impl From<UserOperation> for RpcUserOperation {
    fn from(op: UserOperation) -> Self {
        RpcUserOperation {
            sender: op.sender.into(),
            nonce: op.nonce,
            init_code: op.init_code,
            call_data: op.call_data,
            call_gas_limit: op.call_gas_limit,
            verification_gas_limit: op.verification_gas_limit,
            pre_verification_gas: op.pre_verification_gas,
            max_fee_per_gas: op.max_fee_per_gas,
            max_priority_fee_per_gas: op.max_priority_fee_per_gas,
            paymaster_and_data: op.paymaster_and_data,
            signature: op.signature,
        }
    }
}

impl From<RpcUserOperation> for UserOperation {
    fn from(def: RpcUserOperation) -> Self {
        UserOperation {
            sender: def.sender.into(),
            nonce: def.nonce,
            init_code: def.init_code,
            call_data: def.call_data,
            call_gas_limit: def.call_gas_limit,
            verification_gas_limit: def.verification_gas_limit,
            pre_verification_gas: def.pre_verification_gas,
            max_fee_per_gas: def.max_fee_per_gas,
            max_priority_fee_per_gas: def.max_priority_fee_per_gas,
            paymaster_and_data: def.paymaster_and_data,
            signature: def.signature,
        }
    }
}

/// User operation with optional gas fields for gas estimation RPC
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UserOperationOptionalGas {
    sender: Address,
    nonce: U256,
    init_code: Bytes,
    call_data: Bytes,
    call_gas_limit: Option<U256>,
    verification_gas_limit: Option<U256>,
    pre_verification_gas: Option<U256>,
    max_fee_per_gas: Option<U256>,
    max_priority_fee_per_gas: Option<U256>,
    paymaster_and_data: Bytes,
    signature: Bytes,
}

impl UserOperationOptionalGas {
    pub fn cheap_clone(&self) -> Self {
        self.clone()
    }
}

impl UserOperationOptionalGas {
    pub fn calc_pre_verification_gas(&self) -> U256 {
        gas::calc_pre_verification_gas(&UserOperation::from(self.cheap_clone()))
    }
}

impl From<UserOperationOptionalGas> for UserOperation {
    fn from(op: UserOperationOptionalGas) -> Self {
        UserOperation {
            sender: op.sender,
            nonce: op.nonce,
            init_code: op.init_code,
            call_data: op.call_data,
            call_gas_limit: op.call_gas_limit.unwrap_or_default(),
            verification_gas_limit: op.verification_gas_limit.unwrap_or_default(),
            pre_verification_gas: op.pre_verification_gas.unwrap_or_else(|| 21000.into()), // this dummy is used in calc_pre_verification_gas
            max_fee_per_gas: op.max_fee_per_gas.unwrap_or_default(),
            max_priority_fee_per_gas: op.max_priority_fee_per_gas.unwrap_or_default(),
            paymaster_and_data: op.paymaster_and_data,
            signature: op.signature,
        }
    }
}

/// Gas estimate for a user operation
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GasEstimate {
    pub pre_verification_gas: U256,
    pub verification_gas: U256,
    pub call_gas_limit: U256,
}

/// User operation with additional metadata
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RichUserOperation {
    pub user_operation: RpcUserOperation,
    pub entry_point: RpcAddress,
    pub block_number: U256,
    pub block_hash: H256,
    pub transaction_hash: H256,
}

/// User operation receipt
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOperationReceipt {
    pub user_op_hash: H256,
    pub entry_point: RpcAddress,
    pub sender: RpcAddress,
    pub nonce: U256,
    pub paymaster: RpcAddress,
    pub actual_gas_cost: U256,
    pub acutal_gas_used: U256,
    pub success: bool,
    pub reason: Option<String>,
    pub logs: Vec<Log>,
    pub receipt: TransactionReceipt,
}

impl Serialize for ReputationStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ReputationStatus::Ok => serializer.serialize_str("ok"),
            ReputationStatus::Throttled => serializer.serialize_str("throttled"),
            ReputationStatus::Banned => serializer.serialize_str("banned"),
        }
    }
}

impl<'de> Deserialize<'de> for ReputationStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "ok" => Ok(ReputationStatus::Ok),
            "throttled" => Ok(ReputationStatus::Throttled),
            "banned" => Ok(ReputationStatus::Banned),
            _ => Err(de::Error::custom(format!("Invalid reputation status {s}"))),
        }
    }
}

impl TryFrom<i32> for ReputationStatus {
    type Error = anyhow::Error;

    fn try_from(status: i32) -> Result<Self, Self::Error> {
        match status {
            0 => Ok(ReputationStatus::Ok),
            1 => Ok(ReputationStatus::Throttled),
            2 => Ok(ReputationStatus::Banned),
            _ => bail!("Invalid reputation status {status}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReputation {
    pub address: Address,
    pub ops_seen: U256,
    pub ops_included: U256,
    pub status: ReputationStatus,
}

impl From<RpcReputation> for Reputation {
    fn from(rpc_reputation: RpcReputation) -> Self {
        Reputation {
            address: rpc_reputation.address.as_bytes().to_vec(),
            ops_seen: rpc_reputation.ops_seen.as_u64(),
            ops_included: rpc_reputation.ops_included.as_u64(),
            status: rpc_reputation.status.into(),
        }
    }
}

impl TryFrom<Reputation> for RpcReputation {
    type Error = anyhow::Error;

    fn try_from(reputation: Reputation) -> Result<Self, Self::Error> {
        Ok(RpcReputation {
            address: ProtoBytes(&reputation.address).try_into()?,
            ops_seen: reputation.ops_seen.into(),
            ops_included: reputation.ops_included.into(),
            status: reputation.status.try_into()?,
        })
    }
}
