mod debug;
mod eth;
mod run;

use crate::common::{
    protos::{
        op_pool::{Reputation, ReputationStatus},
        ProtoBytes,
    },
    types::UserOperation,
};
use anyhow::bail;
use ethers::types::{Address, Bytes, Log, TransactionReceipt, H256, U256};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use strum;

pub use run::*;

/// API namespace
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumString)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum ApiNamespace {
    Eth,
    Debug,
}

impl<'de> Deserialize<'de> for UserOperation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        UserOperationDef::deserialize(deserializer)
    }
}

impl Serialize for UserOperation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        UserOperationDef::serialize(self, serializer)
    }
}

/// User operation definition for RPC
#[derive(Deserialize, Serialize)]
#[serde(remote = "UserOperation", rename_all = "camelCase")]
struct UserOperationDef {
    sender: Address,
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

/// User operation with optional gas fields for gas estimation RPC
#[derive(Deserialize)]
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

impl From<UserOperationOptionalGas> for UserOperation {
    fn from(op: UserOperationOptionalGas) -> Self {
        UserOperation {
            sender: op.sender,
            nonce: op.nonce,
            init_code: op.init_code,
            call_data: op.call_data,
            call_gas_limit: op.call_gas_limit.unwrap_or_default(),
            verification_gas_limit: op.verification_gas_limit.unwrap_or_default(),
            pre_verification_gas: op.pre_verification_gas.unwrap_or_default(),
            max_fee_per_gas: op.max_fee_per_gas.unwrap_or_default(),
            max_priority_fee_per_gas: op.max_priority_fee_per_gas.unwrap_or_default(),
            paymaster_and_data: op.paymaster_and_data,
            signature: op.signature,
        }
    }
}

/// Gas estimate for a user operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GasEstimate {
    pub pre_verification_gas: U256,
    pub verification_gas_limit: U256,
    pub call_gas_limit: U256,
}

/// User operation with additional metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RichUserOperation {
    pub user_operation: UserOperation,
    pub entry_point: Address,
    pub block_number: U256,
    pub block_hash: H256,
    pub transaction_hash: H256,
}

/// User operation receipt
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOperationReceipt {
    pub user_op_hash: H256,
    pub entry_point: Address,
    pub sender: Address,
    pub nonce: U256,
    pub paymaster: Address,
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
