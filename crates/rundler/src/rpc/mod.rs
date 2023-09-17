mod debug;
mod eth;
mod health;
mod metrics;
mod rundler;
mod task;

pub use debug::DebugApiClient;
pub use eth::{EthApiClient, EthApiSettings};
use ethers::{
    types::{Address, Bytes, Log, TransactionReceipt, H160, H256, U256},
    utils::to_checksum,
};
use jsonrpsee::types::{ErrorObject, ErrorObjectOwned};
use rundler_pool::{Reputation, ReputationStatus};
use rundler_types::UserOperation;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use strum;
pub use task::*;

/// API namespace
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumString)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum ApiNamespace {
    Eth,
    Debug,
    Rundler,
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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

/// User operation with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RichUserOperation {
    pub user_operation: RpcUserOperation,
    pub entry_point: RpcAddress,
    pub block_number: U256,
    pub block_hash: H256,
    pub transaction_hash: H256,
}

/// User operation receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOperationReceipt {
    pub user_op_hash: H256,
    pub entry_point: RpcAddress,
    pub sender: RpcAddress,
    pub nonce: U256,
    pub paymaster: RpcAddress,
    pub actual_gas_cost: U256,
    pub actual_gas_used: U256,
    pub success: bool,
    pub reason: String,
    pub logs: Vec<Log>,
    pub receipt: TransactionReceipt,
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
            address: rpc_reputation.address,
            ops_seen: rpc_reputation.ops_seen.as_u64(),
            ops_included: rpc_reputation.ops_included.as_u64(),
            status: rpc_reputation.status,
        }
    }
}

impl TryFrom<Reputation> for RpcReputation {
    type Error = anyhow::Error;

    fn try_from(reputation: Reputation) -> Result<Self, Self::Error> {
        Ok(RpcReputation {
            address: reputation.address,
            ops_seen: reputation.ops_seen.into(),
            ops_included: reputation.ops_included.into(),
            status: reputation.status,
        })
    }
}

pub fn rpc_err(code: i32, msg: impl Into<String>) -> ErrorObjectOwned {
    create_rpc_err(code, msg, None::<()>)
}

pub fn rpc_err_with_data<S: Serialize>(
    code: i32,
    msg: impl Into<String>,
    data: S,
) -> ErrorObjectOwned {
    create_rpc_err(code, msg, Some(data))
}

fn create_rpc_err<S: Serialize>(
    code: i32,
    msg: impl Into<String>,
    data: Option<S>,
) -> ErrorObjectOwned {
    ErrorObject::owned(code, msg.into(), data)
}
