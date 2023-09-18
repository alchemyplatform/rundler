use ethers::{
    types::{Address, Bytes, Log, TransactionReceipt, H160, H256, U256},
    utils::to_checksum,
};
use rundler_pool::{Reputation, ReputationStatus};
use rundler_types::UserOperation;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
    /// The full user operation
    pub user_operation: RpcUserOperation,
    /// The entry point address this operation was sent to
    pub entry_point: RpcAddress,
    /// The number of the block this operation was included in
    pub block_number: U256,
    /// The hash of the block this operation was included in
    pub block_hash: H256,
    /// The hash of the transaction this operation was included in
    pub transaction_hash: H256,
}

/// User operation receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOperationReceipt {
    /// The hash of the user operation
    pub user_op_hash: H256,
    /// The entry point address this operation was sent to
    pub entry_point: RpcAddress,
    /// The sender of this user operation
    pub sender: RpcAddress,
    /// The nonce of this user operation
    pub nonce: U256,
    /// The paymaster used by this operation, empty if none used
    pub paymaster: RpcAddress,
    /// The gas cost of this operation
    pub actual_gas_cost: U256,
    /// The gas used by this operation
    pub actual_gas_used: U256,
    /// Whether this operation's execution was successful
    pub success: bool,
    /// If not successful, the revert reason string
    pub reason: String,
    /// Logs emitted by this operation
    pub logs: Vec<Log>,
    /// The receipt of the transaction that included this operation
    pub receipt: TransactionReceipt,
}

/// Reputation of an entity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReputation {
    /// Entity address
    pub address: Address,
    /// Number of operations seen in this interval
    pub ops_seen: U256,
    /// Number of operations included in this interval
    pub ops_included: U256,
    /// Reputation status
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
