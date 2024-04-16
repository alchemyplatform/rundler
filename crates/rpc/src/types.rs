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
    types::{Address, Bytes, Log, TransactionReceipt, H160, H256, U256},
    utils::to_checksum,
};
use rundler_pool::{Reputation, ReputationStatus};
use rundler_types::{v0_6, GasEstimate};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::eth::EthRpcError;

/// API namespace
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumString)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum ApiNamespace {
    Eth,
    Debug,
    Rundler,
    Admin,
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

/// Stake info definition for RPC
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcStakeStatus {
    pub is_staked: bool,
    pub stake_info: RpcStakeInfo,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcStakeInfo {
    pub addr: Address,
    pub stake: u128,
    pub unstake_delay_sec: u32,
}

/// User operation definition for RPC
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
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

impl From<v0_6::UserOperation> for RpcUserOperation {
    fn from(op: v0_6::UserOperation) -> Self {
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

impl TryFrom<RpcUserOperation> for v0_6::UserOperation {
    type Error = EthRpcError;

    fn try_from(def: RpcUserOperation) -> Result<Self, Self::Error> {
        if def.init_code.len() > 0 && def.init_code.len() < 20 {
            return Err(EthRpcError::InvalidParams(
                "init_code must be empty or at least 20 bytes".to_string(),
            ));
        } else if def.paymaster_and_data.len() > 0 && def.paymaster_and_data.len() < 20 {
            return Err(EthRpcError::InvalidParams(
                "paymaster_and_data must be empty or at least 20 bytes".to_string(),
            ));
        }

        Ok(v0_6::UserOperation {
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
        })
    }
}

/// User operation with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RichUserOperation {
    /// The full user operation
    pub user_operation: RpcUserOperation,
    /// The entry point address this operation was sent to
    pub entry_point: RpcAddress,
    /// The number of the block this operation was included in
    pub block_number: Option<U256>,
    /// The hash of the block this operation was included in
    pub block_hash: Option<H256>,
    /// The hash of the transaction this operation was included in
    pub transaction_hash: Option<H256>,
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
#[serde(rename_all = "camelCase")]
pub struct RpcReputationInput {
    /// Entity address
    pub address: Address,
    /// Number of operations seen in this interval
    pub ops_seen: U256,
    /// Number of operations included in this interval
    pub ops_included: U256,
}

/// Reputation of an entity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcReputationOutput {
    /// Entity address
    pub address: Address,
    /// Number of operations seen in this interval
    pub ops_seen: U256,
    /// Number of operations included in this interval
    pub ops_included: U256,
    /// Reputation status
    pub status: ReputationStatus,
}

impl From<RpcReputationInput> for Reputation {
    fn from(rpc_reputation: RpcReputationInput) -> Self {
        Reputation {
            address: rpc_reputation.address,
            ops_seen: rpc_reputation.ops_seen.as_u64(),
            ops_included: rpc_reputation.ops_included.as_u64(),
        }
    }
}

impl TryFrom<Reputation> for RpcReputationInput {
    type Error = anyhow::Error;

    fn try_from(reputation: Reputation) -> Result<Self, Self::Error> {
        Ok(RpcReputationInput {
            address: reputation.address,
            ops_seen: reputation.ops_seen.into(),
            ops_included: reputation.ops_included.into(),
        })
    }
}

/// Reputation of an entity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAdminSetTracking {
    /// Field to set the status for tracking within the paymaster
    /// module
    pub paymaster_tracking: bool,
    /// Field to set the status for tracking within the reputation
    /// module
    pub reputation_tracking: bool,
}

/// Reputation of an entity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAdminClearState {
    /// Field to set whether to clear entire mempool
    pub clear_mempool: Option<bool>,
    /// Field to set whether to clear paymaster state
    pub clear_paymaster: Option<bool>,
    /// Field to set whether to clear reputation state
    pub clear_reputation: Option<bool>,
}

/// Paymaster balance
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcDebugPaymasterBalance {
    /// Paymaster address
    pub address: Address,
    /// Paymaster balance including pending UOs in pool
    pub pending_balance: U256,
    /// Paymaster confirmed balance onchain
    pub confirmed_balance: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RpcGasEstimate {
    /// The pre-verification gas estimate
    pub pre_verification_gas: U256,
    /// The call gas limit estimate
    pub call_gas_limit: U256,
    /// The verification gas limit estimate
    pub verification_gas_limit: U256,
    /// The paymaster verification gas limit estimate
    /// 0.6: unused
    /// 0.7: populated if a paymaster is used
    pub paymaster_verification_gas_limit: Option<U256>,
    /// The paymaster post op gas limit
    /// 0.6: unused
    /// 0.7: populated if a paymaster is used
    pub paymaster_post_op_gas_limit: Option<U256>,
}

impl From<GasEstimate> for RpcGasEstimate {
    fn from(estimate: GasEstimate) -> Self {
        RpcGasEstimate {
            pre_verification_gas: estimate.pre_verification_gas,
            call_gas_limit: estimate.call_gas_limit,
            verification_gas_limit: estimate.verification_gas_limit,
            paymaster_verification_gas_limit: estimate.paymaster_verification_gas_limit,
            paymaster_post_op_gas_limit: estimate.paymaster_post_op_gas_limit,
        }
    }
}
