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
    types::{Address, Log, TransactionReceipt, H160, H256, U256},
    utils::to_checksum,
};
use rundler_types::{
    chain::ChainSpec,
    pool::{Reputation, ReputationStatus},
    v0_6::UserOperation as UserOperationV0_6,
    v0_7::UserOperation as UserOperationV0_7,
    UserOperationOptionalGas, UserOperationVariant,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

mod v0_6;
pub(crate) use v0_6::{
    RpcGasEstimate as RpcGasEstimateV0_6, RpcUserOperation as RpcUserOperationV0_6,
    RpcUserOperationOptionalGas as RpcUserOperationOptionalGasV0_6,
};
mod v0_7;
pub(crate) use v0_7::{
    RpcGasEstimate as RpcGasEstimateV0_7, RpcUserOperation as RpcUserOperationV0_7,
    RpcUserOperationOptionalGas as RpcUserOperationOptionalGasV0_7,
};

/// API namespace
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumString)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum ApiNamespace {
    Eth,
    Debug,
    Rundler,
    Admin,
}

/// Conversion trait for RPC types adding the context of the entry point and chain id
pub(crate) trait FromRpc<R> {
    fn from_rpc(rpc: R, chain_spec: &ChainSpec) -> Self;
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
pub(crate) struct RpcStakeStatus {
    pub(crate) is_staked: bool,
    pub(crate) stake_info: RpcStakeInfo,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcStakeInfo {
    pub(crate) addr: Address,
    pub(crate) stake: u128,
    pub(crate) unstake_delay_sec: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(untagged)]
pub(crate) enum RpcUserOperation {
    V0_6(RpcUserOperationV0_6),
    V0_7(RpcUserOperationV0_7),
}

impl From<UserOperationVariant> for RpcUserOperation {
    fn from(op: UserOperationVariant) -> Self {
        match op {
            UserOperationVariant::V0_6(op) => RpcUserOperation::V0_6(op.into()),
            UserOperationVariant::V0_7(op) => RpcUserOperation::V0_7(op.into()),
        }
    }
}

impl FromRpc<RpcUserOperation> for UserOperationVariant {
    fn from_rpc(op: RpcUserOperation, chain_spec: &ChainSpec) -> Self {
        match op {
            RpcUserOperation::V0_6(op) => {
                UserOperationVariant::V0_6(UserOperationV0_6::from_rpc(op, chain_spec))
            }
            RpcUserOperation::V0_7(op) => {
                UserOperationVariant::V0_7(UserOperationV0_7::from_rpc(op, chain_spec))
            }
        }
    }
}

/// User operation with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcUserOperationByHash {
    /// The full user operation
    pub(crate) user_operation: RpcUserOperation,
    /// The entry point address this operation was sent to
    pub(crate) entry_point: RpcAddress,
    /// The number of the block this operation was included in
    pub(crate) block_number: Option<U256>,
    /// The hash of the block this operation was included in
    pub(crate) block_hash: Option<H256>,
    /// The hash of the transaction this operation was included in
    pub(crate) transaction_hash: Option<H256>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum RpcUserOperationOptionalGas {
    V0_6(RpcUserOperationOptionalGasV0_6),
    V0_7(RpcUserOperationOptionalGasV0_7),
}

impl From<RpcUserOperationOptionalGas> for UserOperationOptionalGas {
    fn from(op: RpcUserOperationOptionalGas) -> Self {
        match op {
            RpcUserOperationOptionalGas::V0_6(op) => UserOperationOptionalGas::V0_6(op.into()),
            RpcUserOperationOptionalGas::V0_7(op) => UserOperationOptionalGas::V0_7(op.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub(crate) enum RpcGasEstimate {
    V0_6(RpcGasEstimateV0_6),
    V0_7(RpcGasEstimateV0_7),
}

impl From<RpcGasEstimateV0_6> for RpcGasEstimate {
    fn from(estimate: RpcGasEstimateV0_6) -> Self {
        RpcGasEstimate::V0_6(estimate)
    }
}

impl From<RpcGasEstimateV0_7> for RpcGasEstimate {
    fn from(estimate: RpcGasEstimateV0_7) -> Self {
        RpcGasEstimate::V0_7(estimate)
    }
}

/// User operation receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcUserOperationReceipt {
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
