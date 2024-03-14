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

use ethers::types::{Address, Bytes, H256, U128, U256};
use rundler_types::v0_7::{UserOperation, UserOperationOptionalGas};
use serde::{Deserialize, Serialize};

use super::RpcAddress;

/// User operation definition for RPC
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcUserOperation {
    sender: Address,
    nonce: U256,
    call_data: Bytes,
    call_gas_limit: U128,
    verification_gas_limit: U128,
    pre_verification_gas: U256,
    max_priority_fee_per_gas: U128,
    max_fee_per_gas: U128,
    factory: Option<Address>,
    factory_data: Option<Bytes>,
    paymaster: Option<Address>,
    paymaster_verification_gas_limit: Option<U128>,
    paymaster_post_op_gas_limit: Option<U128>,
    paymaster_data: Option<Bytes>,
    signature: Bytes,
}

impl From<UserOperation> for RpcUserOperation {
    fn from(_op: UserOperation) -> Self {
        todo!()
    }
}

impl From<RpcUserOperation> for UserOperation {
    fn from(_def: RpcUserOperation) -> Self {
        todo!()
    }
}

/// User operation with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcUserOperationByHash {
    user_operation: RpcUserOperation,
    entry_point: RpcAddress,
    block_number: Option<U256>,
    block_hash: Option<H256>,
    transaction_hash: Option<H256>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcUserOperationOptionalGas {
    sender: Address,
    nonce: U256,
    call_data: Bytes,
    call_gas_limit: Option<U128>,
    verification_gas_limit: Option<U128>,
    pre_verification_gas: Option<U256>,
    max_priority_fee_per_gas: Option<U128>,
    max_fee_per_gas: Option<U128>,
    factory: Option<Address>,
    factory_data: Option<Bytes>,
    paymaster: Option<Address>,
    paymaster_verification_gas_limit: Option<U128>,
    paymaster_post_op_gas_limit: Option<U128>,
    paymaster_data: Option<Bytes>,
    signature: Bytes,
}

impl From<RpcUserOperationOptionalGas> for UserOperationOptionalGas {
    fn from(_def: RpcUserOperationOptionalGas) -> Self {
        todo!()
    }
}
