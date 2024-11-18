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

use alloy_primitives::{Address, Bytes, U128, U256};
use rundler_types::{
    authorization::Authorization,
    chain::ChainSpec,
    v0_6::{
        ExtendedUserOperation, UserOperation, UserOperationBuilder, UserOperationOptionalGas,
        UserOperationRequiredFields,
    },
    GasEstimate,
};
use serde::{Deserialize, Serialize};

use super::{FromRpc, RpcAddress};

/// User operation definition for RPC
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcUserOperation {
    sender: RpcAddress,
    nonce: U256,
    init_code: Bytes,
    call_data: Bytes,
    call_gas_limit: U128,
    verification_gas_limit: U128,
    pre_verification_gas: U128,
    max_fee_per_gas: U128,
    max_priority_fee_per_gas: U128,
    paymaster_and_data: Bytes,
    signature: Bytes,
    authorization_tuple: Option<Authorization>,
}

impl From<UserOperation> for RpcUserOperation {
    fn from(op: UserOperation) -> Self {
        RpcUserOperation {
            sender: op.sender.into(),
            nonce: op.nonce,
            init_code: op.init_code,
            call_data: op.call_data,
            call_gas_limit: U128::from(op.call_gas_limit),
            verification_gas_limit: U128::from(op.verification_gas_limit),
            pre_verification_gas: U128::from(op.pre_verification_gas),
            max_fee_per_gas: U128::from(op.max_fee_per_gas),
            max_priority_fee_per_gas: U128::from(op.max_priority_fee_per_gas),
            paymaster_and_data: op.paymaster_and_data,
            signature: op.signature,
            authorization_tuple: op.authorization_tuple,
        }
    }
}

impl FromRpc<RpcUserOperation> for UserOperation {
    fn from_rpc(def: RpcUserOperation, chain_spec: &ChainSpec) -> Self {
        UserOperationBuilder::new(
            chain_spec,
            UserOperationRequiredFields {
                sender: def.sender.into(),
                nonce: def.nonce,
                init_code: def.init_code,
                call_data: def.call_data,
                call_gas_limit: def.call_gas_limit.to(),
                verification_gas_limit: def.verification_gas_limit.to(),
                pre_verification_gas: def.pre_verification_gas.to(),
                max_fee_per_gas: def.max_fee_per_gas.to(),
                max_priority_fee_per_gas: def.max_priority_fee_per_gas.to(),
                paymaster_and_data: def.paymaster_and_data,
                signature: def.signature,
            },
            ExtendedUserOperation {
                authorization_tuple: def.authorization_tuple,
            },
        )
        .build()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcUserOperationOptionalGas {
    sender: Address,
    nonce: U256,
    init_code: Bytes,
    call_data: Bytes,
    call_gas_limit: Option<U128>,
    verification_gas_limit: Option<U128>,
    pre_verification_gas: Option<U128>,
    max_fee_per_gas: Option<U128>,
    max_priority_fee_per_gas: Option<U128>,
    paymaster_and_data: Bytes,
    signature: Bytes,
    authorization_tuple: Option<Authorization>,
}

impl From<RpcUserOperationOptionalGas> for UserOperationOptionalGas {
    fn from(def: RpcUserOperationOptionalGas) -> Self {
        UserOperationOptionalGas {
            sender: def.sender,
            nonce: def.nonce,
            init_code: def.init_code,
            call_data: def.call_data,
            call_gas_limit: def.call_gas_limit.map(|x| x.to()),
            verification_gas_limit: def.verification_gas_limit.map(|x| x.to()),
            pre_verification_gas: def.pre_verification_gas.map(|x| x.to()),
            max_fee_per_gas: def.max_fee_per_gas.map(|x| x.to()),
            max_priority_fee_per_gas: def.max_priority_fee_per_gas.map(|x| x.to()),
            paymaster_and_data: def.paymaster_and_data,
            signature: def.signature,
            authorization_tuple: def.authorization_tuple,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcGasEstimate {
    pre_verification_gas: U128,
    call_gas_limit: U128,
    verification_gas_limit: U128,
}

impl From<GasEstimate> for RpcGasEstimate {
    fn from(estimate: GasEstimate) -> Self {
        RpcGasEstimate {
            pre_verification_gas: U128::from(estimate.pre_verification_gas),
            call_gas_limit: U128::from(estimate.call_gas_limit),
            verification_gas_limit: U128::from(estimate.verification_gas_limit),
        }
    }
}
