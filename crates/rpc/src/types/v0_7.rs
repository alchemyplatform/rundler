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

use alloy_primitives::{Address, Bytes, B256, U128, U256};
use rundler_types::{
    authorization::Authorization,
    chain::ChainSpec,
    v0_7::{
        UserOperation, UserOperationBuilder, UserOperationOptionalGas, UserOperationRequiredFields,
    },
    GasEstimate,
};
use serde::{Deserialize, Serialize};

use super::{FromRpc, RpcAddress};

/// User operation definition for RPC inputs
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
    #[serde(skip_serializing_if = "Option::is_none")]
    factory: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    factory_data: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paymaster: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paymaster_verification_gas_limit: Option<U128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paymaster_post_op_gas_limit: Option<U128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paymaster_data: Option<Bytes>,
    signature: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_tuple: Option<Authorization>,
}

impl From<UserOperation> for RpcUserOperation {
    fn from(op: UserOperation) -> Self {
        let factory_data = if op.factory.is_some() {
            Some(op.factory_data)
        } else {
            None
        };
        let (paymaster_data, paymaster_verification_gas_limit, paymaster_post_op_gas_limit) =
            if op.paymaster.is_some() {
                (
                    Some(op.paymaster_data),
                    Some(op.paymaster_verification_gas_limit),
                    Some(op.paymaster_post_op_gas_limit),
                )
            } else {
                (None, None, None)
            };

        RpcUserOperation {
            sender: op.sender,
            nonce: op.nonce,
            call_data: op.call_data,
            call_gas_limit: U128::from(op.call_gas_limit),
            verification_gas_limit: U128::from(op.verification_gas_limit),
            pre_verification_gas: U256::from(op.pre_verification_gas),
            max_priority_fee_per_gas: U128::from(op.max_priority_fee_per_gas),
            max_fee_per_gas: U128::from(op.max_fee_per_gas),
            factory: op.factory,
            factory_data,
            paymaster: op.paymaster,
            paymaster_verification_gas_limit: paymaster_verification_gas_limit
                .map(|x| U128::from(x)),
            paymaster_post_op_gas_limit: paymaster_post_op_gas_limit.map(|x| U128::from(x)),
            paymaster_data,
            signature: op.signature,
            authorization_tuple: op.authorization_tuple,
        }
    }
}

impl FromRpc<RpcUserOperation> for UserOperation {
    fn from_rpc(def: RpcUserOperation, chain_spec: &ChainSpec) -> Self {
        let mut builder = UserOperationBuilder::new(
            chain_spec,
            UserOperationRequiredFields {
                sender: def.sender,
                nonce: def.nonce,
                call_data: def.call_data,
                call_gas_limit: def.call_gas_limit.to(),
                verification_gas_limit: def.verification_gas_limit.to(),
                pre_verification_gas: def.pre_verification_gas.to(),
                max_priority_fee_per_gas: def.max_priority_fee_per_gas.to(),
                max_fee_per_gas: def.max_fee_per_gas.to(),
                signature: def.signature,
            },
        );
        if def.paymaster.is_some() {
            builder = builder.paymaster(
                def.paymaster.unwrap(),
                def.paymaster_verification_gas_limit
                    .map(|x| x.to())
                    .unwrap_or_default(),
                def.paymaster_post_op_gas_limit
                    .map(|x| x.to())
                    .unwrap_or_default(),
                def.paymaster_data.unwrap_or_default(),
            );
        }
        if def.factory.is_some() {
            builder = builder.factory(def.factory.unwrap(), def.factory_data.unwrap_or_default());
        }
        if def.authorization_tuple.is_some() {
            builder = builder.authorization_tuple(def.authorization_tuple);
        }
        builder.build()
    }
}

/// User operation with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcUserOperationByHash {
    user_operation: RpcUserOperation,
    entry_point: RpcAddress,
    block_number: Option<U256>,
    block_hash: Option<B256>,
    transaction_hash: Option<B256>,
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
    contract_address: Option<Address>,
}

impl From<RpcUserOperationOptionalGas> for UserOperationOptionalGas {
    fn from(def: RpcUserOperationOptionalGas) -> Self {
        UserOperationOptionalGas {
            sender: def.sender,
            nonce: def.nonce,
            call_data: def.call_data,
            call_gas_limit: def.call_gas_limit.map(|x| x.to()),
            verification_gas_limit: def.verification_gas_limit.map(|x| x.to()),
            pre_verification_gas: def.pre_verification_gas.map(|x| x.to()),
            max_priority_fee_per_gas: def.max_priority_fee_per_gas.map(|x| x.to()),
            max_fee_per_gas: def.max_fee_per_gas.map(|x| x.to()),
            factory: def.factory,
            factory_data: def.factory_data.unwrap_or_default(),
            paymaster: def.paymaster,
            paymaster_verification_gas_limit: def.paymaster_verification_gas_limit.map(|x| x.to()),
            paymaster_post_op_gas_limit: def.paymaster_post_op_gas_limit.map(|x| x.to()),
            paymaster_data: def.paymaster_data.unwrap_or_default(),
            signature: def.signature,
            contract_address: def.contract_address,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcGasEstimate {
    pre_verification_gas: U128,
    call_gas_limit: U128,
    verification_gas_limit: U128,
    paymaster_verification_gas_limit: Option<U128>,
}

impl From<GasEstimate> for RpcGasEstimate {
    fn from(estimate: GasEstimate) -> Self {
        RpcGasEstimate {
            pre_verification_gas: U128::from(estimate.pre_verification_gas),
            call_gas_limit: U128::from(estimate.call_gas_limit),
            verification_gas_limit: U128::from(estimate.verification_gas_limit),
            paymaster_verification_gas_limit: estimate
                .paymaster_verification_gas_limit
                .map(|x| U128::from(x)),
        }
    }
}
