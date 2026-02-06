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

use alloy_primitives::{Address, Bytes, U128, U256, bytes};
use rundler_types::{
    EntryPointVersion, GasEstimate,
    authorization::Eip7702Auth,
    chain::ChainSpec,
    v0_7::{
        EIP7702_FACTORY_MARKER, UserOperation, UserOperationBuilder, UserOperationOptionalGas,
        UserOperationRequiredFields,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    eth::EthRpcError,
    utils::{FromRpcType, TryFromRpcType},
};

/// User operation definition for RPC inputs
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcUserOperation {
    sender: Address,
    nonce: U256,
    call_data: Bytes,
    call_gas_limit: U128,
    verification_gas_limit: U128,
    pre_verification_gas: U256,
    max_priority_fee_per_gas: U128,
    max_fee_per_gas: U128,
    #[serde(skip_serializing_if = "Option::is_none")]
    factory: Option<Bytes>,
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
    eip7702_auth: Option<Eip7702Auth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregator: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paymaster_signature: Option<Bytes>,
}

impl From<UserOperation> for RpcUserOperation {
    fn from(op: UserOperation) -> Self {
        let op = op.into_unstructured();

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
            factory: op.factory.map(|f| f.to_vec().into()),
            factory_data,
            paymaster: op.paymaster,
            paymaster_verification_gas_limit: paymaster_verification_gas_limit
                .map(|x| U128::from(x)),
            paymaster_post_op_gas_limit: paymaster_post_op_gas_limit.map(|x| U128::from(x)),
            paymaster_data,
            signature: op.signature,
            eip7702_auth: op.authorization_tuple,
            aggregator: op.aggregator,
            paymaster_signature: op.paymaster_signature,
        }
    }
}

impl TryFromRpcType<RpcUserOperation> for UserOperation {
    fn try_from_rpc_type(
        def: RpcUserOperation,
        chain_spec: &ChainSpec,
        ep_version: EntryPointVersion,
    ) -> Result<Self, EthRpcError> {
        if ep_version < EntryPointVersion::V0_7 {
            return Err(EthRpcError::InvalidParams(format!(
                "Received v0.7+ user operation payload, but entry point version is {:?} based on the address.",
                ep_version
            )));
        }

        let mut builder = UserOperationBuilder::new(
            chain_spec,
            ep_version,
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
        if let Some(paymaster) = def.paymaster {
            builder = builder.paymaster(
                paymaster,
                def.paymaster_verification_gas_limit
                    .map(|x| x.to())
                    .unwrap_or_default(),
                def.paymaster_post_op_gas_limit
                    .map(|x| x.to())
                    .unwrap_or_default(),
                def.paymaster_data.unwrap_or_default(),
            );
        }
        if let Some(factory) = def.factory {
            // special handling for "0x7702" shortened factory marker
            let factory = if factory == bytes!("7702") {
                EIP7702_FACTORY_MARKER
            } else if factory.len() == 20 {
                Address::from_slice(&factory)
            } else {
                return Err(EthRpcError::InvalidParams(format!(
                    "Invalid factory length. Expected 20 bytes. Got: {:?}",
                    factory.len()
                )));
            };

            builder = builder.factory(factory, def.factory_data.unwrap_or_default());
        }
        if let Some(auth) = def.eip7702_auth {
            builder = builder.authorization_tuple(auth);
        }
        if let Some(aggregator) = def.aggregator {
            builder = builder.aggregator(aggregator);
        }
        if let Some(paymaster_signature) = def.paymaster_signature {
            if ep_version < EntryPointVersion::V0_9 {
                return Err(EthRpcError::InvalidParams(format!(
                    "Paymaster signature is only supported for entry point v0.9+ (got: {:?})",
                    ep_version
                )));
            }

            builder = builder.paymaster_signature(paymaster_signature);
        }

        Ok(builder.build())
    }
}

/// v0.7 user operation with optional gas fields for estimation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RpcUserOperationOptionalGas {
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
    eip7702_auth: Option<Eip7702Auth>,
    aggregator: Option<Address>,
    paymaster_signature: Option<Bytes>,
}

impl FromRpcType<RpcUserOperationOptionalGas> for UserOperationOptionalGas {
    fn from_rpc_type(
        def: RpcUserOperationOptionalGas,
        _chain_spec: &ChainSpec,
        ep_version: EntryPointVersion,
    ) -> Self {
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
            eip7702_auth_address: def.eip7702_auth.map(|a| a.address),
            aggregator: def.aggregator,
            paymaster_signature: def.paymaster_signature,
            entry_point_version: ep_version,
        }
    }
}

/// v0.7 gas estimate for a user operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RpcGasEstimate {
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
