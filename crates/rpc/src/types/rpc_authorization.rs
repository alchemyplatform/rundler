use alloy_primitives::{Address, U256, U64, U8};
use rundler_types::authorization::Authorization;
use serde::{Deserialize, Serialize};

/// authorization tuple for 7702 txn support
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcAuthorization {
    /// The chain ID of the authorization.
    pub chain_id: U64,
    /// The address of the authorization.
    pub address: Address,
    /// The nonce for the authorization.
    pub nonce: U64,
    /// signed authorizzation tuple.
    pub y_parity: U8,
    /// signed authorizzation tuple.
    pub r: U256,
    /// signed authorizzation tuple.
    pub s: U256,
}

impl From<RpcAuthorization> for Authorization {
    fn from(val: RpcAuthorization) -> Self {
        Authorization {
            chain_id: val.chain_id.to(),
            address: val.address,
            nonce: val.nonce.to(),
            y_parity: val.y_parity.to(),
            r: val.r,
            s: val.s,
        }
    }
}

impl From<Authorization> for RpcAuthorization {
    fn from(value: Authorization) -> Self {
        Self {
            chain_id: U64::from(value.chain_id),
            address: value.address,
            nonce: U64::from(value.nonce),
            y_parity: U8::from(value.y_parity),
            r: value.r,
            s: value.s,
        }
    }
}
