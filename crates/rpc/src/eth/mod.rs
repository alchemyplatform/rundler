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

mod api;
pub(crate) use api::EthApi;

mod router;
pub(crate) use router::*;

mod error;
pub(crate) use error::{EthResult, EthRpcError};
mod events;
pub(crate) use events::{UserOperationEventProviderV0_6, UserOperationEventProviderV0_7};
mod server;

use alloy_primitives::{Address, B256, U64};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use rundler_provider::StateOverride;

use crate::types::{
    RpcGasEstimate, RpcUserOperation, RpcUserOperationByHash, RpcUserOperationOptionalGas,
    RpcUserOperationPermissions, RpcUserOperationReceipt,
};

/// Eth API
#[rpc(client, server, namespace = "eth")]
#[cfg_attr(test, automock)]
pub trait EthApi {
    /// Sends a user operation to the pool.
    #[method(name = "sendUserOperation")]
    async fn send_user_operation(
        &self,
        op: RpcUserOperation,
        entry_point: Address,
        permissions: Option<RpcUserOperationPermissions>,
    ) -> RpcResult<B256>;

    /// Estimates the gas fields for a user operation.
    #[method(name = "estimateUserOperationGas")]
    async fn estimate_user_operation_gas(
        &self,
        op: RpcUserOperationOptionalGas,
        entry_point: Address,
        state_override: Option<StateOverride>,
    ) -> RpcResult<RpcGasEstimate>;

    /// Returns the user operation with the given hash.
    #[method(name = "getUserOperationByHash")]
    async fn get_user_operation_by_hash(
        &self,
        hash: B256,
    ) -> RpcResult<Option<RpcUserOperationByHash>>;

    /// Returns the user operation receipt with the given hash.
    #[method(name = "getUserOperationReceipt")]
    async fn get_user_operation_receipt(
        &self,
        hash: B256,
    ) -> RpcResult<Option<RpcUserOperationReceipt>>;

    /// Returns the supported entry points addresses
    #[method(name = "supportedEntryPoints")]
    async fn supported_entry_points(&self) -> RpcResult<Vec<String>>;

    /// Returns the chain ID
    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<U64>;
}

/// Settings for the `eth_` API
#[derive(Copy, Clone, Debug)]
pub struct EthApiSettings {
    /// The number of blocks to look back for user operation events
    pub user_operation_event_block_distance: Option<u64>,
    /// The number of blocks to look back for user operation events during a fallback
    pub user_operation_event_block_distance_fallback: Option<u64>,
    /// If external permissions are allowed
    pub permissions_enabled: bool,
}
