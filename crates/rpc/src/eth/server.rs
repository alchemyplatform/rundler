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

use alloy_primitives::{Address, B256, U64};
use jsonrpsee::core::RpcResult;
use rundler_provider::StateOverride;
use rundler_types::{chain::IntoWithSpec, pool::Pool, BlockTag, UserOperationPermissions};
use tracing::instrument;

use super::{api::EthApi, EthApiServer};
use crate::{
    types::{
        RpcGasEstimate, RpcUserOperation, RpcUserOperationByHash, RpcUserOperationOptionalGas,
        RpcUserOperationPermissions, RpcUserOperationReceipt,
    },
    utils,
};

#[async_trait::async_trait]
impl<P> EthApiServer for EthApi<P>
where
    P: Pool + 'static,
{
    #[instrument(skip_all, fields(rpc_method = "eth_sendUserOperation"))]
    async fn send_user_operation(
        &self,
        op: RpcUserOperation,
        entry_point: Address,
        permissions: Option<RpcUserOperationPermissions>,
    ) -> RpcResult<B256> {
        // if permissions are not enabled, default them
        let mut permissions = if self.permissions_enabled {
            permissions
                .map(|p| p.into_with_spec(&self.chain_spec))
                .unwrap_or_default()
        } else {
            UserOperationPermissions::default()
        };

        // cap percentages at 100
        permissions.underpriced_accept_pct = permissions.underpriced_accept_pct.map(|p| p.min(100));
        permissions.underpriced_bundle_pct = permissions.underpriced_bundle_pct.map(|p| p.min(100));

        utils::safe_call_rpc_handler(
            "eth_sendUserOperation",
            EthApi::send_user_operation(
                self,
                op.into_with_spec(&self.chain_spec),
                entry_point,
                permissions,
            ),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "eth_estimateUserOperationGas"))]
    async fn estimate_user_operation_gas(
        &self,
        op: RpcUserOperationOptionalGas,
        entry_point: Address,
        state_override: Option<StateOverride>,
    ) -> RpcResult<RpcGasEstimate> {
        utils::safe_call_rpc_handler(
            "eth_estimateUserOperationGas",
            EthApi::estimate_user_operation_gas(self, op.into(), entry_point, state_override),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "eth_getUserOperationByHash"))]
    async fn get_user_operation_by_hash(
        &self,
        hash: B256,
    ) -> RpcResult<Option<RpcUserOperationByHash>> {
        utils::safe_call_rpc_handler(
            "eth_getUserOperationByHash",
            EthApi::get_user_operation_by_hash(self, hash),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "eth_getUserOperationReceipt"))]
    async fn get_user_operation_receipt(
        &self,
        hash: B256,
        tag: Option<BlockTag>,
    ) -> RpcResult<Option<RpcUserOperationReceipt>> {
        utils::safe_call_rpc_handler(
            "eth_getUserOperationReceipt",
            EthApi::get_user_operation_receipt(self, hash, tag),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "eth_supportedEntryPoints"))]
    async fn supported_entry_points(&self) -> RpcResult<Vec<String>> {
        utils::safe_call_rpc_handler(
            "eth_supportedEntryPoints",
            EthApi::supported_entry_points(self),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "eth_chainId"))]
    async fn chain_id(&self) -> RpcResult<U64> {
        utils::safe_call_rpc_handler("eth_chainId", EthApi::chain_id(self)).await
    }
}
