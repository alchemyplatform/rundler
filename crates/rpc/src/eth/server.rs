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
use http::Extensions;
use jsonrpsee::core::RpcResult;
use rundler_provider::{EvmProvider, StateOverride};
use rundler_types::{UserOperationPermissions, pool::Pool};
use tracing::instrument;

use super::{EthApiServer, api::EthApi};
use crate::{
    eth::{EthRpcError, events::EventBlockOptions},
    types::{
        MaxBlockRange, RpcBlockOption, RpcBlockOptionOrTag, RpcGasEstimate, RpcPermissions,
        RpcUserOperation, RpcUserOperationByHash, RpcUserOperationOptionalGas,
        RpcUserOperationReceipt,
    },
    utils::{self, IntoRundlerType, TryIntoRundlerType},
};

#[async_trait::async_trait]
impl<P, E> EthApiServer for EthApi<P, E>
where
    P: Pool + 'static,
    E: EvmProvider + 'static,
{
    #[instrument(skip_all, fields(rpc_method = "eth_sendUserOperation"))]
    async fn send_user_operation(
        &self,
        ext: &Extensions,
        op: RpcUserOperation,
        entry_point: Address,
        permissions: Option<RpcPermissions>,
    ) -> RpcResult<B256> {
        let Some(ep_version) = self.chain_spec.entry_point_version(entry_point) else {
            Err(EthRpcError::InvalidParams(format!(
                "Unsupported entry point: {:?}",
                entry_point
            )))?
        };

        // Header-supplied permissions (parsed into the request extensions by the transport
        // middleware) take precedence over the legacy positional parameter.
        let rpc_permissions = ext.get::<RpcPermissions>().cloned().or(permissions);

        // if permissions are not enabled, default them
        let mut permissions = if self.permissions_enabled {
            rpc_permissions
                .map(|p| p.into_rundler_type(&self.chain_spec, ep_version))
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
                op.try_into_rundler_type(&self.chain_spec, ep_version)?,
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
        let Some(ep_version) = self.chain_spec.entry_point_version(entry_point) else {
            Err(EthRpcError::InvalidParams(format!(
                "Unsupported entry point: {:?}",
                entry_point
            )))?
        };

        utils::safe_call_rpc_handler(
            "eth_estimateUserOperationGas",
            EthApi::estimate_user_operation_gas(
                self,
                op.into_rundler_type(&self.chain_spec, ep_version),
                entry_point,
                state_override,
            ),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "eth_getUserOperationByHash"))]
    async fn get_user_operation_by_hash(
        &self,
        ext: &Extensions,
        hash: B256,
        block_option: Option<RpcBlockOption>,
    ) -> RpcResult<Option<RpcUserOperationByHash>> {
        let block_options = EventBlockOptions {
            block_option: block_option.map(|o| o.into()),
            max_block_range: ext.get::<MaxBlockRange>().map(|r| r.0),
        };
        utils::safe_call_rpc_handler(
            "eth_getUserOperationByHash",
            EthApi::get_user_operation_by_hash(self, hash, block_options),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "eth_getUserOperationReceipt"))]
    async fn get_user_operation_receipt(
        &self,
        ext: &Extensions,
        hash: B256,
        block_option_or_tag: Option<RpcBlockOptionOrTag>,
    ) -> RpcResult<Option<RpcUserOperationReceipt>> {
        let (tag, block_option) = match block_option_or_tag {
            None => (None, None),
            Some(RpcBlockOptionOrTag::BlockTag(t)) => (Some(t), None),
            Some(RpcBlockOptionOrTag::BlockOption(bo)) => (None, Some(bo.into())),
        };
        let block_options = EventBlockOptions {
            block_option,
            max_block_range: ext.get::<MaxBlockRange>().map(|r| r.0),
        };

        utils::safe_call_rpc_handler(
            "eth_getUserOperationReceipt",
            EthApi::get_user_operation_receipt(self, hash, tag, block_options),
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
