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
use jsonrpsee::{Extensions, core::RpcResult};
use rundler_provider::StateOverride;
use rundler_types::{BlockTag, UserOperationPermissions};
use tracing::instrument;

use super::{EthApiServer, api::EthApi};
use crate::{
    chain_resolver::ChainResolver,
    eth::EthRpcError,
    types::{
        RpcGasEstimate, RpcUserOperation, RpcUserOperationByHash, RpcUserOperationOptionalGas,
        RpcUserOperationPermissions, RpcUserOperationReceipt,
    },
    utils::{self, IntoRundlerType, TryIntoRundlerType},
};

#[async_trait::async_trait]
impl<R> EthApiServer for EthApi<R>
where
    R: ChainResolver,
{
    #[instrument(skip_all, fields(rpc_method = "eth_sendUserOperation"))]
    async fn send_user_operation(
        &self,
        ext: &Extensions,
        op: RpcUserOperation,
        entry_point: Address,
        permissions: Option<RpcUserOperationPermissions>,
    ) -> RpcResult<B256> {
        let chain = self.resolve(ext)?;

        let Some(ep_version) = chain.chain_spec.entry_point_version(entry_point) else {
            Err(EthRpcError::InvalidParams(format!(
                "Unsupported entry point: {:?}",
                entry_point
            )))?
        };

        // if permissions are not enabled, default them
        let mut permissions = if self.permissions_enabled {
            permissions
                .map(|p| p.into_rundler_type(chain.chain_spec, ep_version))
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
                chain.chain_spec,
                chain.pool,
                chain.entry_points,
                op.try_into_rundler_type(chain.chain_spec, ep_version)?,
                entry_point,
                permissions,
            ),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "eth_estimateUserOperationGas"))]
    async fn estimate_user_operation_gas(
        &self,
        ext: &Extensions,
        op: RpcUserOperationOptionalGas,
        entry_point: Address,
        state_override: Option<StateOverride>,
    ) -> RpcResult<RpcGasEstimate> {
        let chain = self.resolve(ext)?;

        let Some(ep_version) = chain.chain_spec.entry_point_version(entry_point) else {
            Err(EthRpcError::InvalidParams(format!(
                "Unsupported entry point: {:?}",
                entry_point
            )))?
        };

        utils::safe_call_rpc_handler(
            "eth_estimateUserOperationGas",
            EthApi::estimate_user_operation_gas(
                self,
                chain.chain_spec,
                chain.pool,
                op.into_rundler_type(chain.chain_spec, ep_version),
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
    ) -> RpcResult<Option<RpcUserOperationByHash>> {
        let chain = self.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "eth_getUserOperationByHash",
            EthApi::<R>::get_user_operation_by_hash(chain.pool, hash),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "eth_getUserOperationReceipt"))]
    async fn get_user_operation_receipt(
        &self,
        ext: &Extensions,
        hash: B256,
        tag: Option<BlockTag>,
    ) -> RpcResult<Option<RpcUserOperationReceipt>> {
        let chain = self.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "eth_getUserOperationReceipt",
            EthApi::<R>::get_user_operation_receipt(chain.chain_spec, chain.pool, hash, tag),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "eth_supportedEntryPoints"))]
    async fn supported_entry_points(&self, ext: &Extensions) -> RpcResult<Vec<String>> {
        let chain = self.resolve(ext)?;
        utils::safe_call_rpc_handler("eth_supportedEntryPoints", async {
            EthApi::<R>::supported_entry_points(chain.chain_spec, chain.entry_points)
        })
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "eth_chainId"))]
    async fn chain_id(&self, ext: &Extensions) -> RpcResult<U64> {
        let chain = self.resolve(ext)?;
        utils::safe_call_rpc_handler("eth_chainId", async {
            EthApi::<R>::chain_id(chain.chain_spec)
        })
        .await
    }
}
