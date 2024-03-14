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

use ethers::types::{spoof, Address, H256, U64};
use jsonrpsee::core::RpcResult;
use rundler_types::pool::Pool;

use super::{api::EthApi, EthApiServer};
use crate::types::{
    RpcGasEstimate, RpcUserOperation, RpcUserOperationByHash, RpcUserOperationOptionalGas,
    RpcUserOperationReceipt,
};

#[async_trait::async_trait]
impl<P> EthApiServer for EthApi<P>
where
    P: Pool,
{
    async fn send_user_operation(
        &self,
        op: RpcUserOperation,
        entry_point: Address,
    ) -> RpcResult<H256> {
        Ok(EthApi::send_user_operation(self, op.into(), entry_point).await?)
    }

    async fn estimate_user_operation_gas(
        &self,
        op: RpcUserOperationOptionalGas,
        entry_point: Address,
        state_override: Option<spoof::State>,
    ) -> RpcResult<RpcGasEstimate> {
        Ok(
            EthApi::estimate_user_operation_gas(self, op.into(), entry_point, state_override)
                .await?,
        )
    }

    async fn get_user_operation_by_hash(
        &self,
        hash: H256,
    ) -> RpcResult<Option<RpcUserOperationByHash>> {
        Ok(EthApi::get_user_operation_by_hash(self, hash).await?)
    }

    async fn get_user_operation_receipt(
        &self,
        hash: H256,
    ) -> RpcResult<Option<RpcUserOperationReceipt>> {
        Ok(EthApi::get_user_operation_receipt(self, hash).await?)
    }

    async fn supported_entry_points(&self) -> RpcResult<Vec<String>> {
        Ok(EthApi::supported_entry_points(self).await?)
    }

    async fn chain_id(&self) -> RpcResult<U64> {
        Ok(EthApi::chain_id(self).await?)
    }
}
