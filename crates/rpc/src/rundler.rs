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

use alloy_primitives::{Address, B256, U128};
use anyhow::Context;
use async_trait::async_trait;
use futures_util::future;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use rundler_provider::EvmProvider;
use rundler_sim::{gas, FeeEstimator};
use rundler_types::{chain::ChainSpec, pool::Pool, UserOperation, UserOperationVariant};
use tracing::instrument;

use crate::{
    eth::{EntryPointRouter, EthResult, EthRpcError},
    types::{FromRpc, RpcMinedUserOperation, RpcUserOperation},
    utils,
};

/// Settings for the `rundler_` API
#[derive(Copy, Clone, Debug)]
pub struct Settings {
    /// The priority fee mode to use for calculating required user operation priority fee.
    pub priority_fee_mode: gas::PriorityFeeMode,
    /// If using a bundle priority fee, the percentage to add to the network/oracle
    /// provided value as a safety margin for fast inclusion.
    pub bundle_priority_fee_overhead_percent: u32,
}

#[rpc(client, server, namespace = "rundler")]
pub trait RundlerApi {
    /// Returns the maximum priority fee per gas required by Rundler
    #[method(name = "maxPriorityFeePerGas")]
    async fn max_priority_fee_per_gas(&self) -> RpcResult<U128>;

    /// Drops a user operation from the local mempool.
    ///
    /// Requirements:
    ///   - The user operation must contain a sender/nonce pair this is present in the local mempool.
    ///   - The user operation must pass entrypoint.simulateValidation. I.e. it must have a valid signature and verificationGasLimit
    ///   - The user operation must have zero values for: preVerificationGas, callGasLimit, calldata, and maxFeePerGas
    ///
    /// Returns none if no user operation was found, otherwise returns the hash of the removed user operation.
    #[method(name = "dropLocalUserOperation")]
    async fn drop_local_user_operation(
        &self,
        uo: RpcUserOperation,
        entry_point: Address,
    ) -> RpcResult<Option<B256>>;

    /// Gets information about a mined user operation by user operation hash, transaction hash, and entrypoint address
    #[method(name = "getMinedUserOperation")]
    async fn get_mined_user_operation(
        &self,
        uo_hash: B256,
        tx_hash: B256,
        entry_point: Address,
    ) -> RpcResult<Option<RpcMinedUserOperation>>;
}

pub(crate) struct RundlerApi<P, F, E> {
    chain_spec: ChainSpec,
    fee_estimator: F,
    pool_server: P,
    entry_point_router: EntryPointRouter,
    evm_provider: E,
}

#[async_trait]
impl<P, F, E> RundlerApiServer for RundlerApi<P, F, E>
where
    P: Pool + 'static,
    F: FeeEstimator + 'static,
    E: EvmProvider + 'static,
{
    #[instrument(skip_all, fields(rpc_method = "rundler_maxPriorityFeePerGas"))]
    async fn max_priority_fee_per_gas(&self) -> RpcResult<U128> {
        utils::safe_call_rpc_handler(
            "rundler_maxPriorityFeePerGas",
            RundlerApi::max_priority_fee_per_gas(self),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "rundler_dropLocalUserOperation"))]
    async fn drop_local_user_operation(
        &self,
        user_op: RpcUserOperation,
        entry_point: Address,
    ) -> RpcResult<Option<B256>> {
        utils::safe_call_rpc_handler(
            "rundler_dropLocalUserOperation",
            RundlerApi::drop_local_user_operation(self, user_op, entry_point),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "rundler_getMinedUserOperation"))]
    async fn get_mined_user_operation(
        &self,
        uo_hash: B256,
        tx_hash: B256,
        entry_point: Address,
    ) -> RpcResult<Option<RpcMinedUserOperation>> {
        utils::safe_call_rpc_handler(
            "rundler_getMinedUserOperation",
            RundlerApi::get_mined_user_operation(self, uo_hash, tx_hash, entry_point),
        )
        .await
    }
}

impl<P, F, E> RundlerApi<P, F, E>
where
    P: Pool,
    F: FeeEstimator,
    E: EvmProvider,
{
    pub(crate) fn new(
        chain_spec: &ChainSpec,
        entry_point_router: EntryPointRouter,
        pool_server: P,
        fee_estimator: F,
        evm_provider: E,
    ) -> Self {
        Self {
            chain_spec: chain_spec.clone(),
            entry_point_router,
            pool_server,
            fee_estimator,
            evm_provider,
        }
    }
    #[instrument(skip_all)]
    async fn max_priority_fee_per_gas(&self) -> EthResult<U128> {
        let (bundle_fees, _) = self
            .fee_estimator
            .required_bundle_fees(None)
            .await
            .context("should get required fees")?;
        Ok(U128::from(
            self.fee_estimator
                .required_op_fees(bundle_fees)
                .max_priority_fee_per_gas,
        ))
    }

    async fn drop_local_user_operation(
        &self,
        user_op: RpcUserOperation,
        entry_point: Address,
    ) -> EthResult<Option<B256>> {
        let uo = UserOperationVariant::from_rpc(user_op, &self.chain_spec);
        let id = uo.id();

        if uo.pre_verification_gas() != 0
            || uo.call_gas_limit() != 0
            || uo.call_data().is_empty()
            || uo.max_fee_per_gas() != 0
        {
            Err(EthRpcError::InvalidParams("Invalid user operation for drop: preVerificationGas, callGasLimit, callData, and maxFeePerGas must be zero".to_string()))?;
        }

        let valid = self
            .entry_point_router
            .check_signature(&entry_point, uo)
            .await?;
        if !valid {
            Err(EthRpcError::InvalidParams(
                "Invalid user operation for drop: invalid signature".to_string(),
            ))?;
        }

        // remove the op from the pool
        let ret = self
            .pool_server
            .remove_op_by_id(entry_point, id)
            .await
            .map_err(|e| {
                tracing::info!("Error dropping user operation: {}", e);
                EthRpcError::from(e)
            })?;

        Ok(ret)
    }

    async fn get_mined_user_operation(
        &self,
        uo_hash: B256,
        tx_hash: B256,
        entry_point: Address,
    ) -> EthResult<Option<RpcMinedUserOperation>> {
        let tx_receipt = self
            .evm_provider
            .get_transaction_receipt(tx_hash)
            .await
            .context("should have fetched tx receipt")?
            .context("Failed to fetch tx receipt")?;

        let receipt_fut = self.entry_point_router.get_receipt_from_tx_receipt(
            &entry_point,
            uo_hash,
            tx_receipt.clone(),
        );
        let uo_fut =
            self.entry_point_router
                .get_mined_from_tx_receipt(&entry_point, uo_hash, tx_receipt);

        let (uo, receipt) = future::try_join(uo_fut, receipt_fut).await?;

        match (uo, receipt) {
            (Some(uo), Some(mut receipt)) => {
                // clear out the outer transaction logs from the receipt to avoid sending
                // extra data in the response. OOF - this type is a mess.
                receipt.receipt.inner.inner.receipt.logs.clear();
                Ok(Some(RpcMinedUserOperation {
                    user_operation: uo.user_operation,
                    receipt,
                }))
            }
            _ => Ok(None),
        }
    }
}
