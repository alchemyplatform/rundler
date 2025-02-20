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
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use rundler_sim::{gas, FeeEstimator};
use rundler_types::{chain::ChainSpec, pool::Pool, UserOperation, UserOperationVariant};
use tracing::{info, info_span};

use crate::{
    eth::{EntryPointRouter, EthResult, EthRpcError},
    types::{FromRpc, RpcUserOperation},
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
}

pub(crate) struct RundlerApi<P, F> {
    chain_spec: ChainSpec,
    fee_estimator: F,
    pool_server: P,
    entry_point_router: EntryPointRouter,
}

#[async_trait]
impl<P, F> RundlerApiServer for RundlerApi<P, F>
where
    P: Pool + 'static,
    F: FeeEstimator + 'static,
{
    async fn max_priority_fee_per_gas(&self) -> RpcResult<U128> {
        let span = info_span!("max_priority_fee_per_gas api");
        let x = span.in_scope(|| self);
        utils::safe_call_rpc_handler(
            "rundler_maxPriorityFeePerGas",
            RundlerApi::max_priority_fee_per_gas(x),
        )
        .await
    }

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
}

impl<P, F> RundlerApi<P, F>
where
    P: Pool,
    F: FeeEstimator,
{
    pub(crate) fn new(
        chain_spec: &ChainSpec,
        entry_point_router: EntryPointRouter,
        pool_server: P,
        fee_estimator: F,
    ) -> Self {
        Self {
            chain_spec: chain_spec.clone(),
            entry_point_router,
            pool_server,
            fee_estimator,
        }
    }

    async fn max_priority_fee_per_gas(&self) -> EthResult<U128> {
        let span = info_span!("max_priority_fee_per_gas impl");
        let x = span.in_scope(|| None);
        info!("here is a log");
        let (bundle_fees, _) = self
            .fee_estimator
            .required_bundle_fees(x)
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
            || uo.call_data().len() != 0
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
}
