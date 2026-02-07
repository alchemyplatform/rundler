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

use alloy_primitives::{Address, B256, U64, U128, U256};
use anyhow::Context;
use async_trait::async_trait;
use futures_util::future;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use rundler_provider::{EvmProvider, FeeEstimator};
use rundler_types::{
    GasFees, UserOperation, UserOperationId, UserOperationVariant, chain::ChainSpec, pool::Pool,
};
use tracing::instrument;

use crate::{
    eth::{EntryPointRouter, EthResult, EthRpcError},
    types::{
        RpcMinedUserOperation, RpcSuggestedGasFees, RpcUserOperation, RpcUserOperationGasPrice,
        RpcUserOperationStatus, UOStatusEnum, UserOperationStatusEnum,
    },
    utils::{self, TryIntoRundlerType},
};

/// Settings for the rundler API
#[derive(Clone, Copy, Debug)]
pub struct RundlerApiSettings {
    /// Priority fee buffer percent for gas price suggestions (e.g., 30 for 30% above current)
    pub priority_fee_buffer_percent: u64,
    /// Base fee buffer percent for gas price suggestions (e.g., 50 for 1.5x base fee)
    pub base_fee_buffer_percent: u64,
}

impl Default for RundlerApiSettings {
    fn default() -> Self {
        Self {
            priority_fee_buffer_percent: 30,
            base_fee_buffer_percent: 50,
        }
    }
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

    /// Gets the status of a user operation by user operation hash
    #[method(name = "getUserOperationStatus")]
    async fn get_user_operation_status(&self, uo_hash: B256) -> RpcResult<RpcUserOperationStatus>;

    /// Gets the required fees for a sender nonce
    #[method(name = "getPendingUserOperationBySenderNonce")]
    async fn get_pending_user_operation_by_sender_nonce(
        &self,
        sender: Address,
        nonce: U256,
    ) -> RpcResult<Option<RpcUserOperation>>;

    /// Returns suggested gas prices for user operations
    #[method(name = "getUserOperationGasPrice")]
    async fn get_user_operation_gas_price(&self) -> RpcResult<RpcUserOperationGasPrice>;
}

pub(crate) struct RundlerApi<P, F, E> {
    chain_spec: ChainSpec,
    fee_estimator: F,
    pool_server: P,
    entry_point_router: EntryPointRouter,
    evm_provider: E,
    settings: RundlerApiSettings,
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

    #[instrument(skip_all, fields(rpc_method = "rundler_getUserOperationStatus"))]
    async fn get_user_operation_status(&self, uo_hash: B256) -> RpcResult<RpcUserOperationStatus> {
        utils::safe_call_rpc_handler(
            "rundler_getUserOperationStatus",
            RundlerApi::get_user_operation_status(self, uo_hash),
        )
        .await
    }

    #[instrument(
        skip_all,
        fields(rpc_method = "rundler_getPendingUserOperationBySenderNonce")
    )]
    async fn get_pending_user_operation_by_sender_nonce(
        &self,
        sender: Address,
        nonce: U256,
    ) -> RpcResult<Option<RpcUserOperation>> {
        utils::safe_call_rpc_handler(
            "rundler_getPendingUserOperationBySenderNonce",
            RundlerApi::get_pending_user_operation_by_sender_nonce(self, sender, nonce),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "rundler_getUserOperationGasPrice"))]
    async fn get_user_operation_gas_price(&self) -> RpcResult<RpcUserOperationGasPrice> {
        utils::safe_call_rpc_handler(
            "rundler_getUserOperationGasPrice",
            RundlerApi::get_user_operation_gas_price(self),
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
        settings: RundlerApiSettings,
    ) -> Self {
        Self {
            chain_spec: chain_spec.clone(),
            entry_point_router,
            pool_server,
            fee_estimator,
            evm_provider,
            settings,
        }
    }
    #[instrument(skip_all)]
    async fn max_priority_fee_per_gas(&self) -> EthResult<U128> {
        let estimate = self
            .fee_estimator
            .latest_fee_estimate()
            .await
            .context("should get required fees")?;
        let bundle_fees = GasFees {
            max_fee_per_gas: estimate
                .required_base_fee
                .saturating_add(estimate.required_priority_fee),
            max_priority_fee_per_gas: estimate.required_priority_fee,
        };
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
        let Some(ep_version) = self.chain_spec.entry_point_version(entry_point) else {
            Err(EthRpcError::InvalidParams(format!(
                "Unsupported entry point: {:?}",
                entry_point
            )))?
        };

        let uo: UserOperationVariant =
            user_op.try_into_rundler_type(&self.chain_spec, ep_version)?;
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

        let (uo_result, receipt_result) = future::join(uo_fut, receipt_fut).await;
        let uo = uo_result.map_err(EthRpcError::from)?;
        let receipt = receipt_result.map_err(EthRpcError::from)?;

        match (uo, receipt) {
            (Some(uo), Some(mut receipt)) => {
                // clear out the outer transaction logs from the receipt to avoid sending
                // extra data in the response. OOF - this type is a mess.
                receipt.receipt.inner.inner.inner.receipt.logs.clear();
                Ok(Some(RpcMinedUserOperation {
                    user_operation: uo.user_operation,
                    receipt,
                }))
            }
            _ => Ok(None),
        }
    }

    async fn get_user_operation_status(&self, uo_hash: B256) -> EthResult<RpcUserOperationStatus> {
        // Fetch pool status first to get preconf info for the mined query
        let op_status = self
            .pool_server
            .get_op_status(uo_hash)
            .await
            .map_err(EthRpcError::from)?;

        let preconf_transaction: Option<B256> = if self.chain_spec.flashblocks_enabled {
            op_status
                .as_ref()
                .and_then(|s| s.preconf_info.as_ref())
                .map(|info| info.tx_hash)
        } else {
            None
        };

        // Fetch mined UO + receipt from all entry points
        let mined_futs = self.entry_point_router.entry_points().map(|ep| {
            self.entry_point_router
                .get_mined_and_receipt(ep, uo_hash, preconf_transaction)
        });

        // Track if we failed to retrieve receipt for a preconfirmed UO
        let mut preconf_receipt_failed = false;

        // If this fails and the UO is preconfirmed, treat it as pending
        let mined_results = match future::try_join_all(mined_futs).await {
            Ok(results) => results,
            Err(e) => {
                // If UO is preconfirmed but receipt retrieval failed, log and treat as pending
                if preconf_transaction.is_some() {
                    tracing::warn!(
                        "Failed to retrieve receipt for preconfirmed UO {}: {}. Treating as pending.",
                        uo_hash,
                        e
                    );
                    preconf_receipt_failed = true;
                    // Fall through to return pool status as pending
                    vec![]
                } else {
                    // For non-preconfirmed UOs, propagate the error
                    return Err(EthRpcError::from(e));
                }
            }
        };

        // Check for mined/preconfirmed receipt first (includes user operation)
        if let Some((uo_by_hash, receipt)) = mined_results.into_iter().find_map(|r| r) {
            let status = match receipt.status {
                UOStatusEnum::Mined => UserOperationStatusEnum::Mined,
                UOStatusEnum::Preconfirmed => UserOperationStatusEnum::Preconfirmed,
            };

            // For preconfirmed, include pool status since op is still in pool
            let mut rpc_status: RpcUserOperationStatus = op_status
                .map(RpcUserOperationStatus::from)
                .unwrap_or_default();

            rpc_status.status = status;
            rpc_status.receipt = Some(receipt);
            rpc_status.user_operation = Some(uo_by_hash.user_operation);

            return Ok(rpc_status);
        }

        // If found in pool, return extended status
        if let Some(pool_status) = op_status {
            let mut rpc_status: RpcUserOperationStatus = pool_status.into();

            // If we failed to get receipt for a preconfirmed UO, clear preconf info
            if preconf_receipt_failed {
                rpc_status.pending_bundle = None;
            }

            return Ok(rpc_status);
        }

        Ok(RpcUserOperationStatus {
            status: UserOperationStatusEnum::Unknown,
            receipt: None,
            user_operation: None,
            added_at_block: None,
            valid_until: None,
            valid_after: None,
            pending_bundle: None,
        })
    }

    async fn get_pending_user_operation_by_sender_nonce(
        &self,
        sender: Address,
        nonce: U256,
    ) -> EthResult<Option<RpcUserOperation>> {
        let uo = self
            .pool_server
            .get_op_by_id(UserOperationId { sender, nonce })
            .await
            .map_err(EthRpcError::from)?;

        Ok(uo.map(|uo| uo.uo.into()))
    }

    #[instrument(skip_all)]
    async fn get_user_operation_gas_price(&self) -> EthResult<RpcUserOperationGasPrice> {
        // Get base fee, priority fee (with bundler overhead), and block number
        let estimate = self
            .fee_estimator
            .latest_fee_estimate()
            .await
            .context("should get fee estimate")?;
        let bundle_fees = GasFees {
            max_fee_per_gas: estimate
                .required_base_fee
                .saturating_add(estimate.required_priority_fee),
            max_priority_fee_per_gas: estimate.required_priority_fee,
        };

        // Convert to user operation fees (current required)
        let op_fees = self.fee_estimator.required_op_fees(bundle_fees);
        let priority_fee = op_fees.max_priority_fee_per_gas;

        // Calculate suggested priority fee with configured buffer
        let priority_multiplier =
            100u128.saturating_add(u128::from(self.settings.priority_fee_buffer_percent));
        let suggested_priority_fee = priority_fee
            .saturating_mul(priority_multiplier)
            .saturating_div(100);

        // Calculate suggested max fee with configured base fee buffer
        let base_fee_multiplier =
            100u128.saturating_add(u128::from(self.settings.base_fee_buffer_percent));
        let suggested_max_fee = estimate
            .required_base_fee
            .saturating_mul(base_fee_multiplier)
            .saturating_div(100)
            .saturating_add(suggested_priority_fee);

        Ok(RpcUserOperationGasPrice {
            priority_fee: U128::from(priority_fee),
            base_fee: U128::from(estimate.base_fee),
            block_number: U64::from(estimate.block_number),
            suggested: RpcSuggestedGasFees {
                max_priority_fee_per_gas: U128::from(suggested_priority_fee),
                max_fee_per_gas: U128::from(suggested_max_fee),
            },
        })
    }
}
