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
use async_trait::async_trait;
use jsonrpsee::{Extensions, core::RpcResult, proc_macros::rpc};
use rundler_types::{
    GasFees, UserOperation, UserOperationId, UserOperationVariant, chain::ChainSpec, pool::Pool,
};
use tracing::instrument;

use crate::{
    chain_resolver::ChainResolver,
    eth::{EthResult, EthRpcError},
    types::{
        RpcMinedUserOperation, RpcSuggestedGasFees, RpcUserOperation, RpcUserOperationGasPrice,
        RpcUserOperationReceipt, RpcUserOperationStatus, UOStatusEnum, UserOperationStatusEnum,
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
    #[method(name = "maxPriorityFeePerGas", with_extensions)]
    async fn max_priority_fee_per_gas(&self) -> RpcResult<U128>;

    /// Drops a user operation from the local mempool.
    #[method(name = "dropLocalUserOperation", with_extensions)]
    async fn drop_local_user_operation(
        &self,
        uo: RpcUserOperation,
        entry_point: Address,
    ) -> RpcResult<Option<B256>>;

    /// Gets information about a mined user operation
    #[method(name = "getMinedUserOperation", with_extensions)]
    async fn get_mined_user_operation(
        &self,
        uo_hash: B256,
        tx_hash: B256,
        entry_point: Address,
    ) -> RpcResult<Option<RpcMinedUserOperation>>;

    /// Gets the status of a user operation by user operation hash
    #[method(name = "getUserOperationStatus", with_extensions)]
    async fn get_user_operation_status(&self, uo_hash: B256) -> RpcResult<RpcUserOperationStatus>;

    /// Gets the required fees for a sender nonce
    #[method(name = "getPendingUserOperationBySenderNonce", with_extensions)]
    async fn get_pending_user_operation_by_sender_nonce(
        &self,
        sender: Address,
        nonce: U256,
    ) -> RpcResult<Option<RpcUserOperation>>;

    /// Returns suggested gas prices for user operations
    #[method(name = "getUserOperationGasPrice", with_extensions)]
    async fn get_user_operation_gas_price(&self) -> RpcResult<RpcUserOperationGasPrice>;
}

pub(crate) struct RundlerApi<R> {
    resolver: R,
    settings: RundlerApiSettings,
}

#[async_trait]
impl<R> RundlerApiServer for RundlerApi<R>
where
    R: ChainResolver,
{
    #[instrument(skip_all, fields(rpc_method = "rundler_maxPriorityFeePerGas"))]
    async fn max_priority_fee_per_gas(&self, ext: &Extensions) -> RpcResult<U128> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "rundler_maxPriorityFeePerGas",
            Self::max_priority_fee_per_gas_inner(chain.pool),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "rundler_dropLocalUserOperation"))]
    async fn drop_local_user_operation(
        &self,
        ext: &Extensions,
        user_op: RpcUserOperation,
        entry_point: Address,
    ) -> RpcResult<Option<B256>> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "rundler_dropLocalUserOperation",
            Self::drop_local_user_operation_inner(
                chain.chain_spec,
                chain.pool,
                user_op,
                entry_point,
            ),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "rundler_getMinedUserOperation"))]
    async fn get_mined_user_operation(
        &self,
        ext: &Extensions,
        uo_hash: B256,
        tx_hash: B256,
        entry_point: Address,
    ) -> RpcResult<Option<RpcMinedUserOperation>> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "rundler_getMinedUserOperation",
            Self::get_mined_user_operation_inner(chain.pool, uo_hash, tx_hash, entry_point),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "rundler_getUserOperationStatus"))]
    async fn get_user_operation_status(
        &self,
        ext: &Extensions,
        uo_hash: B256,
    ) -> RpcResult<RpcUserOperationStatus> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "rundler_getUserOperationStatus",
            Self::get_user_operation_status_inner(chain.chain_spec, chain.pool, uo_hash),
        )
        .await
    }

    #[instrument(
        skip_all,
        fields(rpc_method = "rundler_getPendingUserOperationBySenderNonce")
    )]
    async fn get_pending_user_operation_by_sender_nonce(
        &self,
        ext: &Extensions,
        sender: Address,
        nonce: U256,
    ) -> RpcResult<Option<RpcUserOperation>> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "rundler_getPendingUserOperationBySenderNonce",
            Self::get_pending_user_operation_by_sender_nonce_inner(chain.pool, sender, nonce),
        )
        .await
    }

    #[instrument(skip_all, fields(rpc_method = "rundler_getUserOperationGasPrice"))]
    async fn get_user_operation_gas_price(
        &self,
        ext: &Extensions,
    ) -> RpcResult<RpcUserOperationGasPrice> {
        let chain = self.resolver.resolve(ext)?;
        let settings = self.settings;
        utils::safe_call_rpc_handler(
            "rundler_getUserOperationGasPrice",
            Self::get_user_operation_gas_price_inner(chain.pool, settings),
        )
        .await
    }
}

impl<R> RundlerApi<R> {
    pub(crate) fn new(resolver: R, settings: RundlerApiSettings) -> Self {
        Self { resolver, settings }
    }

    #[instrument(skip_all)]
    async fn max_priority_fee_per_gas_inner(pool: &dyn Pool) -> EthResult<U128> {
        let fee = pool
            .get_max_priority_fee_per_gas()
            .await
            .map_err(EthRpcError::from)?;
        Ok(U128::from(fee))
    }

    async fn drop_local_user_operation_inner(
        chain_spec: &ChainSpec,
        pool: &dyn Pool,
        user_op: RpcUserOperation,
        entry_point: Address,
    ) -> EthResult<Option<B256>> {
        let Some(ep_version) = chain_spec.entry_point_version(entry_point) else {
            Err(EthRpcError::InvalidParams(format!(
                "Unsupported entry point: {:?}",
                entry_point
            )))?
        };

        let uo: UserOperationVariant = user_op.try_into_rundler_type(chain_spec, ep_version)?;
        let id = uo.id();

        if uo.pre_verification_gas() != 0
            || uo.call_gas_limit() != 0
            || uo.call_data().is_empty()
            || uo.max_fee_per_gas() != 0
        {
            Err(EthRpcError::InvalidParams("Invalid user operation for drop: preVerificationGas, callGasLimit, callData, and maxFeePerGas must be zero".to_string()))?;
        }

        let valid = pool
            .check_signature(entry_point, uo)
            .await
            .map_err(EthRpcError::from)?;
        if !valid {
            Err(EthRpcError::InvalidParams(
                "Invalid user operation for drop: invalid signature".to_string(),
            ))?;
        }

        let ret = pool.remove_op_by_id(entry_point, id).await.map_err(|e| {
            tracing::info!("Error dropping user operation: {}", e);
            EthRpcError::from(e)
        })?;

        Ok(ret)
    }

    async fn get_mined_user_operation_inner(
        pool: &dyn Pool,
        uo_hash: B256,
        tx_hash: B256,
        entry_point: Address,
    ) -> EthResult<Option<RpcMinedUserOperation>> {
        let result = pool
            .get_mined_user_operation(uo_hash, tx_hash, entry_point)
            .await
            .map_err(EthRpcError::from)?;

        match result {
            Some((mined, receipt_data)) => {
                let receipt = Self::receipt_data_to_rpc(receipt_data)?;
                // Clear outer transaction logs to avoid extra data
                let mut receipt = receipt;
                receipt.receipt.inner.inner.inner.receipt.logs.clear();

                Ok(Some(RpcMinedUserOperation {
                    user_operation: mined.user_operation.into(),
                    receipt,
                }))
            }
            None => Ok(None),
        }
    }

    async fn get_user_operation_status_inner(
        chain_spec: &ChainSpec,
        pool: &dyn Pool,
        uo_hash: B256,
    ) -> EthResult<RpcUserOperationStatus> {
        // Fetch pool status first to get preconf info for the mined query
        let op_status = pool
            .get_op_status(uo_hash)
            .await
            .map_err(EthRpcError::from)?;

        let preconf_transaction: Option<B256> = if chain_spec.flashblocks_enabled {
            op_status
                .as_ref()
                .and_then(|s| s.preconf_info.as_ref())
                .map(|info| info.tx_hash)
        } else {
            None
        };

        // Check receipt
        let receipt_data = pool
            .get_user_operation_receipt(uo_hash, preconf_transaction)
            .await
            .map_err(EthRpcError::from)?;

        if let Some(data) = receipt_data {
            let receipt = Self::receipt_data_to_rpc(data)?;
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

            return Ok(rpc_status);
        }

        // If found in pool, return extended status
        if let Some(pool_status) = op_status {
            return Ok(pool_status.into());
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

    async fn get_pending_user_operation_by_sender_nonce_inner(
        pool: &dyn Pool,
        sender: Address,
        nonce: U256,
    ) -> EthResult<Option<RpcUserOperation>> {
        let uo = pool
            .get_op_by_id(UserOperationId { sender, nonce })
            .await
            .map_err(EthRpcError::from)?;

        Ok(uo.map(|uo| uo.uo.into()))
    }

    async fn get_user_operation_gas_price_inner(
        pool: &dyn Pool,
        settings: RundlerApiSettings,
    ) -> EthResult<RpcUserOperationGasPrice> {
        let fee_estimate = pool.get_fee_estimate().await.map_err(EthRpcError::from)?;

        let bundle_fees = GasFees {
            max_fee_per_gas: fee_estimate
                .required_base_fee
                .saturating_add(fee_estimate.required_priority_fee),
            max_priority_fee_per_gas: fee_estimate.required_priority_fee,
        };

        let op_fees = pool
            .get_required_op_fees(bundle_fees)
            .await
            .map_err(EthRpcError::from)?;
        let priority_fee = op_fees.max_priority_fee_per_gas;

        // Calculate suggested priority fee with configured buffer
        let priority_multiplier =
            100u128.saturating_add(u128::from(settings.priority_fee_buffer_percent));
        let suggested_priority_fee = priority_fee
            .saturating_mul(priority_multiplier)
            .saturating_div(100);

        // Calculate suggested max fee with configured base fee buffer
        let base_fee_multiplier =
            100u128.saturating_add(u128::from(settings.base_fee_buffer_percent));
        let suggested_max_fee = fee_estimate
            .required_base_fee
            .saturating_mul(base_fee_multiplier)
            .saturating_div(100)
            .saturating_add(suggested_priority_fee);

        Ok(RpcUserOperationGasPrice {
            priority_fee: U128::from(priority_fee),
            base_fee: U128::from(fee_estimate.base_fee),
            block_number: U64::from(fee_estimate.block_number),
            suggested: RpcSuggestedGasFees {
                max_priority_fee_per_gas: U128::from(suggested_priority_fee),
                max_fee_per_gas: U128::from(suggested_max_fee),
            },
        })
    }

    fn receipt_data_to_rpc(
        data: rundler_types::pool::UserOperationReceiptData,
    ) -> EthResult<RpcUserOperationReceipt> {
        let logs: Vec<rundler_provider::Log> =
            serde_json::from_slice(&data.logs_json).map_err(|e| {
                EthRpcError::Internal(anyhow::anyhow!("Failed to deserialize logs: {e}"))
            })?;

        let receipt: rundler_provider::TransactionReceipt =
            serde_json::from_slice(&data.receipt_json).map_err(|e| {
                EthRpcError::Internal(anyhow::anyhow!("Failed to deserialize receipt: {e}"))
            })?;

        Ok(RpcUserOperationReceipt {
            user_op_hash: data.user_op_hash,
            entry_point: data.entry_point.into(),
            sender: data.sender.into(),
            nonce: data.nonce,
            paymaster: data.paymaster.into(),
            actual_gas_cost: data.actual_gas_cost,
            actual_gas_used: data.actual_gas_used,
            success: data.success,
            reason: data.reason,
            logs,
            receipt,
            status: if data.is_preconfirmed {
                UOStatusEnum::Preconfirmed
            } else {
                UOStatusEnum::Mined
            },
        })
    }
}
