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
use jsonrpsee::Extensions;
use rundler_types::{
    BlockTag, EntryPointAbiVersion, UserOperation, UserOperationOptionalGas,
    UserOperationPermissions, UserOperationVariant, chain::ChainSpec, pool::Pool,
};
use rundler_utils::log::LogOnError;
use tracing::{Level, instrument};

use super::error::{EthResult, EthRpcError};
use crate::{
    chain_resolver::ChainResolver,
    types::{
        RpcGasEstimate, RpcGasEstimateV0_6, RpcGasEstimateV0_7, RpcUserOperationByHash,
        RpcUserOperationReceipt,
    },
};

pub(crate) struct EthApi<R> {
    resolver: R,
    pub(crate) permissions_enabled: bool,
}

impl<R> EthApi<R>
where
    R: ChainResolver,
{
    pub(crate) fn new(resolver: R, permissions_enabled: bool) -> Self {
        Self {
            resolver,
            permissions_enabled,
        }
    }

    pub(crate) fn resolve(
        &self,
        ext: &Extensions,
    ) -> EthResult<crate::chain_resolver::ResolvedChain<'_>> {
        self.resolver.resolve(ext).map_err(EthRpcError::from)
    }

    #[instrument(skip_all)]
    pub(crate) async fn send_user_operation(
        &self,
        chain_spec: &ChainSpec,
        pool: &dyn Pool,
        entry_points: &[rundler_types::EntryPointVersion],
        op: UserOperationVariant,
        entry_point: Address,
        permissions: UserOperationPermissions,
    ) -> EthResult<B256> {
        let bundle_size = op.single_uo_bundle_size_bytes();
        if bundle_size > chain_spec.max_transaction_size_bytes {
            return Err(EthRpcError::InvalidParams(format!(
                "User operation in bundle size {} exceeds max transaction size {}",
                bundle_size, chain_spec.max_transaction_size_bytes
            )));
        }

        if permissions.bundler_sponsorship.is_some()
            && (op.max_fee_per_gas() != 0
                || op.max_priority_fee_per_gas() != 0
                || op.pre_verification_gas() != 0
                || op.paymaster().is_some())
        {
            return Err(EthRpcError::InvalidParams(
                    "Bundler sponsorship requires max fee per gas, max priority fee per gas, pre-verification gas, and paymaster to be 0/empty".to_string(),
                ));
        }

        if op.authorization_tuple().is_some()
            && (!chain_spec.supports_eip7702(entry_point) || permissions.eip7702_disabled)
        {
            return Err(EthRpcError::InvalidParams(format!(
                "EIP-7702 is not supported on entry point {:?} or is disabled",
                entry_point
            )));
        }

        // Validate UO version matches entry point
        Self::validate_uo_version(chain_spec, entry_points, &entry_point, &op)?;

        pool.add_op(op, permissions)
            .await
            .map_err(EthRpcError::from)
            .log_on_error_level(Level::DEBUG, "failed to add op to the mempool")
    }

    #[instrument(skip_all)]
    pub(crate) async fn estimate_user_operation_gas(
        &self,
        chain_spec: &ChainSpec,
        pool: &dyn Pool,
        op: UserOperationOptionalGas,
        entry_point: Address,
        state_override: Option<rundler_provider::StateOverride>,
    ) -> EthResult<RpcGasEstimate> {
        let bundle_size = op.single_uo_bundle_size_bytes();
        if bundle_size > chain_spec.max_transaction_size_bytes {
            return Err(EthRpcError::InvalidParams(format!(
                "User operation in bundle size {} exceeds max transaction size {}",
                bundle_size, chain_spec.max_transaction_size_bytes
            )));
        }

        if op.eip7702_auth_address().is_some() && !chain_spec.supports_eip7702(entry_point) {
            return Err(EthRpcError::InvalidParams(format!(
                "EIP-7702 is not supported on entry point {:?}",
                entry_point
            )));
        }

        let ep_version = chain_spec.entry_point_version(entry_point).ok_or_else(|| {
            EthRpcError::InvalidParams(format!("Unsupported entry point: {:?}", entry_point))
        })?;

        let state_override_json = state_override
            .map(|so| serde_json::to_vec(&so))
            .transpose()
            .map_err(|e| {
                EthRpcError::Internal(anyhow::anyhow!("Failed to serialize state override: {e}"))
            })?;

        let estimate = pool
            .estimate_user_operation_gas(entry_point, op, state_override_json)
            .await
            .map_err(EthRpcError::from)?;

        match ep_version.abi_version() {
            EntryPointAbiVersion::V0_6 => Ok(RpcGasEstimateV0_6::from(estimate).into()),
            EntryPointAbiVersion::V0_7 => Ok(RpcGasEstimateV0_7::from(estimate).into()),
        }
    }

    #[instrument(skip_all)]
    pub(crate) async fn get_user_operation_by_hash(
        pool: &dyn Pool,
        hash: B256,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        if hash == B256::ZERO {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        // Check mined first
        if let Some(mined) = pool
            .get_mined_by_hash(hash)
            .await
            .map_err(EthRpcError::from)?
        {
            return Ok(Some(RpcUserOperationByHash {
                user_operation: mined.user_operation.into(),
                entry_point: mined.entry_point.into(),
                block_number: Some(mined.block_number),
                block_hash: Some(mined.block_hash),
                transaction_hash: Some(mined.transaction_hash),
            }));
        }

        // Check pending
        let res = pool.get_op_by_hash(hash).await.map_err(EthRpcError::from)?;

        Ok(res.map(|op| RpcUserOperationByHash {
            user_operation: op.uo.into(),
            entry_point: op.entry_point.into(),
            block_number: None,
            block_hash: None,
            transaction_hash: None,
        }))
    }

    #[instrument(skip_all)]
    pub(crate) async fn get_user_operation_receipt(
        chain_spec: &ChainSpec,
        pool: &dyn Pool,
        hash: B256,
        tag: Option<BlockTag>,
    ) -> EthResult<Option<RpcUserOperationReceipt>> {
        if hash == B256::ZERO {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }
        let tag = tag.unwrap_or(BlockTag::Latest);

        let bundle_transaction: Option<B256> = match tag {
            BlockTag::Pending => {
                if !chain_spec.flashblocks_enabled {
                    return Err(EthRpcError::InvalidParams(
                        "Unsupported feature: preconfirmation".to_string(),
                    ));
                }
                let op_status = pool.get_op_status(hash).await.map_err(EthRpcError::from)?;

                op_status
                    .and_then(|s| s.preconf_info)
                    .map(|info| info.tx_hash)
            }
            BlockTag::Latest => None,
        };

        let receipt_data = pool
            .get_user_operation_receipt(hash, bundle_transaction)
            .await
            .map_err(EthRpcError::from)?;

        match receipt_data {
            Some(data) => {
                let receipt = Self::receipt_data_to_rpc(data)?;
                Ok(Some(receipt))
            }
            None => Ok(None),
        }
    }

    #[instrument(skip_all)]
    pub(crate) fn supported_entry_points(
        chain_spec: &ChainSpec,
        entry_points: &[rundler_types::EntryPointVersion],
    ) -> EthResult<Vec<String>> {
        Ok(entry_points
            .iter()
            .map(|ep| chain_spec.entry_point_address(*ep).to_checksum(None))
            .collect())
    }

    #[instrument(skip_all)]
    pub(crate) fn chain_id(chain_spec: &ChainSpec) -> EthResult<U64> {
        Ok(U64::from(chain_spec.id))
    }

    fn validate_uo_version(
        chain_spec: &ChainSpec,
        entry_points: &[rundler_types::EntryPointVersion],
        entry_point: &Address,
        uo: &UserOperationVariant,
    ) -> EthResult<()> {
        let ep_version = chain_spec
            .entry_point_version(*entry_point)
            .ok_or_else(|| {
                EthRpcError::InvalidParams(format!("Unsupported entry point: {:?}", entry_point))
            })?;

        // Make sure this entry point version is enabled
        if !entry_points.contains(&ep_version) {
            return Err(EthRpcError::InvalidParams(format!(
                "Entry point {:?} (version {:?}) is not enabled",
                entry_point, ep_version
            )));
        }

        match ep_version.abi_version() {
            EntryPointAbiVersion::V0_6 => {
                if !matches!(uo, UserOperationVariant::V0_6(_)) {
                    return Err(EthRpcError::InvalidParams(format!(
                        "Invalid user operation for entry point: {:?}",
                        entry_point
                    )));
                }
            }
            EntryPointAbiVersion::V0_7 => {
                if !matches!(uo, UserOperationVariant::V0_7(_)) {
                    return Err(EthRpcError::InvalidParams(format!(
                        "Invalid user operation for entry point: {:?}",
                        entry_point
                    )));
                }
            }
        }

        Ok(())
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

        use crate::types::UOStatusEnum;

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

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;
    use mockall::predicate::eq;
    use rundler_types::{
        EntityInfos, UserOperation as UserOperationTrait, ValidTimeRange,
        pool::{MockPool, PoolOperation},
        v0_6::{UserOperationBuilder, UserOperationRequiredFields},
    };

    use super::*;
    use crate::gateway::ChainRouter;

    #[tokio::test]
    async fn test_get_user_op_by_hash_pending() {
        let cs = ChainSpec {
            id: 1,
            ..Default::default()
        };
        let ep = cs.entry_point_address_v0_6;
        let uo = UserOperationBuilder::new(&cs, UserOperationRequiredFields::default()).build();
        let hash = uo.hash();

        let po = PoolOperation {
            uo: uo.clone().into(),
            entry_point: ep,
            aggregator: None,
            valid_time_range: ValidTimeRange::default(),
            expected_code_hash: B256::random(),
            sim_block_hash: B256::random(),
            sim_block_number: 1000,
            account_is_staked: false,
            entity_infos: EntityInfos::default(),
            da_gas_data: rundler_types::da::DAGasData::Empty,
            filter_id: None,
            perms: UserOperationPermissions::default(),
            sender_is_7702: false,
        };

        let mut pool = MockPool::default();
        pool.expect_get_mined_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(|_| Ok(None));
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(Some(po.clone())));

        let res = EthApi::<ChainRouter>::get_user_operation_by_hash(&pool, hash)
            .await
            .unwrap();
        let ro = RpcUserOperationByHash {
            user_operation: UserOperationVariant::from(uo).into(),
            entry_point: ep.into(),
            block_number: None,
            block_hash: None,
            transaction_hash: None,
        };
        assert_eq!(res, Some(ro));
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_mined() {
        let cs = ChainSpec {
            id: 1,
            ..Default::default()
        };
        let ep = cs.entry_point_address_v0_6;
        let uo = UserOperationBuilder::new(&cs, UserOperationRequiredFields::default()).build();
        let hash = uo.hash();
        let block_number = 1000u64;
        let block_hash = B256::random();
        let tx_hash = B256::random();

        let mined = rundler_types::pool::MinedUserOperation {
            user_operation: uo.clone().into(),
            entry_point: ep,
            block_number: U256::from(block_number),
            block_hash,
            transaction_hash: tx_hash,
        };

        let mut pool = MockPool::default();
        pool.expect_get_mined_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(Some(mined.clone())));

        let res = EthApi::<ChainRouter>::get_user_operation_by_hash(&pool, hash)
            .await
            .unwrap();
        let ro = RpcUserOperationByHash {
            user_operation: UserOperationVariant::from(uo).into(),
            entry_point: ep.into(),
            block_number: Some(U256::from(block_number)),
            block_hash: Some(block_hash),
            transaction_hash: Some(tx_hash),
        };
        assert_eq!(res, Some(ro));
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_not_found() {
        let cs = ChainSpec {
            id: 1,
            ..Default::default()
        };
        let uo = UserOperationBuilder::new(&cs, UserOperationRequiredFields::default()).build();
        let hash = uo.hash();

        let mut pool = MockPool::default();
        pool.expect_get_mined_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(|_| Ok(None));
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(None));

        let res = EthApi::<ChainRouter>::get_user_operation_by_hash(&pool, hash)
            .await
            .unwrap();
        assert_eq!(res, None);
    }
}
