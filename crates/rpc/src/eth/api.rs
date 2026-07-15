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

use std::{future::Future, pin::Pin};

use alloy_primitives::{Address, B256, U64};
use futures_util::future;
use rundler_provider::{EvmProvider, FilterBlockOption, StateOverride};
use rundler_types::{
    BlockTag, UserOperation, UserOperationOptionalGas, UserOperationPermissions,
    UserOperationVariant, chain::ChainSpec, pool::Pool,
};
use rundler_utils::log::LogOnError;
use tracing::{Level, instrument};

use super::{
    error::{EthResult, EthRpcError},
    router::EntryPointRouter,
};
use crate::{
    eth::events::{self, EventProviderError},
    types::{RpcGasEstimate, RpcUserOperationByHash, RpcUserOperationReceipt},
};

pub(crate) struct EthApi<P, E> {
    pub(crate) chain_spec: ChainSpec,
    pool: P,
    router: EntryPointRouter,
    provider: E,
    pub(crate) permissions_enabled: bool,
}

impl<P, E> EthApi<P, E>
where
    P: Pool,
    E: EvmProvider,
{
    pub(crate) fn new(
        chain_spec: ChainSpec,
        router: EntryPointRouter,
        pool: P,
        provider: E,
        permissions_enabled: bool,
    ) -> Self {
        Self {
            router,
            pool,
            chain_spec,
            provider,
            permissions_enabled,
        }
    }

    #[instrument(skip_all)]
    pub(crate) async fn send_user_operation(
        &self,
        op: UserOperationVariant,
        entry_point: Address,
        permissions: UserOperationPermissions,
    ) -> EthResult<B256> {
        let bundle_size = op.single_uo_bundle_size_bytes();
        if bundle_size > self.chain_spec.max_transaction_size_bytes {
            return Err(EthRpcError::InvalidParams(format!(
                "User operation in bundle size {} exceeds max transaction size {}",
                bundle_size, self.chain_spec.max_transaction_size_bytes
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
            && (!self.chain_spec.supports_eip7702(entry_point) || permissions.eip7702_disabled)
        {
            return Err(EthRpcError::InvalidParams(format!(
                "EIP-7702 is not supported on entry point {:?} or is disabled",
                entry_point
            )));
        }

        self.router.check_and_get_route(&entry_point, &op)?;

        self.pool
            .add_op(op, permissions)
            .await
            .map_err(EthRpcError::from)
            .log_on_error_level(Level::DEBUG, "failed to add op to the mempool")
    }

    #[instrument(skip_all)]
    pub(crate) async fn estimate_user_operation_gas(
        &self,
        op: UserOperationOptionalGas,
        entry_point: Address,
        state_override: Option<StateOverride>,
    ) -> EthResult<RpcGasEstimate> {
        let bundle_size = op.single_uo_bundle_size_bytes();
        if bundle_size > self.chain_spec.max_transaction_size_bytes {
            return Err(EthRpcError::InvalidParams(format!(
                "User operation in bundle size {} exceeds max transaction size {}",
                bundle_size, self.chain_spec.max_transaction_size_bytes
            )));
        }

        if op.eip7702_auth_address().is_some() && !self.chain_spec.supports_eip7702(entry_point) {
            return Err(EthRpcError::InvalidParams(format!(
                "EIP-7702 is not supported on entry point {:?}",
                entry_point
            )));
        }

        self.router
            .estimate_gas(&entry_point, op, state_override)
            .await
    }

    #[instrument(skip_all)]
    pub(crate) async fn get_user_operation_by_hash(
        &self,
        hash: B256,
        block_option: Option<FilterBlockOption>,
        max_block_range: Option<u64>,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        if hash == B256::ZERO {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        let block_option = self.resolve_block_option(block_option).await?;

        // check both entry points and pending for the user operation event
        #[allow(clippy::type_complexity)]
        let mut futs: Vec<
            Pin<Box<dyn Future<Output = EthResult<Option<RpcUserOperationByHash>>> + Send>>,
        > = vec![];

        for ep in self.router.entry_points() {
            futs.push(Box::pin(async move {
                self.router
                    .get_mined_by_hash(ep, hash, block_option, max_block_range)
                    .await
                    .map_err(EthRpcError::from)
            }));
        }
        futs.push(Box::pin(self.get_pending_user_operation_by_hash(hash)));

        let results = future::try_join_all(futs).await?;
        Ok(results.into_iter().find_map(|x| x))
    }

    #[instrument(skip_all)]
    pub(crate) async fn get_user_operation_receipt(
        &self,
        hash: B256,
        tag: Option<BlockTag>,
        block_option: Option<FilterBlockOption>,
        max_block_range: Option<u64>,
    ) -> EthResult<Option<RpcUserOperationReceipt>> {
        if hash == B256::ZERO {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        let block_option = self.resolve_block_option(block_option).await?;
        let tag = tag.unwrap_or(BlockTag::Latest);

        if tag == BlockTag::Pending {
            if !self.chain_spec.flashblocks_enabled {
                return Err(EthRpcError::InvalidParams(
                    "Pending block tag is not supported on this network".to_string(),
                ));
            }

            // Preconfirmed check. If not found fallthrough to pending check.
            let op_status = self
                .pool
                .get_op_status(hash)
                .await
                .map_err(EthRpcError::from)?;

            if let Some(op_status) = op_status
                && let Some(preconf_info) = op_status.preconf_info
            {
                let ret = self
                    .router
                    .get_receipt(
                        &op_status.entry_point,
                        hash,
                        Some(preconf_info.tx_hash),
                        None,
                        max_block_range,
                    )
                    .await;
                match ret {
                    Ok(Some(receipt)) => return Ok(Some(receipt)),
                    Ok(None) => {
                        // fallthrough to pending if not found
                        tracing::warn!(
                            "no receipt found for preconfirmed user operation {hash}. Treating as pending."
                        );
                    }
                    Err(EventProviderError::Provider(e)) => {
                        return Err(EthRpcError::from(EventProviderError::Provider(e)));
                    }
                    _ => {
                        // fallthrough to pending on unexpected errors related to consistency issues or invalid receipts
                        tracing::warn!(
                            "unexpected error fetching receipt for preconfirmed user operation {hash}. Treating as pending: {ret:?}"
                        );
                    }
                };
            }
        };

        let futs = self.router.entry_points().map(|ep| {
            self.router
                .get_receipt(ep, hash, None, block_option, max_block_range)
        });
        let results = future::try_join_all(futs).await?;
        Ok(results.into_iter().find_map(|x| x))
    }

    #[instrument(skip_all)]
    pub(crate) async fn supported_entry_points(&self) -> EthResult<Vec<String>> {
        Ok(self
            .router
            .entry_points()
            .map(|ep| ep.to_checksum(None))
            .collect())
    }

    #[instrument(skip_all)]
    pub(crate) async fn chain_id(&self) -> EthResult<U64> {
        Ok(U64::from(self.chain_spec.id))
    }

    #[instrument(skip_all)]
    async fn get_pending_user_operation_by_hash(
        &self,
        hash: B256,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        let op = self
            .pool
            .get_op_by_hash(hash)
            .await
            .map_err(EthRpcError::from)?;

        Ok(op.map(|op| RpcUserOperationByHash {
            user_operation: op.uo.into(),
            entry_point: op.entry_point.into(),
            block_number: None,
            block_hash: None,
            transaction_hash: None,
        }))
    }

    // Resolve block tags to concrete numbers once, before fanning out to the entry point
    // routes, so each route doesn't re-resolve them via RPC.
    async fn resolve_block_option(
        &self,
        block_option: Option<FilterBlockOption>,
    ) -> EthResult<Option<FilterBlockOption>> {
        match block_option {
            Some(bo) => Ok(Some(
                events::resolve_block_option(&self.provider, bo)
                    .await
                    .map_err(EthRpcError::from)?,
            )),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_consensus::{Signed, TxEip1559, transaction::Recovered};
    use alloy_primitives::{Log as PrimitiveLog, LogData, Signature, TxKind, U256};
    use alloy_rpc_types_eth::Transaction as AlloyTransaction;
    use alloy_sol_types::SolInterface;
    use mockall::predicate::eq;
    use rundler_contracts::v0_6::IEntryPoint::{IEntryPointCalls, handleOpsCall};
    use rundler_provider::{
        AnyTxEnvelope, Log, MockEntryPointV0_6, MockEvmProvider, Transaction, WithOtherFields,
    };
    use rundler_sim::MockGasEstimator;
    use rundler_types::{
        EntityInfos, UserOperation as UserOperationTrait, ValidTimeRange,
        pool::{MockPool, PoolOperation},
        v0_6::{UserOperationBuilder, UserOperationRequiredFields},
    };

    use super::*;
    use crate::eth::{
        EntryPointRouteImpl, EntryPointRouterBuilder, UserOperationEventProviderV0_6,
    };

    #[tokio::test]
    async fn test_get_user_op_by_hash_pending() {
        let ep = Address::random();
        let cs = ChainSpec {
            entry_point_address_v0_6: ep,
            ..Default::default()
        };
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
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(Some(po.clone())));

        let mut provider = MockEvmProvider::default();
        provider.expect_get_logs().returning(move |_| Ok(vec![]));
        provider.expect_get_block_number().returning(|| Ok(1000));

        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().return_const(ep);

        let api = create_api(
            provider,
            entry_point,
            pool,
            MockGasEstimator::default(),
            false,
        );
        let res = api
            .get_user_operation_by_hash(hash, None, None)
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
        let block_number = 1000;
        let block_hash = B256::random();

        let mut pool = MockPool::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .returning(move |_| Ok(None));

        let mut provider = MockEvmProvider::default();
        provider.expect_get_block_number().returning(|| Ok(1000));

        let tx_data = IEntryPointCalls::handleOps(handleOpsCall {
            ops: vec![uo.clone().into()],
            beneficiary: Address::ZERO,
        })
        .abi_encode();

        let inner_txn = TxEip1559 {
            to: TxKind::Call(ep),
            input: tx_data.into(),
            ..Default::default()
        };

        let inner: alloy_consensus::EthereumTxEnvelope<alloy_consensus::TxEip4844Variant> =
            Signed::new_unchecked(inner_txn, Signature::test_signature(), hash).into();
        let tx_hash = *inner.tx_hash();
        let inner = AnyTxEnvelope::Ethereum(inner);

        let tx: Transaction = WithOtherFields::new(AlloyTransaction {
            inner: Recovered::new_unchecked(inner, Address::ZERO),
            block_hash: Some(block_hash),
            block_number: Some(block_number),
            transaction_index: None,
            effective_gas_price: None,
        })
        .into();

        let log = Log {
            inner: PrimitiveLog {
                address: ep,
                data: LogData::default(),
            },
            transaction_hash: Some(tx_hash),
            ..Default::default()
        };

        provider
            .expect_get_logs()
            .returning(move |_| Ok(vec![log.clone()]));
        provider
            .expect_get_transaction_by_hash()
            .with(eq(tx_hash))
            .returning(move |_| Ok(Some(tx.clone())));

        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().return_const(ep);

        let api = create_api(
            provider,
            entry_point,
            pool,
            MockGasEstimator::default(),
            false,
        );
        let res = api
            .get_user_operation_by_hash(hash, None, None)
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
        let ep = cs.entry_point_address_v0_6;
        let uo = UserOperationBuilder::new(&cs, UserOperationRequiredFields::default()).build();
        let hash = uo.hash();

        let mut pool = MockPool::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(None));

        let mut provider = MockEvmProvider::default();
        provider.expect_get_logs().returning(move |_| Ok(vec![]));
        provider.expect_get_block_number().returning(|| Ok(1000));

        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().return_const(ep);

        let api = create_api(
            provider,
            entry_point,
            pool,
            MockGasEstimator::default(),
            false,
        );
        let res = api
            .get_user_operation_by_hash(hash, None, None)
            .await
            .unwrap();
        assert_eq!(res, None);
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_with_block_option() {
        let cs = ChainSpec {
            id: 1,
            ..Default::default()
        };
        let ep = cs.entry_point_address_v0_6;
        let uo = UserOperationBuilder::new(&cs, UserOperationRequiredFields::default()).build();
        let hash = uo.hash();

        for block_option in [
            FilterBlockOption::Range {
                from_block: Some(100u64.into()),
                to_block: Some(200u64.into()),
            },
            FilterBlockOption::AtBlockHash(B256::random()),
        ] {
            let mut pool = MockPool::default();
            pool.expect_get_op_by_hash()
                .with(eq(hash))
                .returning(move |_| Ok(None));

            // no `expect_get_block_number`: a caller-supplied block option must skip
            // the latest-block lookup used to compute the default search window
            let mut provider = MockEvmProvider::default();
            provider
                .expect_get_logs()
                .withf(move |filter| filter.block_option == block_option)
                .returning(move |_| Ok(vec![]));

            let mut entry_point = MockEntryPointV0_6::default();
            entry_point.expect_address().return_const(ep);

            let api = create_api(
                provider,
                entry_point,
                pool,
                MockGasEstimator::default(),
                false,
            );
            let res = api
                .get_user_operation_by_hash(hash, Some(block_option), None)
                .await
                .unwrap();
            assert_eq!(res, None);
        }
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_max_block_range_override() {
        let cs = ChainSpec {
            id: 1,
            ..Default::default()
        };
        let ep = cs.entry_point_address_v0_6;
        let uo = UserOperationBuilder::new(&cs, UserOperationRequiredFields::default()).build();
        let hash = uo.hash();

        let mut pool = MockPool::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .returning(move |_| Ok(None));

        // The event provider is constructed with no static block distance, so a non-default
        // search window proves the per-request override is applied.
        let mut provider = MockEvmProvider::default();
        provider.expect_get_block_number().returning(|| Ok(1000));
        provider
            .expect_get_logs()
            .withf(|filter| {
                filter.block_option
                    == FilterBlockOption::Range {
                        from_block: Some(900u64.into()),
                        to_block: Some(1000u64.into()),
                    }
            })
            .returning(move |_| Ok(vec![]));

        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().return_const(ep);

        let api = create_api(
            provider,
            entry_point,
            pool,
            MockGasEstimator::default(),
            false,
        );
        let res = api
            .get_user_operation_by_hash(hash, None, Some(100))
            .await
            .unwrap();
        assert_eq!(res, None);
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_resolves_tags_once() {
        use alloy_eips::BlockNumberOrTag;

        let cs = ChainSpec {
            id: 1,
            ..Default::default()
        };
        let ep = cs.entry_point_address_v0_6;
        let uo = UserOperationBuilder::new(&cs, UserOperationRequiredFields::default()).build();
        let hash = uo.hash();

        let mut pool = MockPool::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .returning(move |_| Ok(None));

        // A latest..latest range must be resolved to concrete numbers with a single
        // get_block call before the fan-out; the filter must see the numbers.
        let mut inner = alloy_rpc_types_eth::Block::<
            rundler_provider::AnyRpcTransaction,
            rundler_provider::AnyRpcHeader,
        >::default();
        inner.header.inner.number = 1000;
        let block = rundler_provider::Block::new(WithOtherFields::new(inner));
        let mut provider = MockEvmProvider::default();
        provider
            .expect_get_block()
            .times(1)
            .returning(move |_| Ok(Some(block.clone())));
        provider
            .expect_get_logs()
            .withf(|filter| {
                filter.block_option
                    == FilterBlockOption::Range {
                        from_block: Some(1000u64.into()),
                        to_block: Some(1000u64.into()),
                    }
            })
            .returning(move |_| Ok(vec![]));

        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().return_const(ep);

        let api = create_api(
            provider,
            entry_point,
            pool,
            MockGasEstimator::default(),
            false,
        );
        let res = api
            .get_user_operation_by_hash(
                hash,
                Some(FilterBlockOption::Range {
                    from_block: Some(BlockNumberOrTag::Latest),
                    to_block: Some(BlockNumberOrTag::Latest),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(res, None);
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_block_option_invalid_ranges() {
        let cs = ChainSpec {
            id: 1,
            ..Default::default()
        };
        let ep = cs.entry_point_address_v0_6;
        let uo = UserOperationBuilder::new(&cs, UserOperationRequiredFields::default()).build();
        let hash = uo.hash();

        // Wider than the max block range, missing a bound while a max is enforced, and
        // reversed: all must surface as invalid params, not an internal error.
        for block_option in [
            FilterBlockOption::Range {
                from_block: Some(100u64.into()),
                to_block: Some(300u64.into()),
            },
            FilterBlockOption::Range {
                from_block: Some(100u64.into()),
                to_block: None,
            },
            FilterBlockOption::Range {
                from_block: Some(300u64.into()),
                to_block: Some(100u64.into()),
            },
        ] {
            let mut pool = MockPool::default();
            pool.expect_get_op_by_hash()
                .with(eq(hash))
                .returning(move |_| Ok(None));

            let mut entry_point = MockEntryPointV0_6::default();
            entry_point.expect_address().return_const(ep);

            let api = create_api(
                MockEvmProvider::default(),
                entry_point,
                pool,
                MockGasEstimator::default(),
                false,
            );
            let err = api
                .get_user_operation_by_hash(hash, Some(block_option), Some(100))
                .await
                .unwrap_err();
            assert!(
                matches!(err, EthRpcError::InvalidParams(_)),
                "expected invalid params, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_send_user_op_header_permissions_take_precedence() {
        use std::sync::Mutex;

        use http::Extensions;
        use rundler_types::EntryPointVersion;

        use crate::{
            eth::{EntryPointRouteImpl, EntryPointRouterBuilder, EthApiServer},
            types::{RpcPermissions, RpcUserOperation},
        };

        let chain_spec = ChainSpec {
            id: 1,
            max_transaction_size_bytes: 1_000_000,
            ..Default::default()
        };
        let ep = chain_spec.entry_point_address_v0_6;
        let uo =
            UserOperationBuilder::new(&chain_spec, UserOperationRequiredFields::default()).build();

        let captured = Arc::new(Mutex::new(None));
        let captured_clone = captured.clone();
        let mut pool = MockPool::default();
        pool.expect_add_op().returning(move |_, perms| {
            *captured_clone.lock().unwrap() = Some(perms);
            Ok(B256::ZERO)
        });

        let provider = Arc::new(MockEvmProvider::default());
        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().return_const(ep);
        entry_point
            .expect_version()
            .return_const(EntryPointVersion::V0_6);

        let router = EntryPointRouterBuilder::default()
            .add_route(EntryPointRouteImpl::new(
                Arc::new(entry_point),
                MockGasEstimator::default(),
                UserOperationEventProviderV0_6::new(
                    chain_spec.clone(),
                    ep,
                    provider.clone(),
                    None,
                    None,
                ),
            ))
            .build();

        let api = EthApi {
            router,
            chain_spec,
            pool,
            provider,
            permissions_enabled: true,
        };

        // Positional parameter says untrusted; the header says trusted. The header must win.
        let mut ext = Extensions::new();
        ext.insert(RpcPermissions {
            trusted: true,
            ..Default::default()
        });
        let positional = RpcPermissions {
            trusted: false,
            ..Default::default()
        };

        let rpc_uo: RpcUserOperation = UserOperationVariant::from(uo).into();
        EthApiServer::send_user_operation(&api, &ext, rpc_uo, ep, Some(positional))
            .await
            .unwrap();

        let perms = captured.lock().unwrap().clone().unwrap();
        assert!(perms.trusted, "header permissions should take precedence");
    }

    fn create_api(
        provider: MockEvmProvider,
        ep: MockEntryPointV0_6,
        pool: MockPool,
        gas_estimator: MockGasEstimator,
        permissions_enabled: bool,
    ) -> EthApi<MockPool, Arc<MockEvmProvider>> {
        let ep = Arc::new(ep);
        let provider = Arc::new(provider);
        let chain_spec = ChainSpec {
            id: 1,
            ..Default::default()
        };

        let router = EntryPointRouterBuilder::default()
            .add_route(EntryPointRouteImpl::new(
                ep.clone(),
                gas_estimator,
                UserOperationEventProviderV0_6::new(
                    chain_spec.clone(),
                    chain_spec.entry_point_address_v0_6,
                    provider.clone(),
                    None,
                    None,
                ),
            ))
            .build();

        EthApi {
            router,
            chain_spec,
            pool,
            provider,
            permissions_enabled,
        }
    }
}
