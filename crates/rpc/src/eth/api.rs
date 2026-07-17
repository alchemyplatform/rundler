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
use rundler_provider::{EvmProvider, StateOverride};
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
    eth::events::{EventBlockOptions, EventProviderError},
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
        block_options: EventBlockOptions,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        if hash == B256::ZERO {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        let block_options = block_options
            .resolve(&self.provider)
            .await
            .map_err(EthRpcError::from)?;

        // check both entry points and pending for the user operation event
        #[allow(clippy::type_complexity)]
        let mut futs: Vec<
            Pin<Box<dyn Future<Output = EthResult<Option<RpcUserOperationByHash>>> + Send>>,
        > = vec![];

        for ep in self.router.entry_points() {
            futs.push(Box::pin(async move {
                self.router
                    .get_mined_by_hash(ep, hash, block_options)
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
        block_options: EventBlockOptions,
    ) -> EthResult<Option<RpcUserOperationReceipt>> {
        if hash == B256::ZERO {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        let block_options = block_options
            .resolve(&self.provider)
            .await
            .map_err(EthRpcError::from)?;
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
                        EventBlockOptions {
                            block_option: None,
                            ..block_options
                        },
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

        let futs = self
            .router
            .entry_points()
            .map(|ep| self.router.get_receipt(ep, hash, None, block_options));
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
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_consensus::{Signed, TxEip1559, transaction::Recovered};
    use alloy_eips::BlockNumberOrTag;
    use alloy_primitives::{Log as PrimitiveLog, LogData, Signature, TxKind, U256};
    use alloy_rpc_types_eth::Transaction as AlloyTransaction;
    use alloy_sol_types::SolInterface;
    use mockall::predicate::eq;
    use rundler_contracts::v0_6::IEntryPoint::{IEntryPointCalls, handleOpsCall};
    use rundler_provider::{
        AnyTxEnvelope, FilterBlockOption, Log, MockEntryPointV0_6, MockEvmProvider, ProviderError,
        Transaction, WithOtherFields,
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
            .get_user_operation_by_hash(hash, EventBlockOptions::default())
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
            .get_user_operation_by_hash(hash, EventBlockOptions::default())
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
            .get_user_operation_by_hash(hash, EventBlockOptions::default())
            .await
            .unwrap();
        assert_eq!(res, None);
    }

    /// Fixture for `get_user_operation_by_hash` lookup tests: a pool with no pending
    /// op, a single v0.6 entry point, and per-test provider expectations.
    struct LookupTest {
        provider: MockEvmProvider,
        event_block_distance: Option<u64>,
        event_block_distance_fallback: Option<u64>,
    }

    fn range(from: u64, to: u64) -> FilterBlockOption {
        FilterBlockOption::Range {
            from_block: Some(from.into()),
            to_block: Some(to.into()),
        }
    }

    impl LookupTest {
        fn new() -> Self {
            Self {
                provider: MockEvmProvider::default(),
                event_block_distance: None,
                event_block_distance_fallback: None,
            }
        }

        fn distances(mut self, distance: Option<u64>, fallback: Option<u64>) -> Self {
            self.event_block_distance = distance;
            self.event_block_distance_fallback = fallback;
            self
        }

        /// The provider's latest block number, used to compute default search windows.
        fn latest_block(mut self, number: u64) -> Self {
            self.provider
                .expect_get_block_number()
                .returning(move || Ok(number));
            self
        }

        /// Expect exactly one tag-resolving `get_block` call, resolving to `number`.
        fn resolves_tag_to(mut self, number: u64) -> Self {
            let mut inner = alloy_rpc_types_eth::Block::<
                rundler_provider::AnyRpcTransaction,
                rundler_provider::AnyRpcHeader,
            >::default();
            inner.header.inner.number = number;
            let block = rundler_provider::Block::new(WithOtherFields::new(inner));
            self.provider
                .expect_get_block()
                .times(1)
                .returning(move |_| Ok(Some(block.clone())));
            self
        }

        /// Tag resolution finds no block.
        fn tag_unresolvable(mut self) -> Self {
            self.provider.expect_get_block().returning(|_| Ok(None));
            self
        }

        /// Expect exactly one `get_logs` call for `block_option`, returning no logs.
        fn logs_empty(mut self, block_option: FilterBlockOption) -> Self {
            self.provider
                .expect_get_logs()
                .withf(move |filter| filter.block_option == block_option)
                .times(1)
                .returning(|_| Ok(vec![]));
            self
        }

        /// Expect exactly one `get_logs` call for `block_option`, returning an error.
        fn logs_error(mut self, block_option: FilterBlockOption) -> Self {
            self.provider
                .expect_get_logs()
                .withf(move |filter| filter.block_option == block_option)
                .times(1)
                .returning(|_| Err(ProviderError::Other(anyhow::anyhow!("getLogs failed"))));
            self
        }

        /// Expect exactly two `get_logs` calls for `block_option`: an error, then no logs.
        fn logs_error_then_empty(mut self, block_option: FilterBlockOption) -> Self {
            let mut first = true;
            self.provider
                .expect_get_logs()
                .withf(move |filter| filter.block_option == block_option)
                .times(2)
                .returning(move |_| {
                    if first {
                        first = false;
                        Err(ProviderError::Other(anyhow::anyhow!("getLogs failed")))
                    } else {
                        Ok(vec![])
                    }
                });
            self
        }

        async fn run(
            self,
            block_options: EventBlockOptions,
        ) -> EthResult<Option<RpcUserOperationByHash>> {
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

            let mut entry_point = MockEntryPointV0_6::default();
            entry_point.expect_address().return_const(ep);

            let api = create_api_with_event_distances(
                self.provider,
                entry_point,
                pool,
                MockGasEstimator::default(),
                false,
                self.event_block_distance,
                self.event_block_distance_fallback,
            );
            api.get_user_operation_by_hash(hash, block_options).await
        }
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_with_block_option() {
        // A caller-supplied block option must reach the getLogs filter as-is and skip
        // the latest-block lookup used to compute the default search window.
        for block_option in [
            range(100, 200),
            FilterBlockOption::AtBlockHash(B256::random()),
        ] {
            let res = LookupTest::new()
                .logs_empty(block_option)
                .run(EventBlockOptions {
                    block_option: Some(block_option),
                    max_block_range: None,
                })
                .await
                .unwrap();
            assert_eq!(res, None);
        }
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_max_block_range_override() {
        // No static block distance is configured, so a non-default search window proves
        // the per-request override is applied.
        let res = LookupTest::new()
            .latest_block(1000)
            .logs_empty(range(900, 1000))
            .run(EventBlockOptions {
                block_option: None,
                max_block_range: Some(100),
            })
            .await
            .unwrap();
        assert_eq!(res, None);
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_resolves_tags_once() {
        // A latest..latest range must be resolved to concrete numbers with a single
        // get_block call before the fan-out; the filter must see the numbers.
        let res = LookupTest::new()
            .resolves_tag_to(1000)
            .logs_empty(range(1000, 1000))
            .run(EventBlockOptions {
                block_option: Some(FilterBlockOption::Range {
                    from_block: Some(BlockNumberOrTag::Latest),
                    to_block: Some(BlockNumberOrTag::Latest),
                }),
                max_block_range: None,
            })
            .await
            .unwrap();
        assert_eq!(res, None);
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_unresolvable_tag_is_invalid_params() {
        // The tag is caller-supplied, so a provider returning no block for it must
        // surface as invalid params, not an internal error.
        let err = LookupTest::new()
            .tag_unresolvable()
            .run(EventBlockOptions {
                block_option: Some(FilterBlockOption::Range {
                    from_block: Some(BlockNumberOrTag::Pending),
                    to_block: Some(BlockNumberOrTag::Pending),
                }),
                max_block_range: None,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, EthRpcError::InvalidParams(_)),
            "expected invalid params, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_block_option_invalid_ranges() {
        // Wider than the max block range, missing a bound while a max is enforced, and
        // reversed: all must surface as invalid params, not an internal error.
        for block_option in [
            range(100, 300),
            FilterBlockOption::Range {
                from_block: Some(100u64.into()),
                to_block: None,
            },
            range(300, 100),
        ] {
            let err = LookupTest::new()
                .run(EventBlockOptions {
                    block_option: Some(block_option),
                    max_block_range: Some(100),
                })
                .await
                .unwrap_err();
            assert!(
                matches!(err, EthRpcError::InvalidParams(_)),
                "expected invalid params, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_fallback_retries_default_path() {
        // With no caller-supplied block option, a failed primary query must retry with
        // the configured fallback distance.
        let res = LookupTest::new()
            .distances(Some(500), Some(100))
            .latest_block(1000)
            .logs_error(range(500, 1000))
            .logs_empty(range(900, 1000))
            .run(EventBlockOptions::default())
            .await
            .unwrap();
        assert_eq!(res, None);
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_fallback_suppressed_with_block_option() {
        // A caller-supplied block option must be used as-is: on error there is no
        // fallback retry (a second get_logs call would fail the mock's times(1)).
        let res = LookupTest::new()
            .distances(None, Some(100))
            .logs_error(range(100, 200))
            .run(EventBlockOptions {
                block_option: Some(range(100, 200)),
                max_block_range: None,
            })
            .await;
        assert!(res.is_err(), "expected the provider error to propagate");
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_fallback_capped_by_max_block_range() {
        // The per-request max (50) bounds the primary window; the fallback retry (a
        // larger configured 80) must be capped to it as well.
        let res = LookupTest::new()
            .distances(None, Some(80))
            .latest_block(1000)
            .logs_error_then_empty(range(950, 1000))
            .run(EventBlockOptions {
                block_option: None,
                max_block_range: Some(50),
            })
            .await
            .unwrap();
        assert_eq!(res, None);
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_empty_range_treated_as_omitted() {
        // An empty range `{}` carries no information: the default search window must be
        // used, not the node's getLogs defaults.
        let res = LookupTest::new()
            .distances(Some(100), None)
            .latest_block(1000)
            .logs_empty(range(900, 1000))
            .run(EventBlockOptions {
                block_option: Some(FilterBlockOption::Range {
                    from_block: None,
                    to_block: None,
                }),
                max_block_range: None,
            })
            .await
            .unwrap();
        assert_eq!(res, None);
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
        create_api_with_event_distances(
            provider,
            ep,
            pool,
            gas_estimator,
            permissions_enabled,
            None,
            None,
        )
    }

    fn create_api_with_event_distances(
        provider: MockEvmProvider,
        ep: MockEntryPointV0_6,
        pool: MockPool,
        gas_estimator: MockGasEstimator,
        permissions_enabled: bool,
        event_block_distance: Option<u64>,
        event_block_distance_fallback: Option<u64>,
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
                    event_block_distance,
                    event_block_distance_fallback,
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
