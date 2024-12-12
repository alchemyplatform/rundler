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
use rundler_provider::StateOverride;
use rundler_types::{
    chain::ChainSpec, pool::Pool, UserOperation, UserOperationOptionalGas, UserOperationVariant,
};
use rundler_utils::log::LogOnError;
use tracing::Level;

use super::{
    error::{EthResult, EthRpcError},
    router::EntryPointRouter,
};
use crate::types::{RpcGasEstimate, RpcUserOperationByHash, RpcUserOperationReceipt};

/// Settings for the `eth_` API
#[derive(Copy, Clone, Debug)]
pub struct Settings {
    /// The number of blocks to look back for user operation events
    pub user_operation_event_block_distance: Option<u64>,
}

impl Settings {
    /// Create new settings for the `eth_` API
    pub fn new(block_distance: Option<u64>) -> Self {
        Self {
            user_operation_event_block_distance: block_distance,
        }
    }
}

pub(crate) struct EthApi<P> {
    pub(crate) chain_spec: ChainSpec,
    pool: P,
    router: EntryPointRouter,
}

impl<P> EthApi<P>
where
    P: Pool,
{
    pub(crate) fn new(chain_spec: ChainSpec, router: EntryPointRouter, pool: P) -> Self {
        Self {
            router,
            pool,
            chain_spec,
        }
    }

    pub(crate) async fn send_user_operation(
        &self,
        op: UserOperationVariant,
        entry_point: Address,
    ) -> EthResult<B256> {
        let bundle_size = op.single_uo_bundle_size_bytes();
        if bundle_size > self.chain_spec.max_transaction_size_bytes {
            return Err(EthRpcError::InvalidParams(format!(
                "User operation in bundle size {} exceeds max transaction size {}",
                bundle_size, self.chain_spec.max_transaction_size_bytes
            )));
        }

        self.router.check_and_get_route(&entry_point, &op)?;

        self.pool
            .add_op(entry_point, op)
            .await
            .map_err(EthRpcError::from)
            .log_on_error_level(Level::DEBUG, "failed to add op to the mempool")
    }

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

        self.router
            .estimate_gas(&entry_point, op, state_override)
            .await
    }

    pub(crate) async fn get_user_operation_by_hash(
        &self,
        hash: B256,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        if hash == B256::ZERO {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        // check both entry points and pending for the user operation event
        #[allow(clippy::type_complexity)]
        let mut futs: Vec<
            Pin<Box<dyn Future<Output = EthResult<Option<RpcUserOperationByHash>>> + Send>>,
        > = vec![];

        for ep in self.router.entry_points() {
            futs.push(Box::pin(self.router.get_mined_by_hash(ep, hash)));
        }
        futs.push(Box::pin(self.get_pending_user_operation_by_hash(hash)));

        let results = future::try_join_all(futs).await?;
        Ok(results.into_iter().find_map(|x| x))
    }

    pub(crate) async fn get_user_operation_receipt(
        &self,
        hash: B256,
    ) -> EthResult<Option<RpcUserOperationReceipt>> {
        if hash == B256::ZERO {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        let futs = self
            .router
            .entry_points()
            .map(|ep| self.router.get_receipt(ep, hash));

        let results = future::try_join_all(futs).await?;
        Ok(results.into_iter().find_map(|x| x))
    }

    pub(crate) async fn supported_entry_points(&self) -> EthResult<Vec<String>> {
        Ok(self
            .router
            .entry_points()
            .map(|ep| ep.to_checksum(None))
            .collect())
    }

    pub(crate) async fn chain_id(&self) -> EthResult<U64> {
        Ok(U64::from(self.chain_spec.id))
    }

    async fn get_pending_user_operation_by_hash(
        &self,
        hash: B256,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        let res = self
            .pool
            .get_op_by_hash(hash)
            .await
            .map_err(EthRpcError::from)?;

        Ok(res.map(|op| RpcUserOperationByHash {
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

    use alloy_consensus::{Signed, TxEip1559, TxEnvelope::Eip1559};
    use alloy_primitives::{Log as PrimitiveLog, LogData, PrimitiveSignature, TxKind, U256};
    use alloy_sol_types::SolInterface;
    use mockall::predicate::eq;
    use rundler_contracts::v0_6::IEntryPoint::{handleOpsCall, IEntryPointCalls};
    use rundler_provider::{Log, MockEntryPointV0_6, MockEvmProvider, Transaction};
    use rundler_sim::MockGasEstimator;
    use rundler_types::{
        pool::{MockPool, PoolOperation},
        v0_6::UserOperation,
        EntityInfos, UserOperation as UserOperationTrait, ValidTimeRange,
    };

    use super::*;
    use crate::eth::{
        EntryPointRouteImpl, EntryPointRouterBuilder, UserOperationEventProviderV0_6,
    };

    #[tokio::test]
    async fn test_get_user_op_by_hash_pending() {
        let ep = Address::random();
        let uo = UserOperation::default();
        let hash = uo.hash(ep, 1);

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
            da_gas_data: rundler_types::da::DAGasUOData::Empty,
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

        let api = create_api(provider, entry_point, pool, MockGasEstimator::default());
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
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
        let uo = UserOperation::default();
        let hash = uo.hash(ep, 1);
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

        let inner = Eip1559(Signed::new_unchecked(
            inner_txn,
            PrimitiveSignature::test_signature(),
            hash,
        ));
        let tx = Transaction {
            inner,
            block_hash: Some(block_hash),
            block_number: Some(block_number),
            transaction_index: None,
            effective_gas_price: None,
            from: Address::default(),
        };

        let tx_hash = *tx.inner.tx_hash();
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

        let api = create_api(provider, entry_point, pool, MockGasEstimator::default());
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
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
        let ep = Address::random();
        let uo = UserOperation::default();
        let hash = uo.hash(ep, 1);

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

        let api = create_api(provider, entry_point, pool, MockGasEstimator::default());
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        assert_eq!(res, None);
    }

    fn create_api(
        provider: MockEvmProvider,
        ep: MockEntryPointV0_6,
        pool: MockPool,
        gas_estimator: MockGasEstimator,
    ) -> EthApi<MockPool> {
        let ep = Arc::new(ep);
        let provider = Arc::new(provider);
        let chain_spec = ChainSpec {
            id: 1,
            ..Default::default()
        };

        let router = EntryPointRouterBuilder::default()
            .v0_6(EntryPointRouteImpl::new(
                ep.clone(),
                gas_estimator,
                UserOperationEventProviderV0_6::new(chain_spec.clone(), provider.clone(), None),
            ))
            .build();

        EthApi {
            router,
            chain_spec,
            pool,
        }
    }
}
