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

use ethers::{
    types::{spoof, Address, H256, U64},
    utils::to_checksum,
};
use futures_util::future;
use rundler_pool::PoolServer;
use rundler_types::{chain::ChainSpec, UserOperationOptionalGas, UserOperationVariant};
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

pub(crate) struct EthApi<PS>
where
    PS: PoolServer,
{
    chain_spec: ChainSpec,
    pool: PS,
    router: EntryPointRouter,
}

impl<PS> EthApi<PS>
where
    PS: PoolServer,
{
    pub(crate) fn new(chain_spec: ChainSpec, router: EntryPointRouter, pool: PS) -> Self {
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
    ) -> EthResult<H256> {
        self.router.check_and_get_route(&entry_point, &op)?;

        self.pool
            .add_op(entry_point, op)
            .await
            .map_err(EthRpcError::from)
            .log_on_error_level(Level::DEBUG, "failed to add op to the mempool")
    }

    pub(crate) async fn estimate_user_operation_gas(
        &self,
        uo: UserOperationOptionalGas,
        entry_point: Address,
        state_override: Option<spoof::State>,
    ) -> EthResult<RpcGasEstimate> {
        self.router
            .estimate_gas(&entry_point, uo, state_override)
            .await
    }

    pub(crate) async fn get_user_operation_by_hash(
        &self,
        hash: H256,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        if hash == H256::zero() {
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
        hash: H256,
    ) -> EthResult<Option<RpcUserOperationReceipt>> {
        if hash == H256::zero() {
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
            .map(|ep| to_checksum(ep, None))
            .collect())
    }

    pub(crate) async fn chain_id(&self) -> EthResult<U64> {
        Ok(self.chain_spec.id.into())
    }

    async fn get_pending_user_operation_by_hash(
        &self,
        hash: H256,
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

    use ethers::{
        abi::AbiEncode,
        types::{Bytes, Log, Transaction},
    };
    use mockall::predicate::eq;
    use rundler_pool::{IntoPoolOperationVariant, MockPoolServer, PoolOperation};
    use rundler_provider::{MockEntryPoint, MockEntryPointV0_6, MockProvider};
    use rundler_sim::{EntityInfos, PriorityFeeMode};
    use rundler_types::{
        contracts::v0_6::i_entry_point::{HandleOpsCall, IEntryPointCalls},
        v0_6::UserOperation,
        UserOperation as UserOperationTrait, ValidTimeRange,
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
            uo: uo.clone(),
            entry_point: ep,
            aggregator: None,
            valid_time_range: ValidTimeRange::default(),
            expected_code_hash: H256::random(),
            sim_block_hash: H256::random(),
            sim_block_number: 1000,
            entities_needing_stake: vec![],
            account_is_staked: false,
            entity_infos: EntityInfos::default(),
        };

        let mut pool = MockPoolServer::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(Some(po.clone().into_variant())));

        let mut provider = MockProvider::default();
        provider.expect_get_logs().returning(move |_| Ok(vec![]));
        provider.expect_get_block_number().returning(|| Ok(1000));

        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool);
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
        let ep = Address::random();
        let uo = UserOperation::default();
        let hash = uo.hash(ep, 1);
        let block_number = 1000;
        let block_hash = H256::random();

        let mut pool = MockPoolServer::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .returning(move |_| Ok(None));

        let mut provider = MockProvider::default();
        provider.expect_get_block_number().returning(|| Ok(1000));

        let tx_data: Bytes = IEntryPointCalls::HandleOps(HandleOpsCall {
            beneficiary: Address::zero(),
            ops: vec![uo.clone()],
        })
        .encode()
        .into();
        let tx = Transaction {
            to: Some(ep),
            input: tx_data,
            block_number: Some(block_number.into()),
            block_hash: Some(block_hash),
            ..Default::default()
        };
        let tx_hash = tx.hash();
        let log = Log {
            address: ep,
            transaction_hash: Some(tx_hash),
            ..Default::default()
        };

        provider
            .expect_get_logs()
            .returning(move |_| Ok(vec![log.clone()]));
        provider
            .expect_get_transaction()
            .with(eq(tx_hash))
            .returning(move |_| Ok(Some(tx.clone())));

        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool);
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        let ro = RpcUserOperationByHash {
            user_operation: UserOperationVariant::from(uo).into(),
            entry_point: ep.into(),
            block_number: Some(block_number.into()),
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

        let mut pool = MockPoolServer::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(None));

        let mut provider = MockProvider::default();
        provider.expect_get_logs().returning(move |_| Ok(vec![]));
        provider.expect_get_block_number().returning(|| Ok(1000));

        let mut entry_point = MockEntryPointV0_6::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool);
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        assert_eq!(res, None);
    }

    fn create_api(
        provider: MockProvider,
        ep: MockEntryPointV0_6,
        pool: MockPoolServer,
    ) -> EthApi<MockPoolServer> {
        let provider = Arc::new(provider);
        let chain_spec = ChainSpec {
            id: 1,
            ..Default::default()
        };
        contexts_by_entry_point
            .insert(
                ep.address(),
                EntryPointContext::new(
                    chain_spec.clone(),
                    Arc::clone(&provider),
                    ep,
                    EstimationSettings {
                        max_verification_gas: 1_000_000,
                        max_call_gas: 1_000_000,
                        max_simulate_handle_ops_gas: 1_000_000,
                        verification_estimation_gas_fee: 1_000_000_000_000,
                    },
                    FeeEstimator::new(
                        &chain_spec,
                        Arc::clone(&provider),
                        PriorityFeeMode::BaseFeePercent(0),
                        0,
                    ),
                    UserOperationEventProviderV0_6::new(
                        chain_spec.id,
                        ep.address(),
                        provider.clone(),
                        None,
                    ),
                ),
            )
            .build();

        EthApi {
            router,
            chain_spec,
            pool,
        }
    }
}
