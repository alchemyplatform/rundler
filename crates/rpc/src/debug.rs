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

use async_trait::async_trait;
use ethers::types::{Address, H256};
use futures_util::StreamExt;
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::error::INTERNAL_ERROR_CODE};
use rundler_builder::{BuilderServer, BundlingMode};
use rundler_pool::PoolServer;

use crate::{
    error::rpc_err,
    types::{
        RpcReputationInput, RpcReputationOutput, RpcStakeInfo, RpcStakeStatus, RpcUserOperation,
    },
};

/// Debug API
#[rpc(client, server, namespace = "debug")]
pub trait DebugApi {
    /// Clears the state of the pool.
    #[method(name = "bundler_clearState")]
    async fn bundler_clear_state(&self) -> RpcResult<String>;

    /// Clears the state of the mempool without affect reputations.
    #[method(name = "bundler_clearMempool")]
    async fn bundler_clear_mempool(&self) -> RpcResult<String>;

    /// Dumps the mempool.
    #[method(name = "bundler_dumpMempool")]
    async fn bundler_dump_mempool(&self, entry_point: Address) -> RpcResult<Vec<RpcUserOperation>>;

    /// Triggers the builder to send a bundle now
    ///
    /// Note that the bundling mode must be set to `Manual` else this will fail.
    #[method(name = "bundler_sendBundleNow")]
    async fn bundler_send_bundle_now(&self) -> RpcResult<H256>;

    /// Sets the bundling mode.
    #[method(name = "bundler_setBundlingMode")]
    async fn bundler_set_bundling_mode(&self, mode: BundlingMode) -> RpcResult<String>;

    /// Sets the reputations of entities on the given entry point.
    #[method(name = "bundler_setReputation")]
    async fn bundler_set_reputation(
        &self,
        reputations: Vec<RpcReputationInput>,
        entry_point: Address,
    ) -> RpcResult<String>;

    /// Dumps the reputations of entities from the given entry point.
    #[method(name = "bundler_dumpReputation")]
    async fn bundler_dump_reputation(
        &self,
        entry_point: Address,
    ) -> RpcResult<Vec<RpcReputationOutput>>;

    /// Returns stake status given an address and entrypoint
    #[method(name = "bundler_getStakeStatus")]
    async fn bundler_get_stake_status(
        &self,
        entry_point: Address,
        address: Address,
    ) -> RpcResult<RpcStakeStatus>;
}

pub(crate) struct DebugApi<P, B> {
    pool: P,
    builder: B,
}

impl<P, B> DebugApi<P, B> {
    pub(crate) fn new(pool: P, builder: B) -> Self {
        Self { pool, builder }
    }
}

#[async_trait]
impl<P, B> DebugApiServer for DebugApi<P, B>
where
    P: PoolServer,
    B: BuilderServer,
{
    async fn bundler_clear_state(&self) -> RpcResult<String> {
        let _ = self
            .pool
            .debug_clear_state(true, true)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        Ok("ok".to_string())
    }

    async fn bundler_clear_mempool(&self) -> RpcResult<String> {
        let _ = self
            .pool
            .debug_clear_state(true, false)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        Ok("ok".to_string())
    }

    async fn bundler_clear_mempool(&self) -> RpcResult<String> {
        let _ = self
            .pool
            .debug_clear_mempool()
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        Ok("ok".to_string())
    }

    async fn bundler_dump_mempool(&self, entry_point: Address) -> RpcResult<Vec<RpcUserOperation>> {
        Ok(self
            .pool
            .debug_dump_mempool(entry_point)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?
            .into_iter()
            .map(|pop| pop.uo.into())
            .collect::<Vec<RpcUserOperation>>())
    }

    async fn bundler_send_bundle_now(&self) -> RpcResult<H256> {
        let mut new_heads = self
            .pool
            .subscribe_new_heads()
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        let (tx, block_number) = self
            .builder
            .debug_send_bundle_now()
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        // After the bundle is sent, we need to make sure that the mempool
        // has processes the same block that the transaction was mined on.
        // This removes the potential for an incorrect response from `debug_bundler_dumpMempool`
        // method.
        loop {
            match new_heads.next().await {
                Some(b) => {
                    if b.block_number.eq(&block_number) {
                        break;
                    }
                }
                None => {
                    return Err(rpc_err(INTERNAL_ERROR_CODE, "Next block not available"));
                }
            }
        }

        Ok(tx)
    }

    async fn bundler_set_bundling_mode(&self, mode: BundlingMode) -> RpcResult<String> {
        self.builder
            .debug_set_bundling_mode(mode)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        Ok("ok".to_string())
    }

    async fn bundler_set_reputation(
        &self,
        reputations: Vec<RpcReputationInput>,
        entry_point: Address,
    ) -> RpcResult<String> {
        let _ = self
            .pool
            .debug_set_reputations(
                entry_point,
                reputations.into_iter().map(Into::into).collect(),
            )
            .await;

        Ok("ok".to_string())
    }

    async fn bundler_dump_reputation(
        &self,
        entry_point: Address,
    ) -> RpcResult<Vec<RpcReputationOutput>> {
        let result = self
            .pool
            .debug_dump_reputation(entry_point)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        let mut results = Vec::new();
        for r in result {
            let status = self
                .pool
                .get_reputation_status(entry_point, r.address)
                .await
                .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

            let reputation = RpcReputationOutput {
                address: r.address,
                ops_seen: r.ops_seen.into(),
                ops_included: r.ops_included.into(),
                status,
            };

            results.push(reputation);
        }

        Ok(results)
    }

    async fn bundler_get_stake_status(
        &self,
        address: Address,
        entry_point: Address,
    ) -> RpcResult<RpcStakeStatus> {
        let result = self
            .pool
            .get_stake_status(entry_point, address)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        Ok(RpcStakeStatus {
            is_staked: result.is_staked,
            stake_info: RpcStakeInfo {
                addr: address,
                stake: result.stake_info.stake,
                unstake_delay_sec: result.stake_info.unstake_delay_sec,
            },
        })
    }
}
