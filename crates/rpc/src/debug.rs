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

use anyhow::Context;
use async_trait::async_trait;
use ethers::types::{Address, H256};
use futures_util::StreamExt;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use rundler_types::{
    builder::{Builder, BundlingMode},
    pool::Pool,
};

use crate::{
    types::{
        RpcDebugPaymasterBalance, RpcReputationInput, RpcReputationOutput, RpcStakeInfo,
        RpcStakeStatus, RpcUserOperation,
    },
    utils::{self, InternalRpcResult},
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
        address: Address,
        entry_point: Address,
    ) -> RpcResult<RpcStakeStatus>;

    /// Dumps the paymaster balance cache
    #[method(name = "bundler_dumpPaymasterBalances")]
    async fn bundler_dump_paymaster_balances(
        &self,
        entry_point: Address,
    ) -> RpcResult<Vec<RpcDebugPaymasterBalance>>;
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
    P: Pool,
    B: Builder,
{
    async fn bundler_clear_state(&self) -> RpcResult<String> {
        utils::safe_call_rpc_handler("bundler_clearState", DebugApi::bundler_clear_state(self))
            .await
    }

    async fn bundler_clear_mempool(&self) -> RpcResult<String> {
        utils::safe_call_rpc_handler(
            "bundler_clearMempool",
            DebugApi::bundler_clear_mempool(self),
        )
        .await
    }

    async fn bundler_dump_mempool(&self, entry_point: Address) -> RpcResult<Vec<RpcUserOperation>> {
        utils::safe_call_rpc_handler(
            "bundler_dumpMempool",
            DebugApi::bundler_dump_mempool(self, entry_point),
        )
        .await
    }

    async fn bundler_send_bundle_now(&self) -> RpcResult<H256> {
        utils::safe_call_rpc_handler(
            "bundler_sendBundleNow",
            DebugApi::bundler_send_bundle_now(self),
        )
        .await
    }

    async fn bundler_set_bundling_mode(&self, mode: BundlingMode) -> RpcResult<String> {
        utils::safe_call_rpc_handler(
            "bundler_setBundlingMode",
            DebugApi::bundler_set_bundling_mode(self, mode),
        )
        .await
    }

    async fn bundler_set_reputation(
        &self,
        reputations: Vec<RpcReputationInput>,
        entry_point: Address,
    ) -> RpcResult<String> {
        utils::safe_call_rpc_handler(
            "bundler_setReputation",
            DebugApi::bundler_set_reputation(self, reputations, entry_point),
        )
        .await
    }

    async fn bundler_dump_reputation(
        &self,
        entry_point: Address,
    ) -> RpcResult<Vec<RpcReputationOutput>> {
        utils::safe_call_rpc_handler(
            "bundler_dumpReputation",
            DebugApi::bundler_dump_reputation(self, entry_point),
        )
        .await
    }

    async fn bundler_get_stake_status(
        &self,
        address: Address,
        entry_point: Address,
    ) -> RpcResult<RpcStakeStatus> {
        utils::safe_call_rpc_handler(
            "bundler_getStakeStatus",
            DebugApi::bundler_get_stake_status(self, address, entry_point),
        )
        .await
    }

    async fn bundler_dump_paymaster_balances(
        &self,
        entry_point: Address,
    ) -> RpcResult<Vec<RpcDebugPaymasterBalance>> {
        utils::safe_call_rpc_handler(
            "bundler_dumpPaymasterBalances",
            DebugApi::bundler_dump_paymaster_balances(self, entry_point),
        )
        .await
    }
}

impl<P, B> DebugApi<P, B>
where
    P: Pool,
    B: Builder,
{
    async fn bundler_clear_state(&self) -> InternalRpcResult<String> {
        self.pool
            .debug_clear_state(true, true, true)
            .await
            .context("should clear state")?;

        Ok("ok".to_string())
    }

    async fn bundler_clear_mempool(&self) -> InternalRpcResult<String> {
        self.pool
            .debug_clear_state(true, true, false)
            .await
            .context("should clear mempool")?;

        Ok("ok".to_string())
    }

    async fn bundler_dump_mempool(
        &self,
        entry_point: Address,
    ) -> InternalRpcResult<Vec<RpcUserOperation>> {
        Ok(self
            .pool
            .debug_dump_mempool(entry_point)
            .await
            .context("should dump mempool")?
            .into_iter()
            .map(|pop| pop.uo.into())
            .collect::<Vec<RpcUserOperation>>())
    }

    async fn bundler_send_bundle_now(&self) -> InternalRpcResult<H256> {
        tracing::debug!("Sending bundle");

        let mut new_heads = self
            .pool
            .subscribe_new_heads()
            .await
            .context("should subscribe new heads")?;

        let (tx, block_number) = self.builder.debug_send_bundle_now().await.map_err(|e| {
            tracing::error!("Error sending bundle {e:?}");
            anyhow::anyhow!(e)
        })?;

        tracing::debug!("Waiting for block number {block_number}");

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
                    Err(anyhow::anyhow!("Next block not available"))?;
                }
            }
        }

        Ok(tx)
    }

    async fn bundler_set_bundling_mode(&self, mode: BundlingMode) -> InternalRpcResult<String> {
        tracing::debug!("Setting bundling mode to {:?}", mode);

        self.builder
            .debug_set_bundling_mode(mode)
            .await
            .context("should set bundling mode")?;

        Ok("ok".to_string())
    }

    async fn bundler_set_reputation(
        &self,
        reputations: Vec<RpcReputationInput>,
        entry_point: Address,
    ) -> InternalRpcResult<String> {
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
    ) -> InternalRpcResult<Vec<RpcReputationOutput>> {
        let result = self
            .pool
            .debug_dump_reputation(entry_point)
            .await
            .context("should dump reputation")?;

        let mut results = Vec::new();
        for r in result {
            let status = self
                .pool
                .get_reputation_status(entry_point, r.address)
                .await
                .context("should get reputation status")?;

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
    ) -> InternalRpcResult<RpcStakeStatus> {
        let result = self
            .pool
            .get_stake_status(entry_point, address)
            .await
            .context("should get stake status")?;

        Ok(RpcStakeStatus {
            is_staked: result.is_staked,
            stake_info: RpcStakeInfo {
                addr: address,
                stake: result.stake_info.stake.as_u128(),
                unstake_delay_sec: result.stake_info.unstake_delay_sec.as_u32(),
            },
        })
    }

    async fn bundler_dump_paymaster_balances(
        &self,
        entry_point: Address,
    ) -> InternalRpcResult<Vec<RpcDebugPaymasterBalance>> {
        let result = self
            .pool
            .debug_dump_paymaster_balances(entry_point)
            .await
            .context("should dump paymaster balances")?;

        let mut results = Vec::new();
        for b in result {
            let balance = RpcDebugPaymasterBalance {
                address: b.address,
                pending_balance: b.pending_balance,
                confirmed_balance: b.confirmed_balance,
            };

            results.push(balance);
        }

        Ok(results)
    }
}
