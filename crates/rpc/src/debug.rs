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

use std::time::Duration;

use alloy_primitives::{Address, B256, U64};
use anyhow::Context;
use async_trait::async_trait;
use futures_util::StreamExt;
use jsonrpsee::{Extensions, core::RpcResult, proc_macros::rpc};
use rundler_types::{
    builder::{Builder, BuilderError, BundlingMode},
    pool::Pool,
};

use crate::{
    chain_resolver::ChainResolver,
    types::{
        RpcDebugPaymasterBalance, RpcReputationInput, RpcReputationOutput, RpcStakeInfo,
        RpcStakeStatus, RpcUserOperation,
    },
    utils::{self, InternalRpcError, InternalRpcResult},
};

/// Debug API
#[rpc(client, server, namespace = "debug")]
pub trait DebugApi {
    /// Clears the state of the pool.
    #[method(name = "bundler_clearState", with_extensions)]
    async fn bundler_clear_state(&self) -> RpcResult<String>;

    /// Clears the state of the mempool without affect reputations.
    #[method(name = "bundler_clearMempool", with_extensions)]
    async fn bundler_clear_mempool(&self) -> RpcResult<String>;

    /// Dumps the mempool.
    #[method(name = "bundler_dumpMempool", with_extensions)]
    async fn bundler_dump_mempool(&self, entry_point: Address) -> RpcResult<Vec<RpcUserOperation>>;

    /// Triggers the builder to send a bundle now
    ///
    /// Note that the bundling mode must be set to `Manual` else this will fail.
    #[method(name = "bundler_sendBundleNow", with_extensions)]
    async fn bundler_send_bundle_now(&self) -> RpcResult<B256>;

    /// Sets the bundling mode.
    #[method(name = "bundler_setBundlingMode", with_extensions)]
    async fn bundler_set_bundling_mode(&self, mode: BundlingMode) -> RpcResult<String>;

    /// Sets the reputations of entities on the given entry point.
    #[method(name = "bundler_setReputation", with_extensions)]
    async fn bundler_set_reputation(
        &self,
        reputations: Vec<RpcReputationInput>,
        entry_point: Address,
    ) -> RpcResult<String>;

    /// Dumps the reputations of entities from the given entry point.
    #[method(name = "bundler_dumpReputation", with_extensions)]
    async fn bundler_dump_reputation(
        &self,
        entry_point: Address,
    ) -> RpcResult<Vec<RpcReputationOutput>>;

    /// Returns stake status given an address and entrypoint
    #[method(name = "bundler_getStakeStatus", with_extensions)]
    async fn bundler_get_stake_status(
        &self,
        address: Address,
        entry_point: Address,
    ) -> RpcResult<RpcStakeStatus>;

    /// Dumps the paymaster balance cache
    #[method(name = "bundler_dumpPaymasterBalances", with_extensions)]
    async fn bundler_dump_paymaster_balances(
        &self,
        entry_point: Address,
    ) -> RpcResult<Vec<RpcDebugPaymasterBalance>>;

    /// Clear the reputations of pool.
    #[method(name = "bundler_clearReputation", with_extensions)]
    async fn bundler_clear_reputation(&self) -> RpcResult<String>;
}

pub(crate) struct DebugApi<R> {
    resolver: R,
}

impl<R> DebugApi<R> {
    pub(crate) fn new(resolver: R) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl<R> DebugApiServer for DebugApi<R>
where
    R: ChainResolver,
{
    async fn bundler_clear_state(&self, ext: &Extensions) -> RpcResult<String> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "bundler_clearState",
            Self::bundler_clear_state_inner(chain.pool),
        )
        .await
    }

    async fn bundler_clear_mempool(&self, ext: &Extensions) -> RpcResult<String> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "bundler_clearMempool",
            Self::bundler_clear_mempool_inner(chain.pool),
        )
        .await
    }

    async fn bundler_dump_mempool(
        &self,
        ext: &Extensions,
        entry_point: Address,
    ) -> RpcResult<Vec<RpcUserOperation>> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "bundler_dumpMempool",
            Self::bundler_dump_mempool_inner(chain.pool, entry_point),
        )
        .await
    }

    async fn bundler_send_bundle_now(&self, ext: &Extensions) -> RpcResult<B256> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "bundler_sendBundleNow",
            Self::bundler_send_bundle_now_inner(chain.pool, chain.builder),
        )
        .await
    }

    async fn bundler_set_bundling_mode(
        &self,
        ext: &Extensions,
        mode: BundlingMode,
    ) -> RpcResult<String> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "bundler_setBundlingMode",
            Self::bundler_set_bundling_mode_inner(chain.builder, mode),
        )
        .await
    }

    async fn bundler_set_reputation(
        &self,
        ext: &Extensions,
        reputations: Vec<RpcReputationInput>,
        entry_point: Address,
    ) -> RpcResult<String> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "bundler_setReputation",
            Self::bundler_set_reputation_inner(chain.pool, reputations, entry_point),
        )
        .await
    }

    async fn bundler_dump_reputation(
        &self,
        ext: &Extensions,
        entry_point: Address,
    ) -> RpcResult<Vec<RpcReputationOutput>> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "bundler_dumpReputation",
            Self::bundler_dump_reputation_inner(chain.pool, entry_point),
        )
        .await
    }

    async fn bundler_get_stake_status(
        &self,
        ext: &Extensions,
        address: Address,
        entry_point: Address,
    ) -> RpcResult<RpcStakeStatus> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "bundler_getStakeStatus",
            Self::bundler_get_stake_status_inner(chain.pool, address, entry_point),
        )
        .await
    }

    async fn bundler_dump_paymaster_balances(
        &self,
        ext: &Extensions,
        entry_point: Address,
    ) -> RpcResult<Vec<RpcDebugPaymasterBalance>> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "bundler_dumpPaymasterBalances",
            Self::bundler_dump_paymaster_balances_inner(chain.pool, entry_point),
        )
        .await
    }

    async fn bundler_clear_reputation(&self, ext: &Extensions) -> RpcResult<String> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "bundler_clearReputation",
            Self::bundler_clear_reputation_inner(chain.pool),
        )
        .await
    }
}

impl<R> DebugApi<R> {
    async fn bundler_clear_state_inner(pool: &dyn Pool) -> InternalRpcResult<String> {
        pool.debug_clear_state(true, true, true)
            .await
            .context("should clear state")?;

        Ok("ok".to_string())
    }

    async fn bundler_clear_mempool_inner(pool: &dyn Pool) -> InternalRpcResult<String> {
        pool.debug_clear_state(true, true, false)
            .await
            .context("should clear mempool")?;

        Ok("ok".to_string())
    }

    async fn bundler_dump_mempool_inner(
        pool: &dyn Pool,
        entry_point: Address,
    ) -> InternalRpcResult<Vec<RpcUserOperation>> {
        Ok(pool
            .debug_dump_mempool(entry_point)
            .await
            .context("should dump mempool")?
            .into_iter()
            .map(|pop| pop.uo.into())
            .collect::<Vec<RpcUserOperation>>())
    }

    async fn bundler_send_bundle_now_inner(
        pool: &dyn Pool,
        builder: &dyn Builder,
    ) -> InternalRpcResult<B256> {
        tracing::debug!("Sending bundle");

        let mut new_heads = pool
            .subscribe_new_heads(vec![])
            .await
            .context("should subscribe new heads")?;

        // send bundle now, retrying a few times if no operations are available
        let (tx, block_number) = {
            let mut out = None;
            for _ in 0..3 {
                match builder.debug_send_bundle_now().await {
                    Ok((tx, block_number)) => {
                        out = Some((tx, block_number));
                        break;
                    }
                    Err(BuilderError::NoOperationsToSend) => {
                        tracing::info!("No ops to send, retrying after 1 second");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    Err(e) => {
                        tracing::error!("Error sending bundle {e:?}");
                        return Err::<_, InternalRpcError>(anyhow::anyhow!(e).into());
                    }
                }
            }
            Ok::<_, InternalRpcError>(out.unwrap_or((B256::ZERO, 0)))
        }?;

        if tx == B256::ZERO {
            return Ok(B256::ZERO);
        }

        tracing::debug!("Waiting for block number {block_number}");

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

    async fn bundler_set_bundling_mode_inner(
        builder: &dyn Builder,
        mode: BundlingMode,
    ) -> InternalRpcResult<String> {
        tracing::debug!("Setting bundling mode to {:?}", mode);

        builder
            .debug_set_bundling_mode(mode)
            .await
            .context("should set bundling mode")?;

        Ok("ok".to_string())
    }

    async fn bundler_set_reputation_inner(
        pool: &dyn Pool,
        reputations: Vec<RpcReputationInput>,
        entry_point: Address,
    ) -> InternalRpcResult<String> {
        let _ = pool
            .debug_set_reputations(
                entry_point,
                reputations.into_iter().map(Into::into).collect(),
            )
            .await;

        Ok("ok".to_string())
    }

    async fn bundler_dump_reputation_inner(
        pool: &dyn Pool,
        entry_point: Address,
    ) -> InternalRpcResult<Vec<RpcReputationOutput>> {
        let result = pool
            .debug_dump_reputation(entry_point)
            .await
            .context("should dump reputation")?;

        let mut results = Vec::new();
        for r in result {
            let status = pool
                .get_reputation_status(entry_point, r.address)
                .await
                .context("should get reputation status")?;

            let reputation = RpcReputationOutput {
                address: r.address,
                ops_seen: U64::from(r.ops_seen),
                ops_included: U64::from(r.ops_included),
                status: U64::from(status as u64),
            };

            results.push(reputation);
        }

        Ok(results)
    }

    async fn bundler_get_stake_status_inner(
        pool: &dyn Pool,
        address: Address,
        entry_point: Address,
    ) -> InternalRpcResult<RpcStakeStatus> {
        let result = pool
            .get_stake_status(entry_point, address)
            .await
            .context("should get stake status")?;

        Ok(RpcStakeStatus {
            is_staked: result.is_staked,
            stake_info: RpcStakeInfo {
                addr: address,
                stake: result
                    .stake_info
                    .stake
                    .try_into()
                    .context("stake should fit in u128")?,
                unstake_delay_sec: result.stake_info.unstake_delay_sec,
            },
        })
    }

    async fn bundler_dump_paymaster_balances_inner(
        pool: &dyn Pool,
        entry_point: Address,
    ) -> InternalRpcResult<Vec<RpcDebugPaymasterBalance>> {
        let result = pool
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

    async fn bundler_clear_reputation_inner(pool: &dyn Pool) -> InternalRpcResult<String> {
        pool.debug_clear_state(false, false, true)
            .await
            .context("should clear reputation")?;

        Ok("ok".to_string())
    }
}
