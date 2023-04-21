use std::sync::Arc;

use ethers::types::{H256, U256};
#[cfg(test)]
use mockall::automock;
use tokio::try_join;
use tonic::async_trait;

use crate::{
    common::types::{EntryPointLike, ProviderLike, UserOperation},
    rpc::{GasEstimate, UserOperationOptionalGas},
};

/// Gas estimates will be rounded up to the next multiple of this. Increasing
/// this value reduces the number of rounds of `eth_call` needed in binary
/// search, e.g. a value of 1024 means ten fewer `eth_call`s needed for each of
/// verification gas and call gas.
const GAS_ROUNDING: u64 = 1024;

const GAS_BUFFER_PERCENT: u64 = 10;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait GasEstimator: Send + Sync + 'static {
    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
    ) -> anyhow::Result<Result<GasEstimate, String>>;
}

#[derive(Debug)]
pub struct GasEstimatorImpl<P: ProviderLike, E: EntryPointLike> {
    provider: Arc<P>,
    entry_point: E,
    settings: Settings,
}

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub max_verification_gas: u64,
    pub max_call_gas: u64,
}

#[async_trait]
impl<P: ProviderLike, E: EntryPointLike> GasEstimator for GasEstimatorImpl<P, E> {
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
    ) -> anyhow::Result<Result<GasEstimate, String>> {
        let Self {
            provider,
            entry_point,
            settings,
        } = self;
        let pre_verification_gas = op.calc_pre_verification_gas(settings);
        // Try once with max gas to make sure it's possible to succeed.
        let op = UserOperation {
            pre_verification_gas,
            verification_gas_limit: settings.max_verification_gas.into(),
            call_gas_limit: settings.max_call_gas.into(),
            ..op.into_user_operation(settings)
        };
        let block_hash = provider.get_latest_block_hash().await?;
        let result = entry_point.call_simulate_op(op.clone(), block_hash).await?;
        if let Err(reason) = result {
            return Ok(Err(reason));
        }
        let verification_future = self.binary_search_verification_gas(&op, block_hash);
        let call_future = self.estimate_call_gas(&op, block_hash);
        let (verification_gas_limit, call_gas_limit) = try_join!(verification_future, call_future)?;
        Ok(Ok(GasEstimate {
            pre_verification_gas,
            verification_gas_limit: (verification_gas_limit * (100 + GAS_BUFFER_PERCENT) / 100)
                .min(self.settings.max_verification_gas.into()),
            call_gas_limit: (call_gas_limit * (100 + GAS_BUFFER_PERCENT) / 100)
                .min(self.settings.max_call_gas.into()),
        }))
    }
}

impl<P: ProviderLike, E: EntryPointLike> GasEstimatorImpl<P, E> {
    pub fn new(provider: Arc<P>, entry_point: E, settings: Settings) -> Self {
        Self {
            provider,
            entry_point,
            settings,
        }
    }

    async fn binary_search_verification_gas(
        &self,
        op: &UserOperation,
        block_hash: H256,
    ) -> anyhow::Result<U256> {
        // Scale everything down by the rounding constant, then find the
        // smallest scaled number that succeeds, then scale back up.
        let mut scaled_max_failure_gas = 0;
        let mut scaled_min_success_gas = self.settings.max_verification_gas / GAS_ROUNDING;
        while scaled_min_success_gas - scaled_max_failure_gas > 1 {
            let scaled_guess = (scaled_max_failure_gas + scaled_min_success_gas) / 2;
            let guess = scaled_guess * GAS_ROUNDING;
            let op = UserOperation {
                verification_gas_limit: guess.into(),
                ..op.clone()
            };
            let is_failure = self
                .entry_point
                .call_simulate_op(op, block_hash)
                .await?
                .is_err();
            if is_failure {
                scaled_max_failure_gas = scaled_guess;
            } else {
                scaled_min_success_gas = scaled_guess;
            }
        }
        Ok((scaled_min_success_gas * GAS_ROUNDING).into())
    }

    async fn estimate_call_gas(
        &self,
        _op: &UserOperation,
        _block_hash: H256,
    ) -> anyhow::Result<U256> {
        todo!()
    }
}
