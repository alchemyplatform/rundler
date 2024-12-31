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
#![allow(dead_code)]

use std::fmt::Debug;

use futures_util::future::join_all;
use rundler_provider::{BlockNumberOrTag, EvmProvider};
use rundler_types::chain::{ChainSpec, PriorityFeeOracleType};

pub(crate) type Result<T, E = FeeOracleError> = std::result::Result<T, E>;

/// Error type for the fee oracle
#[derive(Debug, thiserror::Error)]
pub enum FeeOracleError {
    /// No oracle available, or all oracles failed
    #[error("No oracle available")]
    NoOracle,
    /// Error from the oracle
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[async_trait::async_trait]
/// FeeOracle is a trait that provides a way to estimate the priority fee
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait FeeOracle: Send + Sync {
    /// Estimate the priority fee
    async fn estimate_priority_fee(&self) -> Result<u128>;
}

/// Get a fee oracle for the given chain spec.
pub fn get_fee_oracle<'a, P>(chain_spec: &ChainSpec, provider: P) -> Box<dyn FeeOracle + 'a>
where
    P: EvmProvider + 'a,
{
    if !chain_spec.eip1559_enabled {
        return Box::new(ConstantOracle::new(0));
    }

    match chain_spec.priority_fee_oracle_type {
        PriorityFeeOracleType::Provider => Box::new(ProviderOracle::new(
            provider,
            chain_spec.min_max_priority_fee_per_gas(),
        )),
        PriorityFeeOracleType::UsageBased => {
            let config = UsageBasedFeeOracleConfig {
                minimum_fee: chain_spec.min_max_priority_fee_per_gas(),
                maximum_fee: chain_spec.max_max_priority_fee_per_gas(),
                congestion_trigger_usage_ratio_threshold: chain_spec
                    .congestion_trigger_usage_ratio_threshold,
                ..Default::default()
            };
            Box::new(UsageBasedFeeOracle::new(provider, config))
        }
    }
}

/// UsageBasedFeeOracle config
#[derive(Clone, Debug)]
pub(crate) struct UsageBasedFeeOracleConfig {
    /// Minimum fee to return, returned if the chain is not congested
    pub(crate) minimum_fee: u128,
    /// Maximum fee to return, clamped to this value when calculating the average fee
    /// during congestion
    pub(crate) maximum_fee: u128,
    /// Congestion trigger usage ratio threshold, a block with gas usage over this ratio
    /// is considered congested.
    pub(crate) congestion_trigger_usage_ratio_threshold: f64,
    /// Number of congested blocks in a row to trigger the congestion logic
    pub(crate) congestion_trigger_num_blocks: u64,
    /// When congested, this percentile is used to calculate the average fee
    /// from the last N blocks as the priority fee to return
    pub(crate) congestion_fee_percentile: f64,
}

impl Default for UsageBasedFeeOracleConfig {
    fn default() -> Self {
        Self {
            minimum_fee: 0,
            maximum_fee: u128::MAX,
            congestion_trigger_usage_ratio_threshold: 0.75,
            congestion_trigger_num_blocks: 5,
            congestion_fee_percentile: 33.0,
        }
    }
}

/// Fee oracle that takes into account the gas usage of the last N blocks
///
/// For most chains, priority fee above a minimum value doesn't impact the transaction
/// inclusion probability unless the chain is congested. This oracle uses the gas usage
/// of a configurable amount of blocks to determine if the chain is congested and only
/// returns a priority fee above the minimum if the chain is congested.
pub(crate) struct UsageBasedFeeOracle<P> {
    provider: P,
    config: UsageBasedFeeOracleConfig,
}

impl<P> UsageBasedFeeOracle<P>
where
    P: EvmProvider,
{
    pub(crate) fn new(provider: P, config: UsageBasedFeeOracleConfig) -> Self {
        Self { provider, config }
    }
}

#[async_trait::async_trait]
impl<P> FeeOracle for UsageBasedFeeOracle<P>
where
    P: EvmProvider,
{
    async fn estimate_priority_fee(&self) -> Result<u128> {
        let fee_history = self
            .provider
            .fee_history(
                self.config.congestion_trigger_num_blocks,
                BlockNumberOrTag::Latest,
                &[self.config.congestion_fee_percentile],
            )
            .await
            .map_err(|e| FeeOracleError::Other(e.into()))?;

        // Chain is congested if the usage ratio is above the threshold for the last N blocks
        if !fee_history
            .gas_used_ratio
            .iter()
            .all(|x| x >= &self.config.congestion_trigger_usage_ratio_threshold)
        {
            // Chain is not congested, return minimum fee
            return Ok(self.config.minimum_fee);
        }

        let Some(reward) = fee_history.reward else {
            return Ok(0);
        };

        // Chain is congested, return the average of the last N blocks at configured percentile
        let values = reward
            .iter()
            .filter(|b| !b.is_empty() && b[0] != 0)
            .map(|b| b[0])
            .collect::<Vec<_>>();
        if values.is_empty() {
            Ok(self.config.minimum_fee)
        } else {
            let fee: u128 = values.iter().fold(0_u128, |acc, x| acc.saturating_add(*x))
                / (values.len() as u128);
            Ok(fee.clamp(self.config.minimum_fee, self.config.maximum_fee))
        }
    }
}

/// Configuration for the fee history oracle
#[derive(Clone, Debug)]
pub(crate) struct FeeHistoryOracleConfig {
    /// Number of blocks to use for the fee history
    pub(crate) blocks_history: u64,
    /// Percentile to use for the fee history
    pub(crate) percentile: f64,
    /// Minimum fee to return
    pub(crate) minimum_fee: u128,
    /// Maximum fee to return
    pub(crate) maximum_fee: u128,
}

impl Default for FeeHistoryOracleConfig {
    fn default() -> Self {
        Self {
            blocks_history: 15,
            percentile: 50.0,
            minimum_fee: 0,
            maximum_fee: u128::MAX,
        }
    }
}

/// Oracle that uses the fee history to estimate the priority fee
pub(crate) struct FeeHistoryOracle<P> {
    provider: P,
    config: FeeHistoryOracleConfig,
}

impl<P> FeeHistoryOracle<P>
where
    P: EvmProvider,
{
    pub(crate) fn new(provider: P, config: FeeHistoryOracleConfig) -> Self {
        Self { provider, config }
    }
}

#[async_trait::async_trait]
impl<P> FeeOracle for FeeHistoryOracle<P>
where
    P: EvmProvider,
{
    async fn estimate_priority_fee(&self) -> Result<u128> {
        let fee_history = self
            .provider
            .fee_history(
                self.config.blocks_history,
                BlockNumberOrTag::Latest,
                &[self.config.percentile],
            )
            .await
            .map_err(|e| FeeOracleError::Other(e.into()))?;

        let Some(reward) = fee_history.reward else {
            return Ok(0);
        };

        let fee = calculate_estimate_from_rewards(&reward);
        Ok(fee.clamp(self.config.minimum_fee, self.config.maximum_fee))
    }
}

// Calculates the estimate based on the index of inner vector
// and skips the average if block is empty
fn calculate_estimate_from_rewards(reward: &[Vec<u128>]) -> u128 {
    let mut values = reward
        .iter()
        .filter(|b| !b.is_empty() && b[0] != 0)
        .map(|b| b[0])
        .collect::<Vec<_>>();
    if values.is_empty() {
        return 0;
    }

    values.sort();

    let (start, end) = if values.len() < 4 {
        (0, values.len())
    } else {
        (values.len() / 4, 3 * values.len() / 4)
    };

    if start == end {
        return values[start];
    }

    let sum = values[start..end]
        .iter()
        .fold(0_u128, |acc, x| acc.saturating_add(*x));

    sum / ((end - start) as u128)
}

/// Oracle that uses the provider to estimate the priority fee
/// using `eth_maxPriorityFeePerGas`
pub(crate) struct ProviderOracle<P> {
    provider: P,
    min_max_fee_per_gas: u128,
}

impl<P> ProviderOracle<P> {
    pub(crate) fn new(provider: P, min_max_fee_per_gas: u128) -> Self {
        Self {
            provider,
            min_max_fee_per_gas,
        }
    }
}

#[async_trait::async_trait]
impl<P> FeeOracle for ProviderOracle<P>
where
    P: EvmProvider,
{
    async fn estimate_priority_fee(&self) -> Result<u128> {
        Ok(self
            .provider
            .get_max_priority_fee()
            .await
            .map_err(|e| FeeOracleError::Other(e.into()))?
            .max(self.min_max_fee_per_gas))
    }
}

/// Oracle that returns the maximum fee from a list of oracles
pub(crate) struct MaxOracle<'a> {
    oracles: Vec<Box<dyn FeeOracle + 'a>>,
}

impl<'a> MaxOracle<'a> {
    pub(crate) fn new() -> Self {
        Self { oracles: vec![] }
    }

    pub(crate) fn add<T: FeeOracle + 'a>(&mut self, oracle: T) {
        self.oracles.push(Box::new(oracle));
    }
}

#[async_trait::async_trait]
impl FeeOracle for MaxOracle<'_> {
    async fn estimate_priority_fee(&self) -> Result<u128> {
        let futures = self
            .oracles
            .iter()
            .map(|oracle| oracle.estimate_priority_fee());
        let res = join_all(futures).await;
        let values = res.into_iter().filter_map(|r| r.ok()).collect::<Vec<_>>();
        if values.is_empty() {
            return Err(FeeOracleError::NoOracle);
        } else {
            Ok(values.into_iter().max().unwrap())
        }
    }
}

/// Oracle that returns a constant fee
#[derive(Clone, Debug)]
pub(crate) struct ConstantOracle {
    fee: u128,
}

impl ConstantOracle {
    pub(crate) fn new(fee: u128) -> Self {
        Self { fee }
    }
}

#[async_trait::async_trait]
impl FeeOracle for ConstantOracle {
    async fn estimate_priority_fee(&self) -> Result<u128> {
        Ok(self.fee)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rundler_provider::{FeeHistory, MockEvmProvider};

    use super::*;

    #[tokio::test]
    async fn test_usage_oracle_non_congested() {
        let mut mock = MockEvmProvider::default();
        mock.expect_fee_history()
            .times(1)
            .returning(|_: u64, _, _| {
                Ok(FeeHistory {
                    base_fee_per_gas: vec![],
                    gas_used_ratio: vec![0.75, 0.75, 0.75, 0.75, 0.74],
                    oldest_block: 0,
                    reward: Some(vec![vec![100], vec![200], vec![300], vec![400], vec![500]]),
                    ..Default::default()
                })
            });

        let oracle = UsageBasedFeeOracle::new(
            mock,
            UsageBasedFeeOracleConfig {
                congestion_trigger_num_blocks: 5,
                congestion_trigger_usage_ratio_threshold: 0.75,
                minimum_fee: 100,
                ..Default::default()
            },
        );

        assert_eq!(oracle.estimate_priority_fee().await.unwrap(), 100);
    }

    #[tokio::test]
    async fn test_usage_oracle_congested() {
        let mut mock = MockEvmProvider::default();
        mock.expect_fee_history()
            .times(1)
            .returning(|_: u64, _, _| {
                Ok(FeeHistory {
                    base_fee_per_gas: vec![],
                    gas_used_ratio: vec![0.75, 0.75, 0.75, 0.75, 0.75],
                    oldest_block: 0,
                    reward: Some(vec![vec![100], vec![200], vec![300], vec![400], vec![500]]),
                    ..Default::default()
                })
            });

        let oracle = UsageBasedFeeOracle::new(
            mock,
            UsageBasedFeeOracleConfig {
                congestion_trigger_num_blocks: 5,
                congestion_trigger_usage_ratio_threshold: 0.75,
                minimum_fee: 100,
                ..Default::default()
            },
        );

        assert_eq!(oracle.estimate_priority_fee().await.unwrap(), 300);
    }

    #[tokio::test]
    async fn test_fee_history_oracle() {
        let mut mock = MockEvmProvider::default();
        mock.expect_fee_history()
            .times(1)
            .returning(|_: u64, _, _| {
                Ok(FeeHistory {
                    base_fee_per_gas: vec![],
                    gas_used_ratio: vec![],
                    oldest_block: 0,
                    reward: Some(vec![vec![100], vec![200], vec![300]]),
                    ..Default::default()
                })
            });

        let oracle = FeeHistoryOracle::new(
            mock,
            FeeHistoryOracleConfig {
                blocks_history: 3,
                ..Default::default()
            },
        );

        let fee = oracle.estimate_priority_fee().await.unwrap();
        assert_eq!(fee, 200);
    }

    #[tokio::test]
    async fn test_max_oracle() {
        let mut oracle = MaxOracle::new();
        oracle.add(Box::new(ConstantOracle::new(100)));
        oracle.add(Box::new(ConstantOracle::new(200)));
        oracle.add(Box::new(ConstantOracle::new(300)));

        let fee = oracle.estimate_priority_fee().await.unwrap();
        assert_eq!(fee, 300);
    }

    #[tokio::test]
    async fn test_provider_oracle_min() {
        let mut mock = MockEvmProvider::default();
        mock.expect_get_max_priority_fee()
            .times(1)
            .returning(|| Ok(400));
        let oracle = ProviderOracle::new(mock, 401);
        let fee = oracle.estimate_priority_fee().await.unwrap();
        assert_eq!(fee, 401);
    }

    #[tokio::test]
    async fn test_max_oracle_choose_provider() {
        let mut mock = MockEvmProvider::default();
        mock.expect_fee_history()
            .times(1)
            .returning(|_: u64, _, _| {
                Ok(FeeHistory {
                    base_fee_per_gas: vec![],
                    gas_used_ratio: vec![],
                    oldest_block: 0,
                    reward: Some(vec![vec![100], vec![200], vec![300]]),
                    ..Default::default()
                })
            });
        mock.expect_get_max_priority_fee()
            .times(1)
            .returning(|| Ok(400));

        let provider = Arc::new(mock);

        let mut oracle = MaxOracle::new();
        oracle.add(Box::new(FeeHistoryOracle::new(
            Arc::clone(&provider),
            FeeHistoryOracleConfig {
                blocks_history: 3,
                ..Default::default()
            },
        )));
        oracle.add(Box::new(ProviderOracle::new(provider, 0)));

        let fee = oracle.estimate_priority_fee().await.unwrap();
        assert_eq!(fee, 400);
    }

    #[tokio::test]
    async fn test_max_oracle_choose_fee_history() {
        let mut mock = MockEvmProvider::default();
        mock.expect_fee_history()
            .times(1)
            .returning(|_: u64, _, _| {
                Ok(FeeHistory {
                    base_fee_per_gas: vec![],
                    gas_used_ratio: vec![],
                    oldest_block: 0,
                    reward: Some(vec![vec![100], vec![200], vec![300]]),
                    ..Default::default()
                })
            });
        mock.expect_get_max_priority_fee()
            .times(1)
            .returning(|| Ok(100));

        let provider = Arc::new(mock);

        let mut oracle = MaxOracle::new();
        oracle.add(Box::new(FeeHistoryOracle::new(
            Arc::clone(&provider),
            FeeHistoryOracleConfig {
                blocks_history: 3,
                ..Default::default()
            },
        )));
        oracle.add(Box::new(ProviderOracle::new(provider, 0)));

        let fee = oracle.estimate_priority_fee().await.unwrap();
        assert_eq!(fee, 200);
    }

    #[test]
    fn test_calculate_estimate_from_rewards_small() {
        let reward = vec![vec![300], vec![100], vec![200]];
        let fee = calculate_estimate_from_rewards(&reward);
        assert_eq!(fee, 200);
    }

    #[test]
    fn test_calculate_estimate_from_rewards_outliers() {
        let reward = vec![
            vec![300],
            vec![100],
            vec![200],
            vec![300],
            vec![100],
            vec![200],
            vec![2],
            vec![20000],
        ];
        let fee = calculate_estimate_from_rewards(&reward);
        assert_eq!(fee, 200);
    }

    #[test]
    fn test_calculate_estimate_from_rewards_single() {
        let reward = vec![vec![200]];
        let fee = calculate_estimate_from_rewards(&reward);
        assert_eq!(fee, 200);
    }
}
