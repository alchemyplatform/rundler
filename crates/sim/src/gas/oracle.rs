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

use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
use ethers::types::{BlockNumber, U256};
use futures_util::future::join_all;
use rundler_provider::Provider;

pub(crate) type Result<T, E = FeeOracleError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum FeeOracleError {
    /// No oracle available, or all oracles failed
    #[error("No oracle available")]
    NoOracle,
    /// Error from the oracle
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// FeeOracle is a trait that provides a way to estimate the priority fee
#[async_trait]
pub(crate) trait FeeOracle: Send + Sync + Debug {
    async fn estimate_priority_fee(&self) -> Result<U256>;
}

/// UsageBasedFeeOracle config
#[derive(Clone, Debug)]
pub(crate) struct UsageBasedFeeOracleConfig {
    /// Minimum fee to return, returned if the chain is not congested
    pub(crate) minimum_fee: U256,
    /// Maximum fee to return, clamped to this value when calculating the average fee
    /// during congestion
    pub(crate) maximum_fee: U256,
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
            minimum_fee: U256::zero(),
            maximum_fee: U256::MAX,
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
#[derive(Debug)]
pub(crate) struct UsageBasedFeeOracle<P> {
    provider: Arc<P>,
    config: UsageBasedFeeOracleConfig,
}

impl<P> UsageBasedFeeOracle<P>
where
    P: Provider,
{
    pub(crate) fn new(provider: Arc<P>, config: UsageBasedFeeOracleConfig) -> Self {
        Self { provider, config }
    }
}

#[async_trait]
impl<P> FeeOracle for UsageBasedFeeOracle<P>
where
    P: Provider + Debug,
{
    async fn estimate_priority_fee(&self) -> Result<U256> {
        let fee_history = self
            .provider
            .fee_history(
                self.config.congestion_trigger_num_blocks,
                BlockNumber::Latest,
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

        // Chain is congested, return the average of the last N blocks at configured percentile
        let values = fee_history
            .reward
            .iter()
            .filter(|b| !b.is_empty() && !b[0].is_zero())
            .map(|b| b[0])
            .collect::<Vec<_>>();
        if values.is_empty() {
            Ok(self.config.minimum_fee)
        } else {
            let fee: U256 = values
                .iter()
                .fold(U256::zero(), |acc, x| acc.saturating_add(*x))
                / values.len();
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
    pub(crate) minimum_fee: U256,
    /// Maximum fee to return
    pub(crate) maximum_fee: U256,
}

impl Default for FeeHistoryOracleConfig {
    fn default() -> Self {
        Self {
            blocks_history: 15,
            percentile: 50.0,
            minimum_fee: U256::zero(),
            maximum_fee: U256::MAX,
        }
    }
}

/// Oracle that uses the fee history to estimate the priority fee
#[derive(Debug)]
pub(crate) struct FeeHistoryOracle<P> {
    provider: Arc<P>,
    config: FeeHistoryOracleConfig,
}

impl<P> FeeHistoryOracle<P>
where
    P: Provider,
{
    pub(crate) fn new(provider: Arc<P>, config: FeeHistoryOracleConfig) -> Self {
        Self { provider, config }
    }
}

#[async_trait]
impl<P> FeeOracle for FeeHistoryOracle<P>
where
    P: Provider + Debug,
{
    async fn estimate_priority_fee(&self) -> Result<U256> {
        let fee_history = self
            .provider
            .fee_history(
                self.config.blocks_history,
                BlockNumber::Latest,
                &[self.config.percentile],
            )
            .await
            .map_err(|e| FeeOracleError::Other(e.into()))?;

        let fee = calculate_estimate_from_rewards(&fee_history.reward);
        Ok(fee.clamp(self.config.minimum_fee, self.config.maximum_fee))
    }
}

// Calculates the estimate based on the index of inner vector
// and skips the average if block is empty
fn calculate_estimate_from_rewards(reward: &[Vec<U256>]) -> U256 {
    let mut values = reward
        .iter()
        .filter(|b| !b.is_empty() && !b[0].is_zero())
        .map(|b| b[0])
        .collect::<Vec<_>>();
    if values.is_empty() {
        return U256::zero();
    }

    values.sort();

    let (start, end) = if values.len() < 4 {
        (0, values.len())
    } else {
        (values.len() / 4, 3 * values.len() / 4)
    };
    let sum = values[start..end]
        .iter()
        .fold(U256::zero(), |acc, x| acc.saturating_add(*x));
    sum / U256::from(end - start)
}

/// Oracle that uses the provider to estimate the priority fee
/// using `eth_maxPriorityFeePerGas`
#[derive(Debug)]
pub(crate) struct ProviderOracle<P> {
    provider: Arc<P>,
    min_max_fee_per_gas: U256,
}

impl<P> ProviderOracle<P> {
    pub(crate) fn new(provider: Arc<P>, min_max_fee_per_gas: U256) -> Self {
        Self {
            provider,
            min_max_fee_per_gas,
        }
    }
}

#[async_trait]
impl<P> FeeOracle for ProviderOracle<P>
where
    P: Provider + Debug,
{
    async fn estimate_priority_fee(&self) -> Result<U256> {
        Ok(self
            .provider
            .get_max_priority_fee()
            .await
            .map_err(|e| FeeOracleError::Other(e.into()))?
            .max(self.min_max_fee_per_gas))
    }
}

/// Oracle that returns the maximum fee from a list of oracles
#[derive(Debug)]
pub(crate) struct MaxOracle {
    oracles: Vec<Box<dyn FeeOracle>>,
}

impl MaxOracle {
    pub(crate) fn new() -> Self {
        Self { oracles: vec![] }
    }

    pub(crate) fn add<T: FeeOracle + 'static>(&mut self, oracle: T) {
        self.oracles.push(Box::new(oracle));
    }
}

#[async_trait]
impl FeeOracle for MaxOracle {
    async fn estimate_priority_fee(&self) -> Result<U256> {
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
    fee: U256,
}

impl ConstantOracle {
    pub(crate) fn new(fee: U256) -> Self {
        Self { fee }
    }
}

#[async_trait]
impl FeeOracle for ConstantOracle {
    async fn estimate_priority_fee(&self) -> Result<U256> {
        Ok(self.fee)
    }
}

#[cfg(test)]
mod tests {
    use ethers::types::FeeHistory;
    use rundler_provider::MockProvider;

    use super::*;

    #[tokio::test]
    async fn test_usage_oracle_non_congested() {
        let mut mock = MockProvider::default();
        mock.expect_fee_history()
            .times(1)
            .returning(|_: u64, _, _| {
                Ok(FeeHistory {
                    base_fee_per_gas: vec![],
                    gas_used_ratio: vec![0.75, 0.75, 0.75, 0.75, 0.74],
                    oldest_block: U256::zero(),
                    reward: vec![
                        vec![U256::from(100)],
                        vec![U256::from(200)],
                        vec![U256::from(300)],
                        vec![U256::from(400)],
                        vec![U256::from(500)],
                    ],
                })
            });

        let oracle = UsageBasedFeeOracle::new(
            Arc::new(mock),
            UsageBasedFeeOracleConfig {
                congestion_trigger_num_blocks: 5,
                congestion_trigger_usage_ratio_threshold: 0.75,
                minimum_fee: U256::from(100),
                ..Default::default()
            },
        );

        assert_eq!(
            oracle.estimate_priority_fee().await.unwrap(),
            U256::from(100)
        );
    }

    #[tokio::test]
    async fn test_usage_oracle_congested() {
        let mut mock = MockProvider::default();
        mock.expect_fee_history()
            .times(1)
            .returning(|_: u64, _, _| {
                Ok(FeeHistory {
                    base_fee_per_gas: vec![],
                    gas_used_ratio: vec![0.75, 0.75, 0.75, 0.75, 0.75],
                    oldest_block: U256::zero(),
                    reward: vec![
                        vec![U256::from(100)],
                        vec![U256::from(200)],
                        vec![U256::from(300)],
                        vec![U256::from(400)],
                        vec![U256::from(500)],
                    ],
                })
            });

        let oracle = UsageBasedFeeOracle::new(
            Arc::new(mock),
            UsageBasedFeeOracleConfig {
                congestion_trigger_num_blocks: 5,
                congestion_trigger_usage_ratio_threshold: 0.75,
                minimum_fee: U256::from(100),
                ..Default::default()
            },
        );

        assert_eq!(
            oracle.estimate_priority_fee().await.unwrap(),
            U256::from(300)
        );
    }

    #[tokio::test]
    async fn test_fee_history_oracle() {
        let mut mock = MockProvider::default();
        mock.expect_fee_history()
            .times(1)
            .returning(|_: u64, _, _| {
                let reward = vec![
                    vec![U256::from(100)],
                    vec![U256::from(200)],
                    vec![U256::from(300)],
                ];
                Ok(FeeHistory {
                    base_fee_per_gas: vec![],
                    gas_used_ratio: vec![],
                    oldest_block: U256::zero(),
                    reward,
                })
            });

        let oracle = FeeHistoryOracle::new(
            Arc::new(mock),
            FeeHistoryOracleConfig {
                blocks_history: 3,
                ..Default::default()
            },
        );

        let fee = oracle.estimate_priority_fee().await.unwrap();
        assert_eq!(fee, U256::from(200));
    }

    #[tokio::test]
    async fn test_max_oracle() {
        let mut oracle = MaxOracle::new();
        oracle.add(ConstantOracle::new(U256::from(100)));
        oracle.add(ConstantOracle::new(U256::from(200)));
        oracle.add(ConstantOracle::new(U256::from(300)));

        let fee = oracle.estimate_priority_fee().await.unwrap();
        assert_eq!(fee, U256::from(300));
    }

    #[tokio::test]
    async fn test_provider_oracle_min() {
        let mut mock = MockProvider::default();
        mock.expect_get_max_priority_fee()
            .times(1)
            .returning(|| Ok(U256::from(400)));
        let oracle = ProviderOracle::new(Arc::new(mock), U256::from(401));
        let fee = oracle.estimate_priority_fee().await.unwrap();
        assert_eq!(fee, U256::from(401));
    }

    #[tokio::test]
    async fn test_max_oracle_choose_provider() {
        let mut mock = MockProvider::default();
        mock.expect_fee_history()
            .times(1)
            .returning(|_: u64, _, _| {
                let reward = vec![
                    vec![U256::from(100)],
                    vec![U256::from(200)],
                    vec![U256::from(300)],
                ];
                Ok(FeeHistory {
                    base_fee_per_gas: vec![],
                    gas_used_ratio: vec![],
                    oldest_block: U256::zero(),
                    reward,
                })
            });
        mock.expect_get_max_priority_fee()
            .times(1)
            .returning(|| Ok(U256::from(400)));

        let provider = Arc::new(mock);

        let mut oracle = MaxOracle::new();
        oracle.add(FeeHistoryOracle::new(
            Arc::clone(&provider),
            FeeHistoryOracleConfig {
                blocks_history: 3,
                ..Default::default()
            },
        ));
        oracle.add(ProviderOracle::new(provider, U256::from(0)));

        let fee = oracle.estimate_priority_fee().await.unwrap();
        assert_eq!(fee, U256::from(400));
    }

    #[tokio::test]
    async fn test_max_oracle_choose_fee_history() {
        let mut mock = MockProvider::default();
        mock.expect_fee_history()
            .times(1)
            .returning(|_: u64, _, _| {
                let reward = vec![
                    vec![U256::from(100)],
                    vec![U256::from(200)],
                    vec![U256::from(300)],
                ];
                Ok(FeeHistory {
                    base_fee_per_gas: vec![],
                    gas_used_ratio: vec![],
                    oldest_block: U256::zero(),
                    reward,
                })
            });
        mock.expect_get_max_priority_fee()
            .times(1)
            .returning(|| Ok(U256::from(100)));

        let provider = Arc::new(mock);

        let mut oracle = MaxOracle::new();
        oracle.add(FeeHistoryOracle::new(
            Arc::clone(&provider),
            FeeHistoryOracleConfig {
                blocks_history: 3,
                ..Default::default()
            },
        ));
        oracle.add(ProviderOracle::new(provider, U256::from(0)));

        let fee = oracle.estimate_priority_fee().await.unwrap();
        assert_eq!(fee, U256::from(200));
    }

    #[test]
    fn test_calculate_estimate_from_rewards_small() {
        let reward = vec![
            vec![U256::from(300)],
            vec![U256::from(100)],
            vec![U256::from(200)],
        ];
        let fee = calculate_estimate_from_rewards(&reward);
        assert_eq!(fee, U256::from(200));
    }

    #[test]
    fn test_calculate_estimate_from_rewards_outliers() {
        let reward = vec![
            vec![U256::from(300)],
            vec![U256::from(100)],
            vec![U256::from(200)],
            vec![U256::from(300)],
            vec![U256::from(100)],
            vec![U256::from(200)],
            vec![U256::from(2)],
            vec![U256::from(20000)],
        ];
        let fee = calculate_estimate_from_rewards(&reward);
        assert_eq!(fee, U256::from(200));
    }

    #[test]
    fn test_calculate_estimate_from_rewards_single() {
        let reward = vec![vec![U256::from(200)]];
        let fee = calculate_estimate_from_rewards(&reward);
        assert_eq!(fee, U256::from(200));
    }
}
