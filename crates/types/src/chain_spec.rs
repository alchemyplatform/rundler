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

use std::str::FromStr;

use ethers::types::Address;
use paste::paste;
use serde::Deserialize;

// Generate chain spec with optional fields and a merge function.
// TODO should this be a derive macro?
macro_rules! make_optional_spec {
    ( $(#[$attr:meta])* $vis:vis struct $struct_name:ident { $(#[$doc:meta] $fv:vis $field:ident : $ty:ty),* $(,)? }) => {

        $(#[$attr])*
        $vis struct $struct_name {
            $( #[$doc] $fv $field: $ty ),*
        }

        paste! {
            $(#[$attr])*
            #[derive(Deserialize, Default)]
            $vis struct [<Optional $struct_name>] {
                /// The base chain spec to use
                pub base: Option<String>,
                $( $field: Option<$ty> ),*
            }

            impl [<Optional $struct_name>] {
                /// Merge two optional $struct_name structs, preferring the first value if both are present.
                $vis fn merge(self, other: Self) -> Self {
                    Self {
                        base: self.base.or(other.base),
                        $( $field: self.$field.or(other.$field) ),*
                    }
                }
            }

            impl From<[<Optional $struct_name>]> for $struct_name {
                fn from(optional: [<Optional $struct_name>]) -> Self {
                    let default = $struct_name::default();
                    $struct_name {
                        $( $field: optional.$field.unwrap_or(default.$field) ),*
                    }
                }
            }
        }
    }
}

make_optional_spec!(
    /// asdf
    #[derive(Debug)]
    pub struct ChainSpec {
        /*
         * Chain constants
         */
        /// asdf
        pub id: u64,
        /// asdf
        pub entry_point_address: Address,
        /// asdf
        pub supports_eip1559: bool,

        /*
         * Fee estimation
         */
        /// asdf
        pub min_max_priority_fee_per_gas: u64,
        /// asdf
        pub max_max_priority_fee_per_gas: u64,
        /// asdf
        pub use_fee_history_oracle: bool,
        /// asdf
        pub fee_history_oracle_blocks: u64,
        /// asdf
        pub fee_history_oracle_percentile: f64,
        /// asdf
        pub max_with_provider_fee: bool,

        /*
         * Gas estimation
         */
        /// asdf
        pub gas_estimation_accuracy_rounding: u64,
        /// asdf
        pub gas_estimation_error_margin: f64,
        /// asdf
        pub gas_estimation_verification_gas_buffer_percent: u64,
        /// asdf
        pub gas_estimation_fee_transfer_cost: u64,
        /// asdf
        pub min_call_gas_limit: u64,
        /// asdf
        pub l1_gas_oracle_contract_type: L1GasOracleContractType,
        /// asdf
        pub l1_gas_oracle_contract_address: Address,

        /*
         * Pool and validation
         */
        /// asdf
        pub bundle_invalidation_ops_seen_staked_penalty: u64,
        /// asdf
        pub bundle_invalidation_ops_seen_unstaked_penalty: u64,
        /// asdf
        pub same_unstaked_entity_mempool_count: u64,
        /// asdf
        pub min_inclusion_rate_denominator: u64,
        /// asdf
        pub inclusion_rate_factor: u64,
        /// asdf
        pub throttling_slack: u64,
        /// asdf
        pub ban_slack: u64,
        /// asdf
        pub throttled_entity_mempool_count: u64,
        /// asdf
        pub throttled_entity_live_blocks: u64,
        /// asdf
        pub max_user_ops_per_unstaked_sender: usize,
        /// asdf
        pub min_replacement_fee_increase_percentage: u64,
        /// asdf
        pub min_unstake_delay_seconds: u64,
        /// asdf
        pub min_stake_value: u128,
    }
);

impl ChainSpec {
    /*
     * Gas constants
     */
    ///
    pub const ZERO_BYTE_GAS: u64 = 4;
    ///
    pub const NON_ZERO_BYTE_GAS: u64 = 16;
    ///
    pub const PER_USER_OP_WORD_GAS: u64 = 4;
    ///
    pub const PER_USER_OP_GAS: u64 = 18300;
    ///
    pub const TRANSACTION_GAS_OVERHEAD: u64 = 21000;
    ///
    pub const BUNDLE_TRANSACTION_GAS_BUFFER: u64 = 5000;
}

impl Default for ChainSpec {
    fn default() -> Self {
        Self {
            id: 0,
            supports_eip1559: true,
            entry_point_address: Address::from_str("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789")
                .unwrap(),
            min_max_priority_fee_per_gas: 0,
            max_max_priority_fee_per_gas: u64::MAX,
            use_fee_history_oracle: false,
            fee_history_oracle_blocks: 0,
            fee_history_oracle_percentile: 0.0,
            max_with_provider_fee: false,
            min_call_gas_limit: 9100,
            l1_gas_oracle_contract_type: L1GasOracleContractType::None,
            l1_gas_oracle_contract_address: Address::zero(),
            gas_estimation_accuracy_rounding: 4096,
            gas_estimation_error_margin: 0.1,
            gas_estimation_verification_gas_buffer_percent: 10,
            gas_estimation_fee_transfer_cost: 30000,
            bundle_invalidation_ops_seen_staked_penalty: 10000,
            bundle_invalidation_ops_seen_unstaked_penalty: 1000,
            same_unstaked_entity_mempool_count: 10,
            min_inclusion_rate_denominator: 10,
            inclusion_rate_factor: 10,
            throttling_slack: 10,
            ban_slack: 50,
            throttled_entity_mempool_count: 4,
            throttled_entity_live_blocks: 4,
            max_user_ops_per_unstaked_sender: 4,
            min_replacement_fee_increase_percentage: 10,
            min_unstake_delay_seconds: 84600,     // 1 day
            min_stake_value: 1000000000000000000, // 1 ETH
        }
    }
}

///
#[derive(Clone, Copy, Debug, Deserialize, Default)]
pub enum L1GasOracleContractType {
    ///
    #[default]
    None,
    ///
    ArbitrumNitro,
    ///
    OptimismBedrock,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arbitrum_goerli() {
        let spec: ChainSpec = arbitrum_goerli().into();
        assert_eq!(spec.id, 421613);
        assert!(!spec.supports_eip1559);
        assert!(matches!(
            spec.l1_gas_oracle_contract_type,
            L1GasOracleContractType::ArbitrumNitro
        ));
        assert_eq!(
            spec.l1_gas_oracle_contract_address,
            Address::from_str("0x00000000000000000000000000000000000000C8").unwrap()
        );
    }

    fn arbitrum() -> OptionalChainSpec {
        OptionalChainSpec {
            id: Some(42161),
            supports_eip1559: Some(false),
            l1_gas_oracle_contract_type: Some(L1GasOracleContractType::ArbitrumNitro),
            l1_gas_oracle_contract_address: Some(
                Address::from_str("0x00000000000000000000000000000000000000C8").unwrap(), // TODO
            ),
            ..Default::default()
        }
    }

    fn arbitrum_goerli() -> OptionalChainSpec {
        let base = arbitrum();
        let overrides = OptionalChainSpec {
            id: Some(421613),
            ..Default::default()
        };
        overrides.merge(base)
    }
}
