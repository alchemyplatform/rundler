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

//! Chain specification for Rundler

use std::{borrow::Cow, collections::HashMap, fmt, str::FromStr, sync::Arc};

use alloy_eips::eip7702::constants::PER_EMPTY_ACCOUNT_COST;
use alloy_primitives::Address;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    EntryPointVersion, aggregator::SignatureAggregator, da::DAGasOracleType, proxy::SubmissionProxy,
};

const ENTRY_POINT_ADDRESS_V0_6: &str = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
const ENTRY_POINT_ADDRESS_V0_7: &str = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const ENTRY_POINT_ADDRESS_V0_8: &str = "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108";
const ENTRY_POINT_ADDRESS_V0_9: &str = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";
const MULTICALL3_ADDRESS: &str = "0xcA11bde05977b3631167028862bE2a173976CA11";

/// Chain specification for Rundler
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChainSpec {
    /*
     * Chain constants
     */
    /// name for logging purposes, e.g. "Ethereum", no logic is performed on this
    pub name: String,
    /// chain id
    pub id: u64,
    /// entry point address for v0_6
    pub entry_point_address_v0_6: Address,
    /// entry point address for v0_7
    pub entry_point_address_v0_7: Address,
    /// entry point address for v0.8
    pub entry_point_address_v0_8: Address,
    /// entry point address for v0.9
    pub entry_point_address_v0_9: Address,
    /// address of the multicall3 contract
    pub multicall3_address: Address,
    /// flashblocks enabled
    pub flashblocks_enabled: bool,

    /// Overhead when preforming gas estimation to account for the deposit storage
    /// and transfer overhead.
    ///
    /// NOTE: This must take into account when the storage slot was originally 0
    /// and is now non-zero, making the overhead slightly higher for most operations.
    pub deposit_transfer_overhead: u64,
    /// The maximum size of a transaction in bytes
    pub max_transaction_size_bytes: usize,
    /// the block gas limit
    pub block_gas_limit: u64,
    /// the transaction gas limit, 0 indicates no limit
    pub transaction_gas_limit: u64,
    /// Intrinsic gas cost for a transaction
    pub transaction_intrinsic_gas: u64,
    /// Per user operation gas cost for v0.6
    pub per_user_op_v0_6_gas: u64,
    /// Per user operation gas cost for v0.7
    pub per_user_op_v0_7_gas: u64,
    /// Per user operation deploy gas cost overhead, to capture
    /// deploy costs that are not metered by the entry point
    pub per_user_op_deploy_overhead_gas: u64,
    /// Gas cost for a user operation word in a bundle transaction
    pub per_user_op_word_gas: u64,
    /// Gas cost for a zero byte in calldata
    pub calldata_zero_byte_gas: u64,
    /// Gas cost for a non-zero byte in calldata
    pub calldata_non_zero_byte_gas: u64,

    /*
     * Gas estimation
     */
    /// true if DA is priced in preVerificationGas
    pub da_pre_verification_gas: bool,
    /// type of gas oracle contract for pricing calldata in preVerificationGas
    /// If da_pre_verification_gas is true, this must not be None
    pub da_gas_oracle_type: DAGasOracleType,
    /// address of gas oracle contract for pricing calldata in preVerificationGas
    pub da_gas_oracle_contract_address: Address,
    /// true if Data Availability (DA) calldata gas should be included in the gas limit
    /// only applies when da_pre_verification_gas is true
    pub include_da_gas_in_gas_limit: bool,

    /*
     * EIPS
     */
    /// true if eip1559 is enabled, and thus priority fees are used
    pub eip1559_enabled: bool,
    /// true if eip7702 is enabled
    pub eip7702_enabled: bool,
    /// true if eip7623 is enabled, and thus the 7623 calldata floor mechanism is used
    pub eip7623_enabled: bool,
    /// Gas cost for a zero byte in calldata for the floor operation
    pub eip7623_calldata_floor_zero_byte_gas: u64,
    /// Gas cost for a non-zero byte in calldata for the floor operation
    pub eip7623_calldata_floor_non_zero_byte_gas: u64,
    /// Intrinsic gas charged per EIP-7702 authorization in a bundle transaction
    pub eip7702_authorization_gas: u64,

    /*
     * Glamsterdam
     *
     * The gas fields above are the pre-Glamsterdam schedule. Once a block's timestamp reaches
     * `glamsterdam_activation`, the Glamsterdam preset applies, followed by any
     * `glamsterdam_*` overrides. See `ChainSpec::at_timestamp`.
     */
    /// When the Glamsterdam gas schedule takes effect
    pub glamsterdam_activation: ForkActivation,
    /// Override for `transaction_intrinsic_gas` after Glamsterdam
    pub glamsterdam_transaction_intrinsic_gas: Option<u64>,
    /// Override for `calldata_zero_byte_gas` after Glamsterdam
    pub glamsterdam_calldata_zero_byte_gas: Option<u64>,
    /// Override for `calldata_non_zero_byte_gas` after Glamsterdam
    pub glamsterdam_calldata_non_zero_byte_gas: Option<u64>,
    /// Override for `eip7623_enabled` after Glamsterdam
    pub glamsterdam_eip7623_enabled: Option<bool>,
    /// Override for `eip7623_calldata_floor_zero_byte_gas` after Glamsterdam
    pub glamsterdam_eip7623_calldata_floor_zero_byte_gas: Option<u64>,
    /// Override for `eip7623_calldata_floor_non_zero_byte_gas` after Glamsterdam
    pub glamsterdam_eip7623_calldata_floor_non_zero_byte_gas: Option<u64>,
    /// Override for `eip7702_authorization_gas` after Glamsterdam
    pub glamsterdam_eip7702_authorization_gas: Option<u64>,
    /// Override for `per_user_op_v0_6_gas` after Glamsterdam
    pub glamsterdam_per_user_op_v0_6_gas: Option<u64>,
    /// Override for `per_user_op_v0_7_gas` after Glamsterdam
    pub glamsterdam_per_user_op_v0_7_gas: Option<u64>,
    /// Override for `per_user_op_word_gas` after Glamsterdam
    pub glamsterdam_per_user_op_word_gas: Option<u64>,
    /// Override for `per_user_op_deploy_overhead_gas` after Glamsterdam
    pub glamsterdam_per_user_op_deploy_overhead_gas: Option<u64>,
    /// Override for `deposit_transfer_overhead` after Glamsterdam
    pub glamsterdam_deposit_transfer_overhead: Option<u64>,

    /*
     * Fee estimation
     */
    /// Type of oracle for estimating priority fees
    pub priority_fee_oracle_type: PriorityFeeOracleType,
    /// Minimum max priority fee per gas for the network
    pub min_max_priority_fee_per_gas: u64,
    /// Maximum max priority fee per gas for the network
    pub max_max_priority_fee_per_gas: u64,
    /// Usage ratio of the chain that determines "congestion"
    /// Some chains have artificially high block gas limits but
    /// actually cap block gas usage at a lower value.
    pub congestion_trigger_usage_ratio_threshold: f64,
    /// A boolean value to set whether to add the total gas limit for an op to the PVG calculation
    pub charge_gas_limit_via_pvg: bool,

    /*
     * Bundle building
     */
    /// The maximum amount of time to wait before sending a bundle.
    ///
    /// The bundle builder will always try to send a bundle when a new block is received.
    /// This parameter is used to trigger the builder to send a bundle after a specified
    /// amount of time, before a new block is not received.
    pub bundle_max_send_interval_millis: u64,
    /// True if the bundle validation `eth_call` should be sent without
    /// `maxFeePerGas`/`maxPriorityFeePerGas` fee caps.
    pub bundle_simulation_omit_gas_fees: bool,

    /*
     * Senders
     */
    /// True if the flashbots sender is enabled on this chain
    pub flashbots_enabled: bool,
    /// URL for the flashbots relay, must be set if flashbots is enabled
    pub flashbots_relay_url: Option<String>,
    /// True if the bloxroute sender is enabled on this chain
    pub bloxroute_enabled: bool,
    /// True if this chain's node rejects transactions with `-32000: internal error`
    /// as a terminal, per-transaction rejection rather than a provider outage
    pub internal_rpc_error_is_terminal: bool,

    /*
     * Pool
     */
    /// Size of the chain history to keep to handle reorgs
    pub chain_history_size: u64,

    /*
     * Contracts
     */
    /// Registry of signature aggregators
    #[serde(skip)]
    pub signature_aggregators: Arc<ContractRegistry<Arc<dyn SignatureAggregator>>>,

    /*
     * Submission Proxies
     */
    /// Registry of submission proxies
    #[serde(skip)]
    pub submission_proxies: Arc<ContractRegistry<Arc<dyn SubmissionProxy>>>,
}

/// When a timestamp-activated network upgrade takes effect
///
/// Configured as `"never"`, `"genesis"`, or a Unix timestamp in seconds. The timestamp may be
/// given as a string so it can be set from an environment variable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ForkActivation {
    /// The upgrade never activates
    #[default]
    Never,
    /// The upgrade is active from genesis
    Genesis,
    /// The upgrade is active for blocks with a timestamp at or after this value
    Timestamp(u64),
}

impl ForkActivation {
    /// Whether the upgrade is active for a block with the given timestamp
    pub fn is_active_at(&self, timestamp: u64) -> bool {
        match self {
            ForkActivation::Never => false,
            ForkActivation::Genesis => true,
            ForkActivation::Timestamp(activation) => timestamp >= *activation,
        }
    }
}

impl FromStr for ForkActivation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never" => Ok(ForkActivation::Never),
            "genesis" => Ok(ForkActivation::Genesis),
            _ => s.parse::<u64>().map(ForkActivation::Timestamp).map_err(|_| {
                format!(
                    "invalid fork activation {s:?}, expected \"never\", \"genesis\", or a unix timestamp"
                )
            }),
        }
    }
}

impl Serialize for ForkActivation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ForkActivation::Never => serializer.serialize_str("never"),
            ForkActivation::Genesis => serializer.serialize_str("genesis"),
            ForkActivation::Timestamp(timestamp) => serializer.serialize_u64(*timestamp),
        }
    }
}

impl<'de> Deserialize<'de> for ForkActivation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ForkActivationVisitor;

        impl de::Visitor<'_> for ForkActivationVisitor {
            type Value = ForkActivation;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("\"never\", \"genesis\", or a unix timestamp")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(ForkActivation::Timestamp(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                u64::try_from(v)
                    .map(ForkActivation::Timestamp)
                    .map_err(|_| E::custom(format!("fork activation timestamp {v} is negative")))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                v.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(ForkActivationVisitor)
    }
}

/// Identifies which gas schedule applies to a block
#[derive(Clone, Copy, Debug, PartialEq, Eq, parse_display::Display)]
pub enum GasScheduleId {
    /// Before Glamsterdam
    PreGlamsterdam,
    /// Glamsterdam and later
    Glamsterdam,
}

/// The chain spec gas values that change at a timestamp-activated network upgrade
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GasSchedule {
    /// See `ChainSpec::transaction_intrinsic_gas`
    pub transaction_intrinsic_gas: u64,
    /// See `ChainSpec::calldata_zero_byte_gas`
    pub calldata_zero_byte_gas: u64,
    /// See `ChainSpec::calldata_non_zero_byte_gas`
    pub calldata_non_zero_byte_gas: u64,
    /// See `ChainSpec::eip7623_enabled`
    pub eip7623_enabled: bool,
    /// See `ChainSpec::eip7623_calldata_floor_zero_byte_gas`
    pub eip7623_calldata_floor_zero_byte_gas: u64,
    /// See `ChainSpec::eip7623_calldata_floor_non_zero_byte_gas`
    pub eip7623_calldata_floor_non_zero_byte_gas: u64,
    /// See `ChainSpec::eip7702_authorization_gas`
    pub eip7702_authorization_gas: u64,
    /// See `ChainSpec::per_user_op_v0_6_gas`
    pub per_user_op_v0_6_gas: u64,
    /// See `ChainSpec::per_user_op_v0_7_gas`
    pub per_user_op_v0_7_gas: u64,
    /// See `ChainSpec::per_user_op_word_gas`
    pub per_user_op_word_gas: u64,
    /// See `ChainSpec::per_user_op_deploy_overhead_gas`
    pub per_user_op_deploy_overhead_gas: u64,
    /// See `ChainSpec::deposit_transfer_overhead`
    pub deposit_transfer_overhead: u64,
}

impl GasSchedule {
    /// The Glamsterdam gas schedule, derived from the chain's pre-Glamsterdam schedule
    ///
    /// Values Glamsterdam doesn't change are carried over from `pre`.
    pub fn glamsterdam_preset(pre: &GasSchedule) -> GasSchedule {
        GasSchedule {
            // TODO(verify): EIP-2780 TX_BASE_COST (12,000) + COLD_ACCOUNT_ACCESS (3,000) for
            // the `to` of a value-less call to an existing contract, i.e. a bundle transaction.
            transaction_intrinsic_gas: 15_000,
            // TODO(verify): EIP-7976 keeps the EIP-7623 floor and raises it.
            eip7623_enabled: true,
            // TODO(verify): EIP-7976 TOTAL_COST_FLOOR_PER_TOKEN (16) x 4 floor tokens per byte,
            // the same for zero and non-zero bytes.
            eip7623_calldata_floor_zero_byte_gas: 64,
            eip7623_calldata_floor_non_zero_byte_gas: 64,
            // EIP-8037 (STATE_BYTES_PER_NEW_ACCOUNT 120 + STATE_BYTES_PER_AUTH_BASE 23) x CPSB
            // 1,530 = 218,790 state gas for a new authority, plus EIP-2780
            // EXECUTION_PER_AUTH_BASE_COST 7,816 and ACCOUNT_WRITE 9,000. An existing authority
            // with a new delegation indicator costs 52,006.
            eip7702_authorization_gas: 235_606,
            // TODO(verify): EIP-2780 leaves calldata metering unchanged.
            calldata_zero_byte_gas: pre.calldata_zero_byte_gas,
            calldata_non_zero_byte_gas: pre.calldata_non_zero_byte_gas,
            per_user_op_word_gas: pre.per_user_op_word_gas,
            // TODO(verify): placeholders. These EntryPoint overheads are measured, and EIP-8037 and
            // EIP-8038 raise storage costs, so re-measure them on a Glamsterdam network.
            per_user_op_v0_6_gas: pre.per_user_op_v0_6_gas,
            per_user_op_v0_7_gas: pre.per_user_op_v0_7_gas,
            per_user_op_deploy_overhead_gas: pre.per_user_op_deploy_overhead_gas,
            deposit_transfer_overhead: pre.deposit_transfer_overhead,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.transaction_intrinsic_gas == 0 {
            return Err("transaction_intrinsic_gas must be non-zero".to_string());
        }
        if self.eip7702_authorization_gas == 0 {
            return Err("eip7702_authorization_gas must be non-zero".to_string());
        }
        if self.eip7623_enabled
            && (self.eip7623_calldata_floor_zero_byte_gas < self.calldata_zero_byte_gas
                || self.eip7623_calldata_floor_non_zero_byte_gas < self.calldata_non_zero_byte_gas)
        {
            return Err(format!(
                "calldata floor gas ({}/{}) must not be below standard calldata gas ({}/{})",
                self.eip7623_calldata_floor_zero_byte_gas,
                self.eip7623_calldata_floor_non_zero_byte_gas,
                self.calldata_zero_byte_gas,
                self.calldata_non_zero_byte_gas,
            ));
        }
        Ok(())
    }
}

/// Type of oracle for estimating priority fees
#[derive(Clone, Debug, Deserialize, Default, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PriorityFeeOracleType {
    /// Use eth_maxPriorityFeePerGas on the provider
    #[default]
    Provider,
    /// Use the usage based oracle
    UsageBased,
}

impl Default for ChainSpec {
    fn default() -> Self {
        Self {
            name: "Unknown".to_string(),
            id: 0,
            block_gas_limit: 30_000_000,
            entry_point_address_v0_6: Address::from_str(ENTRY_POINT_ADDRESS_V0_6).unwrap(),
            entry_point_address_v0_7: Address::from_str(ENTRY_POINT_ADDRESS_V0_7).unwrap(),
            entry_point_address_v0_8: Address::from_str(ENTRY_POINT_ADDRESS_V0_8).unwrap(),
            entry_point_address_v0_9: Address::from_str(ENTRY_POINT_ADDRESS_V0_9).unwrap(),
            multicall3_address: Address::from_str(MULTICALL3_ADDRESS).unwrap(),
            flashblocks_enabled: false,
            deposit_transfer_overhead: 30_000,
            transaction_gas_limit: 0,
            transaction_intrinsic_gas: 21_000,
            per_user_op_v0_6_gas: 18_300,
            per_user_op_v0_7_gas: 19_500,
            per_user_op_deploy_overhead_gas: 0,
            per_user_op_word_gas: 4,
            calldata_zero_byte_gas: 4,
            calldata_non_zero_byte_gas: 16,
            eip1559_enabled: true,
            eip7702_enabled: false,
            eip7623_enabled: false,
            eip7623_calldata_floor_zero_byte_gas: 10,
            eip7623_calldata_floor_non_zero_byte_gas: 40,
            eip7702_authorization_gas: PER_EMPTY_ACCOUNT_COST,
            glamsterdam_activation: ForkActivation::Never,
            glamsterdam_transaction_intrinsic_gas: None,
            glamsterdam_calldata_zero_byte_gas: None,
            glamsterdam_calldata_non_zero_byte_gas: None,
            glamsterdam_eip7623_enabled: None,
            glamsterdam_eip7623_calldata_floor_zero_byte_gas: None,
            glamsterdam_eip7623_calldata_floor_non_zero_byte_gas: None,
            glamsterdam_eip7702_authorization_gas: None,
            glamsterdam_per_user_op_v0_6_gas: None,
            glamsterdam_per_user_op_v0_7_gas: None,
            glamsterdam_per_user_op_word_gas: None,
            glamsterdam_per_user_op_deploy_overhead_gas: None,
            glamsterdam_deposit_transfer_overhead: None,
            da_pre_verification_gas: false,
            da_gas_oracle_type: DAGasOracleType::default(),
            da_gas_oracle_contract_address: Address::ZERO,
            include_da_gas_in_gas_limit: false,
            priority_fee_oracle_type: PriorityFeeOracleType::default(),
            min_max_priority_fee_per_gas: 0,
            max_max_priority_fee_per_gas: u64::MAX,
            congestion_trigger_usage_ratio_threshold: 0.75,
            charge_gas_limit_via_pvg: false,
            max_transaction_size_bytes: 131072, // 128 KiB
            bundle_max_send_interval_millis: 1000,
            bundle_simulation_omit_gas_fees: false,
            flashbots_enabled: false,
            flashbots_relay_url: None,
            bloxroute_enabled: false,
            internal_rpc_error_is_terminal: false,
            chain_history_size: 64,
            signature_aggregators: Arc::new(ContractRegistry::default()),
            submission_proxies: Arc::new(ContractRegistry::default()),
        }
    }
}

impl ChainSpec {
    /// Get the deposit transfer overhead
    pub fn deposit_transfer_overhead(&self) -> u128 {
        self.deposit_transfer_overhead as u128
    }

    /// Get the transaction intrinsic gas
    pub fn transaction_intrinsic_gas(&self) -> u128 {
        self.transaction_intrinsic_gas as u128
    }

    /// Resolve the transaction gas limit
    ///
    /// If the transaction gas limit is 0, the block gas limit is returned.
    pub fn transaction_gas_limit(&self) -> u128 {
        if self.transaction_gas_limit > 0 {
            self.transaction_gas_limit as u128
        } else {
            self.block_gas_limit as u128
        }
    }

    /// Get the minimum max priority fee per gas
    pub fn min_max_priority_fee_per_gas(&self) -> u128 {
        self.min_max_priority_fee_per_gas as u128
    }

    /// Get the maximum max priority fee per gas
    pub fn max_max_priority_fee_per_gas(&self) -> u128 {
        self.max_max_priority_fee_per_gas as u128
    }

    /// Get the per user operation word gas
    pub fn per_user_op_word_gas(&self) -> u128 {
        self.per_user_op_word_gas as u128
    }

    /// Get the per user operation v0_6 gas
    pub fn per_user_op_v0_6_gas(&self) -> u128 {
        self.per_user_op_v0_6_gas as u128
    }

    /// Get the per user operation v0_7 gas
    pub fn per_user_op_v0_7_gas(&self) -> u128 {
        self.per_user_op_v0_7_gas as u128
    }

    /// Get the calldata zero byte gas
    pub fn calldata_zero_byte_gas(&self) -> u128 {
        self.calldata_zero_byte_gas as u128
    }

    /// Get the calldata non zero byte gas
    pub fn calldata_non_zero_byte_gas(&self) -> u128 {
        self.calldata_non_zero_byte_gas as u128
    }

    /// Get the calldata floor zero byte gas
    pub fn calldata_floor_zero_byte_gas(&self) -> u128 {
        if self.eip7623_enabled {
            self.eip7623_calldata_floor_zero_byte_gas as u128
        } else {
            0
        }
    }

    /// Get the calldata floor non zero byte gas
    pub fn calldata_floor_non_zero_byte_gas(&self) -> u128 {
        if self.eip7623_enabled {
            self.eip7623_calldata_floor_non_zero_byte_gas as u128
        } else {
            0
        }
    }

    /// Get the per user operation deploy overhead gas
    pub fn per_user_op_deploy_overhead_gas(&self) -> u128 {
        self.per_user_op_deploy_overhead_gas as u128
    }

    /// Get the gas charged per EIP-7702 authorization
    pub fn eip7702_authorization_gas(&self) -> u128 {
        self.eip7702_authorization_gas as u128
    }

    /// The largest per-authorization gas of any schedule this chain can be on
    ///
    /// For gas limits that can't be tied to a specific block.
    pub fn max_eip7702_authorization_gas(&self) -> u128 {
        let pre = self.eip7702_authorization_gas;
        if self.glamsterdam_activation == ForkActivation::Never {
            pre as u128
        } else {
            pre.max(self.glamsterdam_gas_schedule().eip7702_authorization_gas) as u128
        }
    }

    /// Which gas schedule applies to a block with the given timestamp
    pub fn gas_schedule_id_at(&self, timestamp: u64) -> GasScheduleId {
        if self.glamsterdam_activation.is_active_at(timestamp) {
            GasScheduleId::Glamsterdam
        } else {
            GasScheduleId::PreGlamsterdam
        }
    }

    /// The gas schedule that applies to a block with the given timestamp
    pub fn gas_schedule_at(&self, timestamp: u64) -> GasSchedule {
        match self.gas_schedule_id_at(timestamp) {
            GasScheduleId::PreGlamsterdam => self.pre_glamsterdam_gas_schedule(),
            GasScheduleId::Glamsterdam => self.glamsterdam_gas_schedule(),
        }
    }

    /// The chain spec with the gas schedule for a block with the given timestamp applied
    pub fn at_timestamp(&self, timestamp: u64) -> Cow<'_, ChainSpec> {
        match self.gas_schedule_id_at(timestamp) {
            GasScheduleId::PreGlamsterdam => Cow::Borrowed(self),
            GasScheduleId::Glamsterdam => {
                let mut spec = self.clone();
                spec.set_gas_schedule(self.glamsterdam_gas_schedule());
                // The pre-fork fields are overwritten, so the result is always post-fork.
                spec.glamsterdam_activation = ForkActivation::Genesis;
                Cow::Owned(spec)
            }
        }
    }

    /// A gas schedule safe for a transaction submitted after the given head
    ///
    /// A submitted transaction may remain pending across a timestamp fork. Before activation,
    /// use the larger cost from each schedule so its gas limit covers either inclusion block.
    ///
    /// Estimation, admission, pool maintenance and bundle building all price preVerificationGas
    /// with this spec, so an op estimated before the fork is bundleable before and after it.
    pub fn for_bundle_inclusion_after(&self, head_timestamp: u64) -> Cow<'_, ChainSpec> {
        match self.glamsterdam_activation {
            ForkActivation::Timestamp(activation) if head_timestamp < activation => {
                let pre = self.pre_glamsterdam_gas_schedule();
                let post = self.glamsterdam_gas_schedule();
                let mut spec = self.clone();
                spec.set_gas_schedule(GasSchedule {
                    transaction_intrinsic_gas: pre
                        .transaction_intrinsic_gas
                        .max(post.transaction_intrinsic_gas),
                    calldata_zero_byte_gas: pre
                        .calldata_zero_byte_gas
                        .max(post.calldata_zero_byte_gas),
                    calldata_non_zero_byte_gas: pre
                        .calldata_non_zero_byte_gas
                        .max(post.calldata_non_zero_byte_gas),
                    eip7623_enabled: pre.eip7623_enabled || post.eip7623_enabled,
                    eip7623_calldata_floor_zero_byte_gas: pre
                        .eip7623_calldata_floor_zero_byte_gas
                        .max(post.eip7623_calldata_floor_zero_byte_gas),
                    eip7623_calldata_floor_non_zero_byte_gas: pre
                        .eip7623_calldata_floor_non_zero_byte_gas
                        .max(post.eip7623_calldata_floor_non_zero_byte_gas),
                    eip7702_authorization_gas: pre
                        .eip7702_authorization_gas
                        .max(post.eip7702_authorization_gas),
                    per_user_op_v0_6_gas: pre.per_user_op_v0_6_gas.max(post.per_user_op_v0_6_gas),
                    per_user_op_v0_7_gas: pre.per_user_op_v0_7_gas.max(post.per_user_op_v0_7_gas),
                    per_user_op_word_gas: pre.per_user_op_word_gas.max(post.per_user_op_word_gas),
                    per_user_op_deploy_overhead_gas: pre
                        .per_user_op_deploy_overhead_gas
                        .max(post.per_user_op_deploy_overhead_gas),
                    deposit_transfer_overhead: pre
                        .deposit_transfer_overhead
                        .max(post.deposit_transfer_overhead),
                });
                spec.glamsterdam_activation = ForkActivation::Never;
                Cow::Owned(spec)
            }
            _ => self.at_timestamp(head_timestamp),
        }
    }

    /// The gas schedule before Glamsterdam, taken from the top-level gas fields
    pub fn pre_glamsterdam_gas_schedule(&self) -> GasSchedule {
        GasSchedule {
            transaction_intrinsic_gas: self.transaction_intrinsic_gas,
            calldata_zero_byte_gas: self.calldata_zero_byte_gas,
            calldata_non_zero_byte_gas: self.calldata_non_zero_byte_gas,
            eip7623_enabled: self.eip7623_enabled,
            eip7623_calldata_floor_zero_byte_gas: self.eip7623_calldata_floor_zero_byte_gas,
            eip7623_calldata_floor_non_zero_byte_gas: self.eip7623_calldata_floor_non_zero_byte_gas,
            eip7702_authorization_gas: self.eip7702_authorization_gas,
            per_user_op_v0_6_gas: self.per_user_op_v0_6_gas,
            per_user_op_v0_7_gas: self.per_user_op_v0_7_gas,
            per_user_op_word_gas: self.per_user_op_word_gas,
            per_user_op_deploy_overhead_gas: self.per_user_op_deploy_overhead_gas,
            deposit_transfer_overhead: self.deposit_transfer_overhead,
        }
    }

    /// The gas schedule after Glamsterdam: the preset, then any `glamsterdam_*` overrides
    pub fn glamsterdam_gas_schedule(&self) -> GasSchedule {
        let preset = GasSchedule::glamsterdam_preset(&self.pre_glamsterdam_gas_schedule());
        GasSchedule {
            transaction_intrinsic_gas: self
                .glamsterdam_transaction_intrinsic_gas
                .unwrap_or(preset.transaction_intrinsic_gas),
            calldata_zero_byte_gas: self
                .glamsterdam_calldata_zero_byte_gas
                .unwrap_or(preset.calldata_zero_byte_gas),
            calldata_non_zero_byte_gas: self
                .glamsterdam_calldata_non_zero_byte_gas
                .unwrap_or(preset.calldata_non_zero_byte_gas),
            eip7623_enabled: self
                .glamsterdam_eip7623_enabled
                .unwrap_or(preset.eip7623_enabled),
            eip7623_calldata_floor_zero_byte_gas: self
                .glamsterdam_eip7623_calldata_floor_zero_byte_gas
                .unwrap_or(preset.eip7623_calldata_floor_zero_byte_gas),
            eip7623_calldata_floor_non_zero_byte_gas: self
                .glamsterdam_eip7623_calldata_floor_non_zero_byte_gas
                .unwrap_or(preset.eip7623_calldata_floor_non_zero_byte_gas),
            eip7702_authorization_gas: self
                .glamsterdam_eip7702_authorization_gas
                .unwrap_or(preset.eip7702_authorization_gas),
            per_user_op_v0_6_gas: self
                .glamsterdam_per_user_op_v0_6_gas
                .unwrap_or(preset.per_user_op_v0_6_gas),
            per_user_op_v0_7_gas: self
                .glamsterdam_per_user_op_v0_7_gas
                .unwrap_or(preset.per_user_op_v0_7_gas),
            per_user_op_word_gas: self
                .glamsterdam_per_user_op_word_gas
                .unwrap_or(preset.per_user_op_word_gas),
            per_user_op_deploy_overhead_gas: self
                .glamsterdam_per_user_op_deploy_overhead_gas
                .unwrap_or(preset.per_user_op_deploy_overhead_gas),
            deposit_transfer_overhead: self
                .glamsterdam_deposit_transfer_overhead
                .unwrap_or(preset.deposit_transfer_overhead),
        }
    }

    /// Check that every gas schedule this chain can be on is usable
    pub fn validate_gas_schedules(&self) -> anyhow::Result<()> {
        self.pre_glamsterdam_gas_schedule()
            .validate()
            .map_err(|e| anyhow::anyhow!("invalid pre-Glamsterdam gas schedule: {e}"))?;
        if self.glamsterdam_activation != ForkActivation::Never {
            self.glamsterdam_gas_schedule()
                .validate()
                .map_err(|e| anyhow::anyhow!("invalid Glamsterdam gas schedule: {e}"))?;
        }
        Ok(())
    }

    fn set_gas_schedule(&mut self, schedule: GasSchedule) {
        let GasSchedule {
            transaction_intrinsic_gas,
            calldata_zero_byte_gas,
            calldata_non_zero_byte_gas,
            eip7623_enabled,
            eip7623_calldata_floor_zero_byte_gas,
            eip7623_calldata_floor_non_zero_byte_gas,
            eip7702_authorization_gas,
            per_user_op_v0_6_gas,
            per_user_op_v0_7_gas,
            per_user_op_word_gas,
            per_user_op_deploy_overhead_gas,
            deposit_transfer_overhead,
        } = schedule;
        self.transaction_intrinsic_gas = transaction_intrinsic_gas;
        self.calldata_zero_byte_gas = calldata_zero_byte_gas;
        self.calldata_non_zero_byte_gas = calldata_non_zero_byte_gas;
        self.eip7623_enabled = eip7623_enabled;
        self.eip7623_calldata_floor_zero_byte_gas = eip7623_calldata_floor_zero_byte_gas;
        self.eip7623_calldata_floor_non_zero_byte_gas = eip7623_calldata_floor_non_zero_byte_gas;
        self.eip7702_authorization_gas = eip7702_authorization_gas;
        self.per_user_op_v0_6_gas = per_user_op_v0_6_gas;
        self.per_user_op_v0_7_gas = per_user_op_v0_7_gas;
        self.per_user_op_word_gas = per_user_op_word_gas;
        self.per_user_op_deploy_overhead_gas = per_user_op_deploy_overhead_gas;
        self.deposit_transfer_overhead = deposit_transfer_overhead;
    }

    /// Calculate a multiple of the block limit
    pub fn transaction_gas_limit_mult(&self, mult: f64) -> u128 {
        (self.transaction_gas_limit() as f64 * mult) as u128
    }

    /// Set signature aggregators
    pub fn set_signature_aggregators(
        &mut self,
        signature_aggregators: Arc<ContractRegistry<Arc<dyn SignatureAggregator>>>,
    ) {
        self.signature_aggregators = signature_aggregators;
    }

    /// Get a signature aggregator from the registry
    pub fn get_signature_aggregator(
        &self,
        address: &Address,
    ) -> Option<&Arc<dyn SignatureAggregator>> {
        self.signature_aggregators.get(address)
    }

    /// Set submission proxies
    pub fn set_submission_proxies(
        &mut self,
        submission_proxies: Arc<ContractRegistry<Arc<dyn SubmissionProxy>>>,
    ) {
        self.submission_proxies = submission_proxies;
    }

    /// Get a submission proxy from the registry
    pub fn get_submission_proxy(&self, address: &Address) -> Option<&Arc<dyn SubmissionProxy>> {
        self.submission_proxies.get(address)
    }

    /// Get all known proxy addresses
    pub fn known_proxy_addresses(&self) -> impl Iterator<Item = &Address> {
        self.submission_proxies.contracts.keys()
    }

    /// Check if the chain supports EIP-7702
    pub fn supports_eip7702(&self, entry_point: Address) -> bool {
        self.eip7702_enabled && entry_point != self.entry_point_address_v0_6
    }

    /// Get the entry point address for a given version
    pub fn entry_point_address(&self, entry_point_version: EntryPointVersion) -> Address {
        match entry_point_version {
            EntryPointVersion::V0_6 => self.entry_point_address_v0_6,
            EntryPointVersion::V0_7 => self.entry_point_address_v0_7,
            EntryPointVersion::V0_8 => self.entry_point_address_v0_8,
            EntryPointVersion::V0_9 => self.entry_point_address_v0_9,
        }
    }

    /// Get the entry point version for a given address
    pub fn entry_point_version(&self, entry_point: Address) -> Option<EntryPointVersion> {
        match entry_point {
            ep if ep == self.entry_point_address_v0_6 => Some(EntryPointVersion::V0_6),
            ep if ep == self.entry_point_address_v0_7 => Some(EntryPointVersion::V0_7),
            ep if ep == self.entry_point_address_v0_8 => Some(EntryPointVersion::V0_8),
            ep if ep == self.entry_point_address_v0_9 => Some(EntryPointVersion::V0_9),
            _ => None,
        }
    }
}

/// Registry of contracts
#[derive(Debug)]
pub struct ContractRegistry<T> {
    contracts: HashMap<Address, T>,
}

impl<T> ContractRegistry<T> {
    /// Register a contract in the registry
    pub fn register(&mut self, address: Address, contract: T) {
        self.contracts.insert(address, contract);
    }

    /// Get a contract from the registry
    pub fn get(&self, address: &Address) -> Option<&T> {
        self.contracts.get(address)
    }
}

impl<T> Default for ContractRegistry<T> {
    fn default() -> Self {
        Self {
            contracts: HashMap::new(),
        }
    }
}

/// Fallibly convert types with the help of the chain spec
pub trait TryFromWithSpec<T>: Sized {
    /// Convert error
    type Error;

    /// Fallibly convert types with the help of the chain spec
    fn try_from_with_spec(value: T, chain_spec: &ChainSpec) -> Result<Self, Self::Error>;
}

/// Fallibly convert types with the help of the chain spec
pub trait TryIntoWithSpec<T>: Sized {
    /// Convert error
    type Error;

    /// Fallibly convert types with the help of the chain spec
    fn try_into_with_spec(self, chain_spec: &ChainSpec) -> Result<T, Self::Error>;
}

impl<T, U> TryIntoWithSpec<U> for T
where
    U: TryFromWithSpec<T>,
{
    type Error = U::Error;
    fn try_into_with_spec(self, chain_spec: &ChainSpec) -> Result<U, U::Error> {
        U::try_from_with_spec(self, chain_spec)
    }
}

/// Convert types with the help of the chain spec
pub trait FromWithSpec<T>: Sized {
    /// Convert types with the help of the chain spec
    fn from_with_spec(value: T, chain_spec: &ChainSpec) -> Self;
}

/// Convert types with the help of the chain spec
pub trait IntoWithSpec<T>: Sized {
    /// Convert types with the help of the chain spec
    fn into_with_spec(self, chain_spec: &ChainSpec) -> T;
}

impl<T, U> IntoWithSpec<U> for T
where
    U: FromWithSpec<T>,
{
    fn into_with_spec(self, chain_spec: &ChainSpec) -> U {
        U::from_with_spec(self, chain_spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTIVATION: u64 = 1_000;

    fn spec_with_activation(activation: ForkActivation) -> ChainSpec {
        ChainSpec {
            eip7623_enabled: true,
            glamsterdam_activation: activation,
            ..Default::default()
        }
    }

    #[test]
    fn schedule_switches_at_activation_timestamp() {
        let spec = spec_with_activation(ForkActivation::Timestamp(ACTIVATION));
        let pre = spec.pre_glamsterdam_gas_schedule();
        let post = spec.glamsterdam_gas_schedule();

        assert_eq!(spec.gas_schedule_at(ACTIVATION - 1), pre);
        assert_eq!(spec.gas_schedule_at(ACTIVATION), post);
        assert_eq!(spec.gas_schedule_at(ACTIVATION + 1), post);
        assert_eq!(
            spec.gas_schedule_id_at(ACTIVATION - 1),
            GasScheduleId::PreGlamsterdam
        );
        assert_eq!(
            spec.gas_schedule_id_at(ACTIVATION),
            GasScheduleId::Glamsterdam
        );
    }

    #[test]
    fn never_and_genesis_activation() {
        let never = spec_with_activation(ForkActivation::Never);
        assert_eq!(never.gas_schedule_id_at(0), GasScheduleId::PreGlamsterdam);
        assert_eq!(
            never.gas_schedule_id_at(u64::MAX),
            GasScheduleId::PreGlamsterdam
        );

        let genesis = spec_with_activation(ForkActivation::Genesis);
        assert_eq!(genesis.gas_schedule_id_at(0), GasScheduleId::Glamsterdam);
    }

    #[test]
    fn glamsterdam_preset_values() {
        let spec = spec_with_activation(ForkActivation::Genesis);
        let pre = spec.pre_glamsterdam_gas_schedule();
        let post = spec.glamsterdam_gas_schedule();

        assert_eq!(post.transaction_intrinsic_gas, 15_000);
        assert!(post.eip7623_enabled);
        assert_eq!(post.eip7623_calldata_floor_zero_byte_gas, 64);
        assert_eq!(post.eip7623_calldata_floor_non_zero_byte_gas, 64);
        assert_eq!(post.eip7702_authorization_gas, 235_606);
        assert_eq!(post.calldata_zero_byte_gas, pre.calldata_zero_byte_gas);
        assert_eq!(post.per_user_op_v0_7_gas, pre.per_user_op_v0_7_gas);
        assert_eq!(
            post.deposit_transfer_overhead,
            pre.deposit_transfer_overhead
        );
    }

    #[test]
    fn glamsterdam_overrides_replace_preset() {
        let spec = ChainSpec {
            glamsterdam_per_user_op_v0_7_gas: Some(40_000),
            glamsterdam_eip7623_calldata_floor_non_zero_byte_gas: Some(70),
            ..spec_with_activation(ForkActivation::Genesis)
        };
        let post = spec.glamsterdam_gas_schedule();
        assert_eq!(post.per_user_op_v0_7_gas, 40_000);
        assert_eq!(post.eip7623_calldata_floor_non_zero_byte_gas, 70);
        assert_eq!(post.eip7623_calldata_floor_zero_byte_gas, 64);
        // overrides don't touch the pre-fork schedule
        assert_eq!(
            spec.pre_glamsterdam_gas_schedule().per_user_op_v0_7_gas,
            19_500
        );
    }

    #[test]
    fn at_timestamp_applies_schedule() {
        let spec = spec_with_activation(ForkActivation::Timestamp(ACTIVATION));

        let pre = spec.at_timestamp(ACTIVATION - 1);
        assert!(matches!(pre, Cow::Borrowed(_)));
        assert_eq!(pre.transaction_intrinsic_gas(), 21_000);
        assert_eq!(pre.calldata_floor_non_zero_byte_gas(), 40);
        assert_eq!(pre.eip7702_authorization_gas(), 25_000);

        let post = spec.at_timestamp(ACTIVATION);
        assert_eq!(post.transaction_intrinsic_gas(), 15_000);
        assert_eq!(post.calldata_floor_zero_byte_gas(), 64);
        assert_eq!(post.calldata_floor_non_zero_byte_gas(), 64);
        assert_eq!(post.eip7702_authorization_gas(), 235_606);
        // the derived spec stays post-fork whatever timestamp it's asked about
        assert_eq!(post.gas_schedule_at(0), spec.glamsterdam_gas_schedule());
    }

    #[test]
    fn max_authorization_gas_covers_both_schedules() {
        assert_eq!(
            spec_with_activation(ForkActivation::Never).max_eip7702_authorization_gas(),
            25_000
        );
        assert_eq!(
            spec_with_activation(ForkActivation::Timestamp(ACTIVATION))
                .max_eip7702_authorization_gas(),
            235_606
        );
    }

    #[test]
    fn bundle_inclusion_schedule_covers_both_sides_of_activation() {
        let spec = ChainSpec {
            glamsterdam_calldata_non_zero_byte_gas: Some(8),
            glamsterdam_per_user_op_v0_7_gas: Some(10_000),
            ..spec_with_activation(ForkActivation::Timestamp(ACTIVATION))
        };

        let inclusion = spec.for_bundle_inclusion_after(ACTIVATION - 1);
        assert_eq!(inclusion.transaction_intrinsic_gas(), 21_000);
        assert_eq!(inclusion.calldata_non_zero_byte_gas(), 16);
        assert_eq!(inclusion.calldata_floor_non_zero_byte_gas(), 64);
        assert_eq!(inclusion.eip7702_authorization_gas(), 235_606);
        assert_eq!(inclusion.per_user_op_v0_7_gas(), 19_500);

        let post = spec.for_bundle_inclusion_after(ACTIVATION);
        assert_eq!(post.transaction_intrinsic_gas(), 15_000);
        assert_eq!(post.calldata_non_zero_byte_gas(), 8);
        assert_eq!(post.per_user_op_v0_7_gas(), 10_000);

        let never = spec_with_activation(ForkActivation::Never);
        assert!(matches!(
            never.for_bundle_inclusion_after(ACTIVATION - 1),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn validate_rejects_bad_schedules() {
        spec_with_activation(ForkActivation::Genesis)
            .validate_gas_schedules()
            .unwrap();

        let floor_below_standard = ChainSpec {
            glamsterdam_eip7623_calldata_floor_non_zero_byte_gas: Some(8),
            ..spec_with_activation(ForkActivation::Genesis)
        };
        assert!(floor_below_standard.validate_gas_schedules().is_err());

        // an invalid override is ignored while the fork can't activate
        let never = ChainSpec {
            glamsterdam_activation: ForkActivation::Never,
            ..floor_below_standard
        };
        never.validate_gas_schedules().unwrap();

        let zero_intrinsic = ChainSpec {
            transaction_intrinsic_gas: 0,
            ..Default::default()
        };
        assert!(zero_intrinsic.validate_gas_schedules().is_err());

        let zero_authorization = ChainSpec {
            eip7702_authorization_gas: 0,
            ..Default::default()
        };
        assert!(zero_authorization.validate_gas_schedules().is_err());
    }

    #[test]
    fn fork_activation_deserialize() {
        let parse = |json: &str| serde_json::from_str::<ForkActivation>(json);
        assert_eq!(parse(r#""never""#).unwrap(), ForkActivation::Never);
        assert_eq!(parse(r#""genesis""#).unwrap(), ForkActivation::Genesis);
        assert_eq!(
            parse("1791294816").unwrap(),
            ForkActivation::Timestamp(1791294816)
        );
        assert_eq!(
            parse(r#""1791294816""#).unwrap(),
            ForkActivation::Timestamp(1791294816)
        );
        assert!(parse(r#""soon""#).is_err());
        assert!(parse("-1").is_err());
        assert!(parse(r#""0x10""#).is_err());
    }

    #[test]
    fn fork_activation_round_trips() {
        for activation in [
            ForkActivation::Never,
            ForkActivation::Genesis,
            ForkActivation::Timestamp(1791294816),
        ] {
            let json = serde_json::to_string(&activation).unwrap();
            assert_eq!(
                serde_json::from_str::<ForkActivation>(&json).unwrap(),
                activation
            );
        }
    }
}
