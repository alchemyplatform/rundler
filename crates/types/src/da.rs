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

//! Types associated with DA gas calculations

use serde::{Deserialize, Serialize};

/// Type of gas oracle for pricing calldata in preVerificationGas
#[derive(Clone, Copy, Debug, Deserialize, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DAGasOracleType {
    /// No gas oracle
    #[default]
    None,
    /// Arbitrum Nitro type gas oracle
    ArbitrumNitro,
    /// Optimism Bedrock type gas oracle
    OptimismBedrock,
    /// Local Bedrock type gas oracle
    LocalBedrock,
    /// Cached Nitro type gas oracle
    CachedNitro,
}

/// Data associated with a user operation for Nitro DA gas calculations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NitroDAGasUOData {
    /// The calculated user operation units as they apply to DA gas. Only have meaning when used
    /// with the NitroDAGasBlockData that was used to calculate them and combined with a NitroDAGasBlockData.
    pub uo_units: u128,
}

/// Data associated with a user operation for Bedrock DA gas calculations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BedrockDAGasUOData {
    /// The calculated user operation units as they apply to DA gas. Only have meaning when used
    /// with the BedrockDAGasBlockData that was used to calculate them and combined with a
    /// BedrockDAGasBlockData.
    pub uo_units: u64,
}

/// Data associated with a user operation for DA gas calculations
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum DAGasUOData {
    /// Empty, no data
    #[default]
    Empty,
    /// Nitro DA
    Nitro(NitroDAGasUOData),
    /// Bedrock DA
    Bedrock(BedrockDAGasUOData),
}

/// Data associated with a block for DA gas calculations
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum DAGasBlockData {
    /// Empty, no data
    #[default]
    Empty,
    /// Nitro DA
    Nitro(NitroDAGasBlockData),
    /// Bedrock DA
    Bedrock(BedrockDAGasBlockData),
}

/// Data associated with a block for Nitro DA gas calculations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NitroDAGasBlockData {
    /// L1 base fee retrieved from the nitro node interface precompile.
    pub l1_base_fee: u128,
    /// Base fee retrieved from the nitro node interface precompile.
    pub base_fee: u128,
}

/// Data associated with a block for Bedrock DA gas calculations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BedrockDAGasBlockData {
    /// Base fee scalar retrieved from the bedrock gas oracle.
    pub base_fee_scalar: u64,
    /// L1 base fee retrieved from the bedrock gas oracle.
    pub l1_base_fee: u64,
    /// Blob base fee scalar retrieved from the bedrock gas oracle.
    pub blob_base_fee_scalar: u64,
    /// Blob base fee retrieved from the bedrock gas oracle.
    pub blob_base_fee: u64,
}
