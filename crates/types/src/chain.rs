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

//! Grouped/Labeled chain IDs for various networks

use ethers::types::Chain;

/// Known chain IDs that use the Optimism Bedrock stack
pub const OP_BEDROCK_CHAIN_IDS: &[u64] = &[
    Chain::Optimism as u64,
    Chain::OptimismGoerli as u64,
    11155420, // OptimismSepolia
    Chain::Base as u64,
    Chain::BaseGoerli as u64,
    84532, // BaseSepolia
];

// TODO use chain from ethers types once my PR is merged into ethers
// https://github.com/gakonst/ethers-rs/pull/2657
/// Known chain IDs for the Base ecosystem
pub const ARBITRUM_CHAIN_IDS: &[u64] = &[
    Chain::Arbitrum as u64,
    Chain::ArbitrumGoerli as u64,
    421614, /* ArbitrumSepolia */
    Chain::ArbitrumNova as u64,
];

/// Known chain IDs for the Base ecosystem
pub const BASE_CHAIN_IDS: &[u64] = &[
    Chain::Base as u64,
    Chain::BaseGoerli as u64,
    84532, /* BaseSepolia */
];

/// Known chain IDs for the Polygon ecosystem
pub const POLYGON_CHAIN_IDS: &[u64] = &[Chain::Polygon as u64, Chain::PolygonMumbai as u64];

/// Return true if the chain ID has a dynamic preVerificationGas field
pub fn is_dynamic_pvg(chain_id: u64) -> bool {
    ARBITRUM_CHAIN_IDS.contains(&chain_id) || OP_BEDROCK_CHAIN_IDS.contains(&chain_id)
}
