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

use alloy_chains::NamedChain;

/// Known chain IDs that use the Optimism Bedrock stack
pub const OP_BEDROCK_CHAIN_IDS: &[u64] = &[
    NamedChain::Optimism as u64,
    NamedChain::OptimismGoerli as u64,
    NamedChain::OptimismSepolia as u64,
    NamedChain::Base as u64,
    NamedChain::BaseGoerli as u64,
    NamedChain::BaseSepolia as u64,
];

// TODO use chain from ethers types once my PR is merged into ethers
// https://github.com/gakonst/ethers-rs/pull/2657
/// Known chain IDs for the Base ecosystem
pub const ARBITRUM_CHAIN_IDS: &[u64] = &[
    NamedChain::Arbitrum as u64,
    NamedChain::ArbitrumGoerli as u64,
    NamedChain::ArbitrumSepolia as u64,
    NamedChain::ArbitrumNova as u64,
];

/// Known chain IDs for the Base ecosystem
pub const BASE_CHAIN_IDS: &[u64] = &[
    NamedChain::Base as u64,
    NamedChain::BaseGoerli as u64,
    NamedChain::BaseSepolia as u64,
];

/// Known chain IDs for the Polygon ecosystem
pub const POLYGON_CHAIN_IDS: &[u64] = &[
    NamedChain::Polygon as u64,
    NamedChain::PolygonMumbai as u64,
    80002, // PolygonAmoy - Change to named chain once there is a new release on alloy-rs/chains
];

/// Return true if the chain ID has a dynamic preVerificationGas field
pub fn is_dynamic_pvg(chain_id: u64) -> bool {
    ARBITRUM_CHAIN_IDS.contains(&chain_id) || OP_BEDROCK_CHAIN_IDS.contains(&chain_id)
}
