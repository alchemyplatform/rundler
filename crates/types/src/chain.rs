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
    8453, // Base
    Chain::BaseGoerli as u64,
];

/// Known chain IDs that use the Arbitrum stack
pub const ARBITRUM_CHAIN_IDS: &[u64] = &[Chain::Arbitrum as u64, Chain::ArbitrumGoerli as u64];

/// Known chain IDs for the Base ecosystem
pub const BASE_CHAIN_IDS: &[u64] = &[8453, Chain::BaseGoerli as u64];

/// Known chain IDs for the Polygon ecosystem
pub const POLYGON_CHAIN_IDS: &[u64] = &[Chain::Polygon as u64, Chain::PolygonMumbai as u64];
