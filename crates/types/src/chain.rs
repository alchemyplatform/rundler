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
