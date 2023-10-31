use ethers::types::Chain;

pub const OP_BEDROCK_CHAIN_IDS: &[u64] = &[
    Chain::Optimism as u64,
    Chain::OptimismGoerli as u64,
    8453, // Base
    Chain::BaseGoerli as u64,
];

// TODO use chain from ethers types once my PR is merged into ethers
pub const ARBITRUM_CHAIN_IDS: &[u64] =
    &[Chain::Arbitrum as u64, Chain::ArbitrumGoerli as u64, 421614];

pub const BASE_CHAIN_IDS: &[u64] = &[8453, Chain::BaseGoerli as u64];

pub const POLYGON_CHAIN_IDS: &[u64] = &[Chain::Polygon as u64, Chain::PolygonMumbai as u64];
