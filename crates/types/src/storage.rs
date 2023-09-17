//! Types for interacting with EVM storage

use ethers::types::{Address, U256};

/// An EVM storage slot
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct StorageSlot {
    /// The address of the contract owning this slot
    pub address: Address,
    /// The storage slot
    pub slot: U256,
}
