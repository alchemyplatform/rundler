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

use alloy_primitives::{Address, Bytes};
use rundler_types::da::{DAGasBlockData, DAGasUOData};

use crate::{BlockHashOrNumber, ProviderResult};

/// Trait for a DA gas oracle
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait DAGasOracle: Send + Sync {
    /// Estimate the DA gas for a given user operation's bytes
    ///
    /// Returns the estimated gas, as well as both the UO DA data and the block DA data.
    /// These fields can be safely ignored if the caller is only interested in the gas estimate and
    /// is not implementing any caching logic.
    async fn estimate_da_gas(
        &self,
        uo_bytes: Bytes,
        to: Address,
        block: BlockHashOrNumber,
        gas_price: u128,
    ) -> ProviderResult<(u128, DAGasUOData, DAGasBlockData)>;
}

/// Trait for a DA gas oracle with a synchronous calculation method
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait DAGasOracleSync: DAGasOracle {
    /// Retrieve the DA gas data for a given block. This value can change block to block and
    /// thus must be retrieved fresh from the DA for every block.
    async fn block_data(&self, block: BlockHashOrNumber) -> ProviderResult<DAGasBlockData>;

    /// Retrieve the DA gas data for a given user operation's bytes
    ///
    /// This should not change block to block, but may change after underlying hard forks,
    /// thus a block number is required.
    ///
    /// It is safe to calculate this once and re-use if the same UO is used for multiple calls within
    /// a small time period (no hard forks impacting DA calculations)
    async fn uo_data(
        &self,
        uo_data: Bytes,
        to: Address,
        block: BlockHashOrNumber,
    ) -> ProviderResult<DAGasUOData>;

    /// Synchronously calculate the DA gas for a given user operation data and block data.
    /// These values must have been previously retrieved from a DA oracle of the same implementation
    /// else this function will PANIC.
    ///
    /// This function is intended to allow synchronous DA gas calculation from a cached UO data and a
    /// recently retrieved block data.
    fn calc_da_gas_sync(
        &self,
        uo_data: &DAGasUOData,
        block_data: &DAGasBlockData,
        gas_price: u128,
    ) -> u128;
}
