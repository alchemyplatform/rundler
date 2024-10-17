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

//! Providers traits for tasks.

use rundler_provider::{DAGasOracleSync, EntryPointProvider, EvmProvider};
use rundler_types::{
    v0_6::UserOperation as UserOperationV0_6, v0_7::UserOperation as UserOperationV0_7,
};

/// A trait that provides access to various providers.
pub trait Providers: Clone {
    /// The EVM provider.
    type Evm: EvmProvider + Clone;

    /// The entry point provider for v0.6.
    type EntryPointV0_6: EntryPointProvider<UserOperationV0_6> + Clone;

    /// The entry point provider for v0.7.
    type EntryPointV0_7: EntryPointProvider<UserOperationV0_7> + Clone;

    /// The DA gas oracle sync provider.
    type DAGasOracleSync: DAGasOracleSync + Clone;

    /// Returns the EVM provider.
    fn evm(&self) -> &Self::Evm;

    /// Returns the entry point provider for v0.6.
    fn ep_v0_6(&self) -> &Option<Self::EntryPointV0_6>;

    /// Returns the entry point provider for v0.7.
    fn ep_v0_7(&self) -> &Option<Self::EntryPointV0_7>;

    /// Returns the DA gas oracle sync provider.
    fn da_gas_oracle_sync(&self) -> &Option<Self::DAGasOracleSync>;
}
