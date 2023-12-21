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

use ethers::types::Address;
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_types::contracts::i_stake_manager::DepositInfo;

/// Trait for interacting with an stake manager contract.
/// Implemented for the v0.6 version of the stake manager contract.
/// [Contracts can be found here](https://github.com/eth-infinitism/account-abstraction/tree/v0.6.0).
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait StakeManager: Send + Sync + 'static {
    /// Get the deposit info from address
    async fn get_deposit_info(&self, address: Address) -> anyhow::Result<DepositInfo>;
}
