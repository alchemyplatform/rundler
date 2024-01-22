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

use ethers::types::{Address, U256};
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_types::DepositInfo;

/// Trait for interacting with the PaymasterHelper contract
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait PaymasterHelper: Send + Sync + 'static {
    /// Get the deposit info from address
    async fn get_balances(&self, addresses: Vec<Address>) -> anyhow::Result<Vec<U256>>;
    /// Get deposit info for paymaster
    async fn get_deposit_info(&self, address: Address) -> anyhow::Result<DepositInfo>;
}
