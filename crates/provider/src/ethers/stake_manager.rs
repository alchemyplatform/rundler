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

use anyhow::Result;
use ethers::{providers::Middleware, types::Address};
use rundler_types::{contracts::i_stake_manager::IStakeManager, DepositInfo};

use crate::StakeManager;

#[async_trait::async_trait]
impl<M> StakeManager for IStakeManager<M>
where
    M: Middleware + 'static,
{
    async fn get_deposit_info(&self, address: Address) -> Result<DepositInfo> {
        Ok(IStakeManager::get_deposit_info(self, address).await?)
    }
}
