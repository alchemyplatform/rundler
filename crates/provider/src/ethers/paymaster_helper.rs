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
use ethers::{
    providers::Middleware,
    types::{Address, U256},
};
use rundler_types::{contracts::i_paymaster_helper::IPaymasterHelper, DepositInfo};

use crate::PaymasterHelper;

#[async_trait::async_trait]
impl<M> PaymasterHelper for IPaymasterHelper<M>
where
    M: Middleware + 'static,
{
    async fn get_balances(&self, addresses: Vec<Address>) -> Result<Vec<U256>> {
        Ok(IPaymasterHelper::get_balances(self, addresses).await?)
    }
    async fn get_deposit_info(&self, address: Address) -> Result<DepositInfo> {
        Ok(IPaymasterHelper::get_deposit_info(self, address).await?)
    }
}
