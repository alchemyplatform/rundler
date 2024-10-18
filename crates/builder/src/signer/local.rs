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

use alloy_signer::Signer as _;
use alloy_signer_local::PrivateKeySigner;
use anyhow::Context;
use rundler_provider::EvmProvider;
use rundler_task::TaskSpawner;
/// A local signer handle
#[derive(Debug)]
pub(crate) struct LocalSigner {
    pub(crate) signer: PrivateKeySigner,
}

impl LocalSigner {
    pub(crate) async fn connect<P: EvmProvider + 'static, T: TaskSpawner>(
        task_spawner: &T,
        provider: P,
        chain_id: u64,
        private_key: String,
    ) -> anyhow::Result<Self> {
        let signer = private_key
            .parse::<PrivateKeySigner>()
            .context("should create signer")?;

        task_spawner.spawn(Box::pin(super::monitor_account_balance(
            signer.address(),
            provider,
        )));

        Ok(Self {
            signer: signer.with_chain_id(Some(chain_id)),
        })
    }
}
