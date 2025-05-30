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

use alloy_network::EthereumWallet;
use alloy_signer::Signer;
use alloy_signer_local::{
    coins_bip39::English, LocalSignerError, MnemonicBuilder, PrivateKeySigner,
};
use anyhow::Context;
use secrecy::{ExposeSecret, SecretString};

use crate::{Error, Result};

pub(crate) fn construct_local_wallet_from_private_keys(
    private_keys: &[SecretString],
    chain_id: u64,
) -> Result<EthereumWallet> {
    let mut wallet = EthereumWallet::default();

    for private_key in private_keys {
        let signer = private_key
            .expose_secret()
            .parse::<PrivateKeySigner>()
            .context("failed to parse private key signer")?
            .with_chain_id(Some(chain_id));
        wallet.register_signer(signer);
    }

    Ok(wallet)
}

pub(crate) fn construct_local_wallet_from_mnemonic(
    mnemonic: SecretString,
    chain_id: u64,
    count: usize,
) -> Result<EthereumWallet> {
    let mut wallet = EthereumWallet::default();
    let builder = MnemonicBuilder::<English>::default().phrase(mnemonic.expose_secret());

    for i in 0..count {
        let signer = builder
            .clone()
            .index(i as u32)?
            .build()?
            .with_chain_id(Some(chain_id));
        wallet.register_signer(signer);
    }

    Ok(wallet)
}

impl From<LocalSignerError> for Error {
    fn from(value: LocalSignerError) -> Self {
        Error::SigningError(value.to_string())
    }
}
