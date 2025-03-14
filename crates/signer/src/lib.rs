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

#![warn(missing_docs, unreachable_pub, unused_crate_dependencies)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
//! Signer implementations for Rundler

use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy_network::EthereumWallet;
use aws::LockingKmsSigner;
use funding::FunderSettings;
use manager::FundingSignerManager;
use rundler_provider::EvmProvider;
use rundler_task::TaskSpawner;
use rundler_types::chain::ChainSpec;

mod aws;

mod error;
use alloy_primitives::U256;
pub use error::{Error, Result};

mod funding;
mod local;

mod manager;
pub use manager::{SignerLease, SignerManager};

pub mod utils;

/// Settings for locking KMS keys
#[derive(Debug, Clone)]
pub struct KmsLockingSettings {
    /// Redis URI
    pub redis_uri: String,
    /// TTL in milliseconds
    pub ttl_millis: u64,
}

/// Settings for funding
#[derive(Default, Debug, Clone)]
pub struct FundingSettings {
    /// Fund below balance
    pub fund_below_balance: U256,
    /// Fund to balance
    pub fund_to_balance: U256,
    /// Poll interval
    pub poll_interval: Duration,
    /// Poll max retries
    pub poll_max_retries: u64,
    /// Priority fee multiplier
    pub priority_fee_multiplier: f64,
    /// Base fee multiplier
    pub base_fee_multiplier: f64,
}

/// Signing scheme for the signer manager
///
/// Schemes:
/// 1. Private keys w/o funding
/// 2. KMS locking w/o funding
/// 3. Mnemonic w/ KMS funding & locking
#[derive(Debug, Clone)]
pub enum SigningScheme {
    /// List of private keys
    PrivateKeys {
        /// Private keys
        private_keys: Vec<String>,
    },
    /// List of kms key ids to lock
    AwsKms {
        /// Key IDs
        key_ids: Vec<String>,
        /// The number of keys to lock
        to_lock: usize,
        /// Settings
        settings: KmsLockingSettings,
    },
    /// KMS funding with associated mnemonic for key derivation
    KmsFundingMnemonics {
        /// Mnemonics by KMS key ID
        mnemonics_by_key_id: HashMap<String, String>,
        /// Lock settings
        lock_settings: KmsLockingSettings,
        /// Funding settings
        funding_settings: FundingSettings,
        /// The number of keys to create
        to_create: usize,
    },
}

impl SigningScheme {
    /// Returns true if the signing scheme supports funding
    pub fn supports_funding(&self) -> bool {
        matches!(self, SigningScheme::KmsFundingMnemonics { .. })
    }
}

/// Create a new signer manager
pub async fn new_signer_manager<P: EvmProvider + Clone + 'static, T: TaskSpawner>(
    scheme: &SigningScheme,
    auto_fund: bool,
    chain_spec: &ChainSpec,
    provider: P,
    task_spawner: &T,
) -> Result<Arc<dyn SignerManager>> {
    let manager = match scheme {
        SigningScheme::PrivateKeys { private_keys } => new_private_keys_signer_manager(
            task_spawner,
            provider.clone(),
            private_keys,
            chain_spec,
        ),
        SigningScheme::AwsKms {
            key_ids,
            to_lock,
            settings,
        } => {
            new_kms_signer_manager(
                task_spawner,
                provider.clone(),
                key_ids,
                *to_lock,
                settings,
                chain_spec,
            )
            .await
        }
        SigningScheme::KmsFundingMnemonics {
            mnemonics_by_key_id,
            lock_settings,
            funding_settings,
            to_create,
        } => {
            new_kms_funding_signer_manager(
                task_spawner,
                provider.clone(),
                *to_create,
                funding_settings,
                mnemonics_by_key_id,
                lock_settings,
                chain_spec,
                auto_fund,
            )
            .await
        }
    }?;

    init_balances(&manager, &provider).await?;
    Ok(manager)
}

fn new_private_keys_signer_manager<P: EvmProvider + 'static, T: TaskSpawner>(
    task_spawner: &T,
    provider: P,
    private_keys: &[String],
    chain_spec: &ChainSpec,
) -> Result<Arc<dyn SignerManager>> {
    let wallet = local::construct_local_wallet_from_private_keys(private_keys, chain_spec.id)?;
    Ok(Arc::new(FundingSignerManager::new(
        wallet,
        None,
        false,
        task_spawner,
        provider,
    )))
}

async fn new_kms_signer_manager<P: EvmProvider + 'static, T: TaskSpawner>(
    task_spawner: &T,
    provider: P,
    key_ids: &[String],
    to_lock: usize,
    settings: &KmsLockingSettings,
    chain_spec: &ChainSpec,
) -> Result<Arc<dyn SignerManager>> {
    let mut wallet = EthereumWallet::default();

    for _ in 0..to_lock {
        let signer = LockingKmsSigner::connect(
            task_spawner,
            chain_spec.id,
            key_ids.to_vec(),
            settings.redis_uri.clone(),
            settings.ttl_millis,
        )
        .await?;
        wallet.register_signer(signer);
    }

    Ok(Arc::new(FundingSignerManager::new(
        wallet,
        None,
        false,
        task_spawner,
        provider,
    )))
}

#[allow(clippy::too_many_arguments)]
async fn new_kms_funding_signer_manager<P: EvmProvider + 'static, T: TaskSpawner>(
    task_spawner: &T,
    provider: P,
    to_create: usize,
    settings: &FundingSettings,
    mnemonics_by_key_id: &HashMap<String, String>,
    lock_settings: &KmsLockingSettings,
    chain_spec: &ChainSpec,
    auto_fund: bool,
) -> Result<Arc<dyn SignerManager>> {
    let key_ids = mnemonics_by_key_id.keys().cloned().collect::<Vec<_>>();
    let funding_signer = LockingKmsSigner::connect(
        task_spawner,
        chain_spec.id,
        key_ids,
        lock_settings.redis_uri.clone(),
        lock_settings.ttl_millis,
    )
    .await?;

    let mnemonic = mnemonics_by_key_id
        .get(funding_signer.key_id())
        .expect("key id should be in mnemonics by key id")
        .clone();

    let wallet = local::construct_local_wallet_from_mnemonic(mnemonic, chain_spec.id, to_create)?;

    let funder_settings = FunderSettings {
        fund_below_balance: settings.fund_below_balance,
        fund_to_balance: settings.fund_to_balance,
        poll_interval: settings.poll_interval,
        poll_max_retries: settings.poll_max_retries,
        priority_fee_multiplier: settings.priority_fee_multiplier,
        base_fee_multiplier: settings.base_fee_multiplier,
        chain_id: chain_spec.id,
        multicall3_address: chain_spec.multicall3_address,
        signer: Arc::new(funding_signer),
    };

    Ok(Arc::new(FundingSignerManager::new(
        wallet,
        Some(funder_settings),
        auto_fund,
        task_spawner,
        provider,
    )))
}

async fn init_balances<P: EvmProvider>(
    manager: &Arc<dyn SignerManager>,
    provider: &P,
) -> Result<()> {
    let balances = provider.get_balances(manager.addresses()).await?;
    manager.update_balances(balances);
    Ok(())
}
