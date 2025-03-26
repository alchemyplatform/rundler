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

use alloy_network::{EthereumWallet, TxSigner};
use anyhow::Context;
use rundler_provider::{DAGasOracle, EvmProvider};
use rundler_task::TaskSpawner;
use rundler_types::chain::ChainSpec;

mod aws;
use aws::LockingKmsSigner;

mod error;
use alloy_primitives::U256;
pub use error::{Error, Result};

mod funding;
use funding::FunderSettings;

mod local;

mod manager;
use manager::FundingSignerManager;
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
    /// Mnemonic
    Mnemonic {
        /// Mnemonic
        mnemonic: String,
        /// Number of keys to create
        num_keys: usize,
    },
    /// List of kms key ids to lock
    AwsKmsLocking {
        /// Key IDs
        key_ids: Vec<String>,
        /// The number of keys to lock
        to_lock: usize,
        /// Settings
        settings: KmsLockingSettings,
    },
    /// KMS without locking
    AwsKms {
        /// Key IDs
        key_ids: Vec<String>,
    },
    /// KMS funding key and associated keys
    KmsFunding {
        /// Subkey map keyed by the funding key ids
        subkeys_by_key_id: HashMap<String, SigningScheme>,
        /// Lock settings
        lock_settings: Option<KmsLockingSettings>,
        /// Funding settings
        funding_settings: FundingSettings,
    },
}

impl SigningScheme {
    /// Returns true if the signing scheme supports funding
    pub fn supports_funding(&self) -> bool {
        matches!(self, SigningScheme::KmsFunding { .. })
    }
}

/// Create a new signer manager
pub async fn new_signer_manager<
    P: EvmProvider + Clone + 'static,
    T: TaskSpawner,
    D: DAGasOracle + 'static,
>(
    scheme: &SigningScheme,
    auto_fund: bool,
    chain_spec: &ChainSpec,
    provider: P,
    da_gas_oracle: D,
    task_spawner: &T,
) -> Result<Arc<dyn SignerManager>> {
    let manager = match scheme {
        SigningScheme::PrivateKeys { private_keys } => new_private_keys_signer_manager(
            task_spawner,
            provider.clone(),
            private_keys,
            chain_spec,
        ),
        SigningScheme::Mnemonic { mnemonic, num_keys } => new_mnemonic_signer_manager(
            task_spawner,
            provider.clone(),
            mnemonic.clone(),
            *num_keys,
            chain_spec,
        ),
        SigningScheme::AwsKmsLocking {
            key_ids,
            to_lock,
            settings,
        } => {
            new_kms_signer_manager(
                task_spawner,
                provider.clone(),
                key_ids.clone(),
                *to_lock,
                Some(settings),
                chain_spec,
            )
            .await
        }
        SigningScheme::AwsKms { key_ids } => {
            new_kms_signer_manager(
                task_spawner,
                provider.clone(),
                key_ids.clone(),
                key_ids.len(),
                None,
                chain_spec,
            )
            .await
        }
        SigningScheme::KmsFunding {
            subkeys_by_key_id,
            lock_settings,
            funding_settings,
        } => {
            new_kms_funding_signer_manager(
                task_spawner,
                provider.clone(),
                da_gas_oracle,
                subkeys_by_key_id,
                funding_settings,
                lock_settings.as_ref(),
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

fn new_mnemonic_signer_manager<P: EvmProvider + 'static, T: TaskSpawner>(
    task_spawner: &T,
    provider: P,
    mnemonic: String,
    num_keys: usize,
    chain_spec: &ChainSpec,
) -> Result<Arc<dyn SignerManager>> {
    let wallet = local::construct_local_wallet_from_mnemonic(mnemonic, chain_spec.id, num_keys)?;
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
    key_ids: Vec<String>,
    count: usize,
    settings: Option<&KmsLockingSettings>,
    chain_spec: &ChainSpec,
) -> Result<Arc<dyn SignerManager>> {
    let wallet = if let Some(settings) = settings {
        let mut wallet = EthereumWallet::default();
        for _ in 0..count {
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
        wallet
    } else {
        aws::create_wallet_from_key_ids(key_ids, chain_spec.id).await?
    };

    Ok(Arc::new(FundingSignerManager::new(
        wallet,
        None,
        false,
        task_spawner,
        provider,
    )))
}

#[allow(clippy::too_many_arguments)]
async fn new_kms_funding_signer_manager<
    P: EvmProvider + 'static,
    T: TaskSpawner,
    D: DAGasOracle + 'static,
>(
    task_spawner: &T,
    provider: P,
    da_gas_oracle: D,
    subkeys_by_key_id: &HashMap<String, SigningScheme>,
    settings: &FundingSettings,
    lock_settings: Option<&KmsLockingSettings>,
    chain_spec: &ChainSpec,
    auto_fund: bool,
) -> Result<Arc<dyn SignerManager>> {
    let key_ids = subkeys_by_key_id.keys().cloned().collect::<Vec<_>>();

    let (funding_signer, key_id): (Arc<dyn TxSigner<_> + Send + Sync + 'static>, _) =
        if let Some(lock_settings) = lock_settings {
            let signer = LockingKmsSigner::connect(
                task_spawner,
                chain_spec.id,
                key_ids,
                lock_settings.redis_uri.clone(),
                lock_settings.ttl_millis,
            )
            .await?;
            let key_id = signer.key_id().to_string();
            (Arc::new(signer), key_id)
        } else {
            // non-locking, just use the first key id
            let key_id = subkeys_by_key_id
                .iter()
                .next()
                .context("no key ids configured")?
                .0;
            let signer = aws::create_signer_from_key_id(key_id.clone(), chain_spec.id).await?;
            (Arc::new(signer), key_id.clone())
        };

    let subkeys = subkeys_by_key_id
        .get(&key_id)
        .context("funding key id should be in key ids by funding key id")?;

    let wallet = match subkeys {
        SigningScheme::PrivateKeys { private_keys } => {
            local::construct_local_wallet_from_private_keys(private_keys, chain_spec.id)?
        }
        SigningScheme::AwsKms { key_ids } => {
            aws::create_wallet_from_key_ids(key_ids.clone(), chain_spec.id).await?
        }
        SigningScheme::Mnemonic { mnemonic, num_keys } => {
            local::construct_local_wallet_from_mnemonic(mnemonic.clone(), chain_spec.id, *num_keys)?
        }
        _ => Err(anyhow::anyhow!(
            "Signing scheme {subkeys:?} not supported in kms funding"
        ))?,
    };

    let funder_settings = FunderSettings {
        fund_below_balance: settings.fund_below_balance,
        fund_to_balance: settings.fund_to_balance,
        poll_interval: settings.poll_interval,
        poll_max_retries: settings.poll_max_retries,
        priority_fee_multiplier: settings.priority_fee_multiplier,
        base_fee_multiplier: settings.base_fee_multiplier,
        chain_spec: chain_spec.clone(),
        multicall3_address: chain_spec.multicall3_address,
        signer: funding_signer,
        da_gas_oracle: Arc::new(da_gas_oracle),
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
