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
use alloy_primitives::{Address, Signature};
use anyhow::Context;
use rundler_provider::{DAGasOracle, EvmProvider};
use rundler_task::TaskSpawner;
use rundler_types::{EntryPointVersion, chain::ChainSpec};
use secrecy::SecretString;

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
pub use manager::{CachedAccountState, SignerLease, SignerManager};

pub mod mapping;
use mapping::{FundingGroup, MappedSigner, SignerCounts, SignerMapping};

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
        private_keys: Vec<SecretString>,
    },
    /// Mnemonic
    Mnemonic {
        /// Mnemonic
        mnemonic: SecretString,
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
    /// KMS funding keys with signers pinned to EntryPoints by a signer mapping
    KmsFundingMapped {
        /// Signer mapping
        mapping: SignerMapping,
        /// Signers per funding group for each EntryPoint
        counts: SignerCounts,
        /// Funding key ids; position 0/1/2 is funding group a/b/c
        funding_key_ids: Vec<String>,
        /// Enabled EntryPoints
        enabled_entry_points: Vec<EntryPointVersion>,
        /// Lock settings
        lock_settings: Option<KmsLockingSettings>,
        /// Funding settings
        funding_settings: FundingSettings,
    },
}

impl SigningScheme {
    /// Returns true if the signing scheme supports funding
    pub fn supports_funding(&self) -> bool {
        matches!(
            self,
            SigningScheme::KmsFunding { .. } | SigningScheme::KmsFundingMapped { .. }
        )
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
        SigningScheme::KmsFundingMapped {
            mapping,
            counts,
            funding_key_ids,
            enabled_entry_points,
            lock_settings,
            funding_settings,
        } => {
            new_kms_funding_mapped_signer_manager(
                task_spawner,
                provider.clone(),
                da_gas_oracle,
                MappedSchemeArgs {
                    mapping,
                    counts,
                    funding_key_ids,
                    enabled_entry_points,
                    lock_settings: lock_settings.as_ref(),
                    settings: funding_settings,
                },
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
    private_keys: &[SecretString],
    chain_spec: &ChainSpec,
) -> Result<Arc<dyn SignerManager>> {
    let wallet = local::construct_local_wallet_from_private_keys(private_keys, chain_spec.id)?;
    Ok(Arc::new(FundingSignerManager::new(
        chain_spec.id,
        wallet,
        None,
        false,
        task_spawner,
        provider,
        HashMap::new(),
    )))
}

fn new_mnemonic_signer_manager<P: EvmProvider + 'static, T: TaskSpawner>(
    task_spawner: &T,
    provider: P,
    mnemonic: SecretString,
    num_keys: usize,
    chain_spec: &ChainSpec,
) -> Result<Arc<dyn SignerManager>> {
    let wallet = local::construct_local_wallet_from_mnemonic(mnemonic, chain_spec.id, num_keys)?;
    Ok(Arc::new(FundingSignerManager::new(
        chain_spec.id,
        wallet,
        None,
        false,
        task_spawner,
        provider,
        HashMap::new(),
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
        chain_spec.id,
        wallet,
        None,
        false,
        task_spawner,
        provider,
        HashMap::new(),
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
        chain_spec.id,
        wallet,
        Some(funder_settings),
        auto_fund,
        task_spawner,
        provider,
        HashMap::new(),
    )))
}

struct MappedSchemeArgs<'a> {
    mapping: &'a SignerMapping,
    counts: &'a SignerCounts,
    funding_key_ids: &'a [String],
    enabled_entry_points: &'a [EntryPointVersion],
    lock_settings: Option<&'a KmsLockingSettings>,
    settings: &'a FundingSettings,
}

async fn new_kms_funding_mapped_signer_manager<
    P: EvmProvider + 'static,
    T: TaskSpawner,
    D: DAGasOracle + 'static,
>(
    task_spawner: &T,
    provider: P,
    da_gas_oracle: D,
    args: MappedSchemeArgs<'_>,
    chain_spec: &ChainSpec,
    auto_fund: bool,
) -> Result<Arc<dyn SignerManager>> {
    let MappedSchemeArgs {
        mapping,
        counts,
        funding_key_ids,
        enabled_entry_points,
        lock_settings,
        settings,
    } = args;
    mapping
        .validate_against(enabled_entry_points, counts, funding_key_ids)
        .context("signer mapping does not match the signer configuration")?;

    // Funding keys are tried in a/b/c order; the Redis lock decides which one this pod gets.
    let (funding_signer, funding_key_id): (Arc<dyn TxSigner<_> + Send + Sync + 'static>, _) =
        if let Some(lock_settings) = lock_settings {
            let signer = LockingKmsSigner::connect(
                task_spawner,
                chain_spec.id,
                funding_key_ids.to_vec(),
                lock_settings.redis_uri.clone(),
                lock_settings.ttl_millis,
            )
            .await?;
            let key_id = signer.key_id().to_string();
            (Arc::new(signer), key_id)
        } else {
            let key_id = funding_key_ids[0].clone();
            let signer = aws::create_signer_from_key_id(key_id.clone(), chain_spec.id).await?;
            (Arc::new(signer), key_id)
        };

    let group = FundingGroup::for_funding_key(funding_key_ids, &funding_key_id)
        .context("locked funding key should be one of the configured funding keys")?;
    let selected = mapping
        .select(group, counts)
        .context("should select signers from the signer mapping")?;

    let key_ids = selected.iter().map(|s| s.kms_key_id.clone()).collect();
    let signers = aws::create_signers_from_key_ids(key_ids, chain_spec.id).await?;
    let (wallet, entry_points) = mapped_wallet(&selected, signers)?;

    let per_entry_point = counts
        .entries()
        .iter()
        .map(|(ep, n)| format!("{}: {n}", mapping::entry_point_name(*ep)))
        .collect::<Vec<_>>()
        .join(", ");
    tracing::info!(
        "signer mapping: funding group {group} = funding key {funding_key_id} ({}); signers per entry point: {per_entry_point}",
        funding_signer.address()
    );

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
        chain_spec.id,
        wallet,
        Some(funder_settings),
        auto_fund,
        task_spawner,
        provider,
        entry_points,
    )))
}

/// Register the selected signers, refusing any whose key does not resolve to the
/// address written in the mapping.
fn mapped_wallet<S>(
    selected: &[MappedSigner],
    signers: Vec<S>,
) -> Result<(EthereumWallet, HashMap<Address, EntryPointVersion>)>
where
    S: TxSigner<Signature> + Send + Sync + 'static,
{
    if selected.len() != signers.len() {
        Err(anyhow::anyhow!(
            "expected {} signers from the mapping, got {}",
            selected.len(),
            signers.len()
        ))?;
    }
    let mut wallet = EthereumWallet::default();
    let mut entry_points = HashMap::new();
    for (mapped, signer) in selected.iter().zip(signers) {
        let actual = signer.address();
        if actual != mapped.address {
            Err(anyhow::anyhow!(
                "signer mapping mismatch: KMS key {} resolves to {actual}, but the mapping says {}",
                mapped.kms_key_id,
                mapped.address
            ))?;
        }
        entry_points.insert(actual, mapped.entry_point);
        wallet.register_signer(signer);
    }
    Ok((wallet, entry_points))
}

async fn init_balances<P: EvmProvider>(
    manager: &Arc<dyn SignerManager>,
    provider: &P,
) -> Result<()> {
    let balances = match provider.get_balances(manager.addresses()).await {
        Ok(balances) => balances,
        Err(e) => {
            tracing::warn!("Error initializing balances for signer manager: {e}");
            return Ok(());
        }
    };
    manager.update_balances(balances);
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_signer_local::PrivateKeySigner;

    use super::*;

    const GOLDEN: &str = include_str!("../testdata/signer-mapping.golden.json");

    /// The golden fixture's addresses are derived from private keys 1..=24, in file order.
    fn golden_signer(index: usize) -> PrivateKeySigner {
        let mut key = [0u8; 32];
        key[31] = (index + 1) as u8;
        PrivateKeySigner::from_slice(&key).unwrap()
    }

    fn signer_for(mapping: &SignerMapping, mapped: &MappedSigner) -> PrivateKeySigner {
        let index = mapping
            .signers()
            .iter()
            .position(|s| s.kms_key_id == mapped.kms_key_id)
            .unwrap();
        golden_signer(index)
    }

    #[test]
    fn mapped_wallet_registers_selected_signers_with_tags() {
        let mapping = SignerMapping::from_json_str(GOLDEN).unwrap();
        let counts: SignerCounts = "v0.7=2,v0.6=1".parse().unwrap();
        let selected = mapping.select(FundingGroup::B, &counts).unwrap();
        let signers = selected.iter().map(|s| signer_for(&mapping, s)).collect();

        let (wallet, entry_points) = mapped_wallet(&selected, signers).unwrap();

        let mut registered: Vec<Address> =
            alloy_network::NetworkWallet::<alloy_network::AnyNetwork>::signer_addresses(&wallet)
                .collect();
        registered.sort();
        let mut expected: Vec<Address> = selected.iter().map(|s| s.address).collect();
        expected.sort();
        assert_eq!(registered, expected);
        for s in &selected {
            assert_eq!(entry_points.get(&s.address), Some(&s.entry_point));
            assert_eq!(s.group, FundingGroup::B);
        }
    }

    #[test]
    fn mapped_wallet_rejects_wrong_key() {
        let mapping = SignerMapping::from_json_str(GOLDEN).unwrap();
        let counts: SignerCounts = "v0.7=2".parse().unwrap();
        let selected = mapping.select(FundingGroup::A, &counts).unwrap();
        // Second signer is swapped for a key that resolves to a different address.
        let signers = vec![signer_for(&mapping, &selected[0]), golden_signer(23)];

        let err = mapped_wallet(&selected, signers).unwrap_err().to_string();
        assert!(err.contains("signer mapping mismatch"), "{err}");
        assert!(err.contains(&selected[1].kms_key_id), "{err}");
    }

    #[test]
    fn mapped_wallet_rejects_count_mismatch() {
        let mapping = SignerMapping::from_json_str(GOLDEN).unwrap();
        let selected = mapping
            .select(FundingGroup::A, &"v0.7=2".parse().unwrap())
            .unwrap();
        let signers = vec![signer_for(&mapping, &selected[0])];
        assert!(mapped_wallet(&selected, signers).is_err());
    }

    #[test]
    fn funding_group_follows_funding_key_position() {
        let ids = vec![
            "fund-a".to_string(),
            "fund-b".to_string(),
            "fund-c".to_string(),
        ];
        for (id, group) in ids.iter().zip(FundingGroup::ALL) {
            assert_eq!(FundingGroup::for_funding_key(&ids, id), Some(group));
        }
    }
}
