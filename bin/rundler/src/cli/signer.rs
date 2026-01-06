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

use std::time::Duration;

use alloy_primitives::U256;
use anyhow::{Context, bail};
use clap::Args;
use rundler_signer::{FundingSettings, KmsLockingSettings, SigningScheme};
use secrecy::SecretString;

#[derive(Args, Debug)]
#[command(next_help_heading = "SIGNER")]
pub struct SignerArgs {
    /// Private keys to use for signing transactions
    #[arg(
        long = "signer.private_keys",
        name = "signer.private_keys",
        env = "SIGNER_PRIVATE_KEYS",
        value_delimiter = ',',
        value_parser = super::parse_secret
    )]
    pub private_keys: Vec<SecretString>,

    /// Mnemonic to use for signing transactions
    #[arg(
        long = "signer.mnemonic",
        name = "signer.mnemonic",
        env = "SIGNER_MNEMONIC",
        value_parser = super::parse_secret
    )]
    pub mnemonic: Option<SecretString>,

    /// AWS KMS key IDs to use for signing transactions
    #[arg(
        long = "signer.aws_kms_key_ids",
        name = "signer.aws_kms_key_ids",
        env = "SIGNER_AWS_KMS_KEY_IDS",
        value_delimiter = ','
    )]
    pub aws_kms_key_ids: Vec<String>,

    #[arg(
        long = "signer.aws_kms_grouped_keys",
        name = "signer.aws_kms_grouped_keys",
        env = "SIGNER_AWS_KMS_GROUPED_KEYS",
        value_delimiter = ','
    )]
    pub aws_kms_grouped_keys: Vec<String>,

    /// Whether to enable KMS funding
    #[arg(
        long = "signer.enable_kms_funding",
        name = "signer.enable_kms_funding",
        env = "SIGNER_ENABLE_KMS_FUNDING",
        default_value = "false"
    )]
    pub enable_kms_funding: bool,

    /// Whether to enable KMS locking
    #[arg(
        long = "signer.enable_kms_locking",
        name = "signer.enable_kms_locking",
        env = "SIGNER_ENABLE_KMS_LOCKING",
        default_value = "false"
    )]
    pub enable_kms_locking: bool,

    /// Redis URI to use for KMS leasing
    #[arg(
        long = "signer.redis_uri",
        name = "signer.redis_uri",
        env = "SIGNER_REDIS_URI",
        default_value = ""
    )]
    pub redis_uri: String,

    /// Redis lock TTL in milliseconds
    #[arg(
        long = "signer.redis_lock_ttl_millis",
        name = "signer.redis_lock_ttl_millis",
        env = "SIGNER_REDIS_LOCK_TTL_MILLIS",
        default_value = "60000"
    )]
    pub redis_lock_ttl_millis: u64,

    /// The balance below which signers will be funded
    #[arg(
        long = "signer.fund_below",
        name = "signer.fund_below",
        env = "SIGNER_FUND_BELOW",
        value_parser = alloy_primitives::utils::parse_ether
    )]
    pub fund_below: Option<U256>,

    /// The balance to fund signers to
    #[arg(
        long = "signer.fund_to",
        name = "signer.fund_to",
        env = "SIGNER_FUND_TO",
        value_parser = alloy_primitives::utils::parse_ether
    )]
    pub fund_to: Option<U256>,

    /// The interval to poll for funding
    #[arg(
        long = "signer.funding_txn_poll_interval_ms",
        name = "signer.funding_txn_poll_interval_ms",
        env = "SIGNER_FUNDING_TXN_POLL_INTERVAL_MS",
        default_value = "1000"
    )]
    pub funding_txn_poll_interval_ms: u64,

    /// The number of retries to poll for funding
    #[arg(
        long = "signer.funding_txn_poll_max_retries",
        name = "signer.funding_txn_poll_max_retries",
        env = "SIGNER_FUNDING_TXN_POLL_MAX_RETRIES",
        default_value = "20"
    )]
    pub funding_txn_poll_max_retries: u64,

    /// The multiplier for the priority fee
    #[arg(
        long = "signer.funding_txn_priority_fee_multiplier",
        name = "signer.funding_txn_priority_fee_multiplier",
        env = "SIGNER_FUNDING_TXN_PRIORITY_FEE_MULTIPLIER",
        default_value = "2.0"
    )]
    pub funding_txn_priority_fee_multiplier: f64,

    /// The multiplier for the base fee
    #[arg(
        long = "signer.funding_txn_base_fee_multiplier",
        name = "signer.funding_txn_base_fee_multiplier",
        env = "SIGNER_FUNDING_TXN_BASE_FEE_MULTIPLIER",
        default_value = "2.0"
    )]
    pub funding_txn_base_fee_multiplier: f64,
}

impl SignerArgs {
    pub fn signing_scheme(&self, num_signers: Option<usize>) -> anyhow::Result<SigningScheme> {
        if self.enable_kms_funding {
            return self.funding_signer_scheme(num_signers);
        }

        if !self.private_keys.is_empty() {
            if num_signers.is_some_and(|num_signers| num_signers > self.private_keys.len()) {
                bail!(
                    "Found {} private keys, but need {} keys for the number of builders. You may need to disable one of the entry points.",
                    self.private_keys.len(),
                    num_signers.unwrap()
                );
            }

            return Ok(SigningScheme::PrivateKeys {
                private_keys: self.private_keys.clone(),
            });
        }

        if let Some(mnemonic) = &self.mnemonic {
            return Ok(SigningScheme::Mnemonic {
                mnemonic: mnemonic.clone(),
                num_keys: num_signers.unwrap_or(1),
            });
        }

        if !self.aws_kms_key_ids.is_empty() {
            if num_signers.is_some_and(|num_signers| num_signers > self.aws_kms_key_ids.len()) {
                bail!(
                    "Not enough AWS KMS key IDs for the number of builders. Need {} keys, found {}. You may need to disable one of the entry points.",
                    num_signers.unwrap(),
                    self.aws_kms_key_ids.len()
                );
            }

            if self.enable_kms_locking {
                return Ok(SigningScheme::AwsKmsLocking {
                    key_ids: self.aws_kms_key_ids.clone(),
                    to_lock: num_signers.unwrap_or(self.aws_kms_key_ids.len()),
                    settings: KmsLockingSettings {
                        redis_uri: self.redis_uri.clone(),
                        ttl_millis: self.redis_lock_ttl_millis,
                    },
                });
            } else {
                return Ok(SigningScheme::AwsKms {
                    key_ids: self.aws_kms_key_ids.clone(),
                });
            }
        }

        bail!(
            "No signing scheme provided (unfunded). Provide either signer.private_keys, signer.mnemonic, or signer.aws_kms_key_ids"
        );
    }

    fn funding_signer_scheme(&self, num_signers: Option<usize>) -> anyhow::Result<SigningScheme> {
        if self.aws_kms_key_ids.is_empty() {
            bail!(
                "AWS KMS key IDs are not set and KMS funding is enabled. Please set signer.aws_kms_key_ids"
            );
        };
        let lock_settings = if self.enable_kms_locking {
            Some(KmsLockingSettings {
                redis_uri: self.redis_uri.clone(),
                ttl_millis: self.redis_lock_ttl_millis,
            })
        } else {
            None
        };

        let subkeys_by_key_id = if !self.aws_kms_grouped_keys.is_empty() {
            let num_signers =
                num_signers.context("Num signers must be set when using AWS KMS grouped keys")?;
            if num_signers == 0 {
                bail!("Number of signers must be greater than 0");
            }

            if self.aws_kms_grouped_keys.len() / num_signers < self.aws_kms_key_ids.len() {
                bail!(
                    "Number of AWS KMS key groups ({} / {}) is less than the number of AWS KMS key IDs ({}).",
                    self.aws_kms_grouped_keys.len(),
                    num_signers,
                    self.aws_kms_key_ids.len()
                );
            }

            let aws_kms_key_groups = self
                .aws_kms_grouped_keys
                .chunks_exact(num_signers)
                .map(|group| group.to_vec())
                .collect::<Vec<_>>();

            self.aws_kms_key_ids
                .iter()
                .zip(aws_kms_key_groups.iter())
                .map(|(key_id, group)| {
                    (
                        key_id.to_string(),
                        SigningScheme::AwsKms {
                            key_ids: group.clone(),
                        },
                    )
                })
                .collect()
        } else if !self.private_keys.is_empty() {
            if num_signers.is_some_and(|num_signers| num_signers > self.private_keys.len()) {
                bail!(
                    "Number of private keys ({}) is less than the number of builders ({}).",
                    self.private_keys.len(),
                    num_signers.unwrap()
                );
            }
            let keys = SigningScheme::PrivateKeys {
                private_keys: self.private_keys.clone(),
            };

            self.aws_kms_key_ids
                .iter()
                .map(|key_id| (key_id.to_string(), keys.clone()))
                .collect()
        } else if self.mnemonic.is_some() {
            let keys = SigningScheme::Mnemonic {
                mnemonic: self.mnemonic.clone().unwrap(),
                num_keys: num_signers.unwrap_or(1),
            };

            self.aws_kms_key_ids
                .iter()
                .map(|key_id| (key_id.to_string(), keys.clone()))
                .collect()
        } else {
            bail!(
                "No signing scheme provided (funded). Provide either signer.private_keys, signer.mnemonic, signer.aws_kms_key_groups"
            );
        };

        Ok(SigningScheme::KmsFunding {
            subkeys_by_key_id,
            lock_settings,
            funding_settings: FundingSettings {
                fund_below_balance: self.fund_below.context("Fund below balance not set")?,
                fund_to_balance: self.fund_to.context("Fund to balance not set")?,
                poll_interval: Duration::from_millis(self.funding_txn_poll_interval_ms),
                poll_max_retries: self.funding_txn_poll_max_retries,
                priority_fee_multiplier: self.funding_txn_priority_fee_multiplier,
                base_fee_multiplier: self.funding_txn_base_fee_multiplier,
            },
        })
    }
}
