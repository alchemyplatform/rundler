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

use std::{collections::HashMap, time::Duration};

use alloy_primitives::U256;
use anyhow::{bail, Context};
use clap::Args;
use rundler_signer::{FundingSettings, KmsLockingSettings, SigningScheme};

#[derive(Args, Debug)]
#[command(next_help_heading = "SIGNER")]
pub struct SignerArgs {
    /// Private keys to use for signing transactions
    ///
    /// Cannot use both `builder.private_keys` and `builder.aws_kms_key_ids` at the same time.
    #[arg(
        long = "signer.private_keys",
        name = "signer.private_keys",
        env = "SIGNER_PRIVATE_KEYS",
        value_delimiter = ','
    )]
    pub private_keys: Vec<String>,

    /// AWS KMS key IDs to use for signing transactions
    #[arg(
        long = "signer.aws_kms_key_ids",
        name = "signer.aws_kms_key_ids",
        env = "SIGNER_AWS_KMS_KEY_IDS",
        value_delimiter = ','
    )]
    pub aws_kms_key_ids: Vec<String>,

    /// TODO how do we want to handle this?
    /// AWS KMS mnemonics to use for signing transactions
    #[arg(
        long = "signer.aws_kms_key_id_and_mnemonics",
        name = "signer.aws_kms_key_id_and_mnemonics",
        env = "SIGNER_AWS_KMS_KEY_ID_AND_MNEMONICS",
        value_delimiter = ','
    )]
    pub aws_kms_key_id_and_mnemonics: Vec<String>,

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

    /// Whether to automatically fund signers
    #[arg(
        long = "signer.auto_fund",
        name = "signer.auto_fund",
        default_value = "true"
    )]
    pub auto_fund: bool,

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
        long = "signer.funding_priority_fee_multiplier",
        name = "signer.funding_priority_fee_multiplier",
        env = "SIGNER_FUNDING_PRIORITY_FEE_MULTIPLIER",
        default_value = "2.0"
    )]
    pub funding_priority_fee_multiplier: f64,

    /// The multiplier for the base fee
    #[arg(
        long = "signer.funding_base_fee_multiplier",
        name = "signer.funding_base_fee_multiplier",
        env = "SIGNER_FUNDING_BASE_FEE_MULTIPLIER",
        default_value = "2.0"
    )]
    pub funding_base_fee_multiplier: f64,
}

impl SignerArgs {
    pub fn signing_scheme(&self, num_signers: usize) -> anyhow::Result<SigningScheme> {
        if !self.aws_kms_key_id_and_mnemonics.is_empty() {
            let mut mnemonics_by_key_id = HashMap::new();
            for key_id_and_mnemonic in self.aws_kms_key_id_and_mnemonics.iter() {
                let (key_id, mnemonic) = key_id_and_mnemonic.split_once(':').unwrap();
                mnemonics_by_key_id.insert(key_id.to_string(), mnemonic.to_string());
            }

            return Ok(SigningScheme::KmsFundingMnemonics {
                mnemonics_by_key_id,
                lock_settings: KmsLockingSettings {
                    redis_uri: self.redis_uri.clone(),
                    ttl_millis: self.redis_lock_ttl_millis,
                },
                funding_settings: FundingSettings {
                    fund_below_balance: self.fund_below.context("Fund below balance not set")?,
                    fund_to_balance: self.fund_to.context("Fund to balance not set")?,
                    poll_interval: Duration::from_millis(self.funding_txn_poll_interval_ms),
                    poll_max_retries: self.funding_txn_poll_max_retries,
                    priority_fee_multiplier: self.funding_priority_fee_multiplier,
                    base_fee_multiplier: self.funding_base_fee_multiplier,
                },
                to_create: num_signers,
            });
        }

        if !self.private_keys.is_empty() {
            if num_signers > self.private_keys.len() {
                bail!(
                        "Found {} private keys, but need {} keys for the number of builders. You may need to disable one of the entry points.",
                        self.private_keys.len(), num_signers
                    );
            }

            return Ok(SigningScheme::PrivateKeys {
                private_keys: self.private_keys.clone(),
            });
        }

        if !self.aws_kms_key_ids.is_empty() {
            if self.aws_kms_key_ids.len() < num_signers {
                bail!(
                        "Not enough AWS KMS key IDs for the number of builders. Need {} keys, found {}. You may need to disable one of the entry points.",
                        num_signers, self.aws_kms_key_ids.len()
                    );
            }

            return Ok(SigningScheme::AwsKms {
                key_ids: self.aws_kms_key_ids.clone(),
                to_lock: num_signers,
                settings: KmsLockingSettings {
                    redis_uri: self.redis_uri.clone(),
                    ttl_millis: self.redis_lock_ttl_millis,
                },
            });
        }

        bail!("No signing scheme provided. Provide either signer.private_keys or signer.aws_kms_key_ids or signer.aws_kms_key_id_and_mnemonics");
    }
}
