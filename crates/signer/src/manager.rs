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

use std::{
    collections::HashMap,
    fmt::{self, Debug},
    sync::Arc,
};

use alloy_consensus::{SignableTransaction, TypedTransaction};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{AnyNetwork, AnyTxEnvelope, EthereumWallet, NetworkWallet, TxSigner};
use alloy_primitives::{Address, Bytes, PrimitiveSignature, U256};
use metrics::Gauge;
use metrics_derive::Metrics;
use parking_lot::RwLock;
use rundler_provider::{EvmProvider, TransactionRequest};
use rundler_task::TaskSpawner;
use tokio::sync::Notify;

use crate::{
    funding::{self, FunderSettings},
    utils, Error, Result,
};

/// Trait for a signer manager
///
/// Leases available signers and manages their balances
#[async_trait::async_trait]
pub trait SignerManager: Send + Sync {
    /// Get the addresses of the signers
    fn addresses(&self) -> Vec<Address>;

    /// Get the number of available signers
    fn available(&self) -> usize;

    /// Wait for the number of available signers to reach the given number
    async fn wait_for_available(&self, num_required: usize) -> Result<()>;

    /// Lease a signer
    fn lease_signer(&self) -> Option<SignerLease>;

    /// Lease a specific signer
    fn lease_signer_by_address(&self, address: &Address) -> Option<SignerLease>;

    /// Return a leased signer
    fn return_lease(&self, lease: SignerLease);

    /// Update the balances of the signers
    fn update_balances(&self, balances: Vec<(Address, U256)>);

    /// Fund the signers
    ///
    /// Returns an error if the signer manager does not support funding
    fn fund_signers(&self) -> Result<()>;
}

/// A leased signer
#[derive(Clone)]
pub struct SignerLease {
    signer: Arc<dyn TxSigner<PrimitiveSignature> + Send + Sync + 'static>,
}

impl Debug for SignerLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Lease {{ address: {} }}", self.address())
    }
}

impl SignerLease {
    /// Create a new signer lease
    pub fn new(signer: Arc<dyn TxSigner<PrimitiveSignature> + Send + Sync + 'static>) -> Self {
        Self { signer }
    }

    /// Get the address of the signer
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Sign a transaction
    pub async fn sign_tx(&self, tx: TransactionRequest) -> Result<AnyTxEnvelope> {
        let Ok(tx) = tx.build_typed_tx() else {
            return Err(Error::InvalidTransaction(
                "could not build typed transaction".to_string(),
            ));
        };

        let tx_envelope = match tx {
            TypedTransaction::Legacy(mut t) => {
                let sig = self.signer.sign_transaction(&mut t).await?;
                t.into_signed(sig).into()
            }
            TypedTransaction::Eip2930(mut t) => {
                let sig = self.signer.sign_transaction(&mut t).await?;
                t.into_signed(sig).into()
            }
            TypedTransaction::Eip1559(mut t) => {
                let sig = self.signer.sign_transaction(&mut t).await?;
                t.into_signed(sig).into()
            }
            TypedTransaction::Eip4844(mut t) => {
                let sig = self.signer.sign_transaction(&mut t).await?;
                t.into_signed(sig).into()
            }
            TypedTransaction::Eip7702(mut t) => {
                let sig = self.signer.sign_transaction(&mut t).await?;
                t.into_signed(sig).into()
            }
        };

        Ok(AnyTxEnvelope::Ethereum(tx_envelope))
    }

    /// Sign a transaction and return the raw bytes
    pub async fn sign_tx_raw(&self, tx: TransactionRequest) -> Result<Bytes> {
        let tx_envelope = self.sign_tx(tx).await?;
        let mut raw_tx = vec![];
        tx_envelope.encode_2718(&mut raw_tx);
        Ok(raw_tx.into())
    }
}

pub(crate) struct FundingSignerManager {
    wallet: EthereumWallet,
    signer_statuses: Arc<RwLock<HashMap<Address, SignerStatus>>>,
    auto_fund: bool,
    funder_settings: Option<FunderSettings>,
    funding_notify: Arc<Notify>,
}

#[derive(Debug)]
pub(crate) enum SignerStatus {
    Available,
    NeedsFunding,
    LeasedNeedsFunding,
    Leased,
}

#[async_trait::async_trait]
impl SignerManager for FundingSignerManager {
    fn addresses(&self) -> Vec<Address> {
        NetworkWallet::<AnyNetwork>::signer_addresses(&self.wallet).collect()
    }

    fn available(&self) -> usize {
        self.signer_statuses
            .read()
            .values()
            .filter(|status| matches!(status, SignerStatus::Available))
            .count()
    }

    async fn wait_for_available(&self, num_required: usize) -> Result<()> {
        if self.available() >= num_required {
            return Ok(());
        }

        let Some(funder_settings) = &self.funder_settings else {
            Err(anyhow::anyhow!(
                "Required {num_required} but only have {} and funding is not enabled",
                self.available()
            ))?
        };

        while self.available() < num_required {
            tokio::time::sleep(funder_settings.poll_interval).await;
        }

        Ok(())
    }

    fn lease_signer(&self) -> Option<SignerLease> {
        let mut statuses = self.signer_statuses.write();

        let (address, status) = statuses
            .iter_mut()
            .find(|(_, status)| matches!(status, SignerStatus::Available))?;

        *status = SignerStatus::Leased;

        Some(SignerLease::new(Arc::new(
            self.wallet.signer_by_address(*address)?,
        )))
    }

    fn lease_signer_by_address(&self, address: &Address) -> Option<SignerLease> {
        let mut statuses = self.signer_statuses.write();
        let status = statuses.get_mut(address)?;
        if matches!(status, SignerStatus::Available) {
            *status = SignerStatus::Leased;
        }
        Some(SignerLease::new(Arc::new(
            self.wallet.signer_by_address(*address)?,
        )))
    }

    fn return_lease(&self, lease: SignerLease) {
        let mut statuses = self.signer_statuses.write();

        let status = statuses.get_mut(&lease.address()).unwrap();
        match *status {
            SignerStatus::Leased => *status = SignerStatus::Available,
            SignerStatus::LeasedNeedsFunding => *status = SignerStatus::NeedsFunding,
            _ => unreachable!(),
        }
    }

    fn update_balances(&self, balances: Vec<(Address, U256)>) {
        if Self::update_signer_statuses(
            &self.signer_statuses,
            balances,
            self.funder_settings.as_ref(),
            self.auto_fund,
        ) {
            self.funding_notify.notify_one();
        }
    }

    fn fund_signers(&self) -> Result<()> {
        if self.funder_settings.is_none() {
            Err(anyhow::anyhow!("Manager does not support funding"))?
        }

        self.funding_notify.notify_one();
        Ok(())
    }
}

impl FundingSignerManager {
    pub(crate) fn new<T: TaskSpawner, P: EvmProvider + 'static>(
        wallet: EthereumWallet,
        funder_settings: Option<FunderSettings>,
        auto_fund: bool,
        task_spawner: &T,
        provider: P,
    ) -> Self {
        let signer_statuses = Arc::new(RwLock::new(
            NetworkWallet::<AnyNetwork>::signer_addresses(&wallet)
                .map(|address| (address, SignerStatus::Available))
                .collect(),
        ));
        let funding_notify = Arc::new(Notify::new());

        if let Some(funder_settings) = &funder_settings {
            task_spawner.spawn_critical(
                "funding task",
                Box::pin(funding::funding_task(
                    funder_settings.clone(),
                    provider,
                    signer_statuses.clone(),
                    funding_notify.clone(),
                )),
            );
        }

        Self {
            wallet,
            signer_statuses,
            auto_fund,
            funder_settings,
            funding_notify,
        }
    }

    pub(crate) fn update_signer_statuses(
        signer_statuses: &Arc<RwLock<HashMap<Address, SignerStatus>>>,
        balances: Vec<(Address, U256)>,
        funder_settings: Option<&FunderSettings>,
        should_fund: bool,
    ) -> bool {
        let mut needs_funding = false;

        for (address, balance) in balances {
            if signer_statuses.read().get(&address).is_none() {
                continue;
            }

            if let Some(funder_settings) = funder_settings {
                let mut statuses = signer_statuses.write();
                let status = statuses.get_mut(&address).unwrap();
                if should_fund && balance < funder_settings.fund_below_balance {
                    match status {
                        SignerStatus::Available => *status = SignerStatus::NeedsFunding,
                        SignerStatus::Leased => *status = SignerStatus::LeasedNeedsFunding,
                        SignerStatus::LeasedNeedsFunding | SignerStatus::NeedsFunding => {}
                    }
                    needs_funding = true;
                } else {
                    match status {
                        SignerStatus::NeedsFunding => *status = SignerStatus::Available,
                        SignerStatus::LeasedNeedsFunding => *status = SignerStatus::Leased,
                        SignerStatus::Available | SignerStatus::Leased => {}
                    }
                }
            }

            let address_metrics =
                SignerMetrics::new_with_labels(&[("addr", format!("{address:?}"))]);
            utils::set_balance_gauge(&address_metrics.account_balance, address, balance);
        }

        needs_funding
    }
}

#[derive(Metrics)]
#[metrics(scope = "signer")]
pub(crate) struct SignerMetrics {
    #[metric(describe = "the balance of a signer address")]
    pub(crate) account_balance: Gauge,
}
