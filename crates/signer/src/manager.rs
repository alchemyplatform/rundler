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
use alloy_network::{
    AnyNetwork, AnyTxEnvelope, EthereumWallet, NetworkWallet, TransactionBuilder, TxSigner,
};
use alloy_primitives::{Address, Bytes, Signature, U256};
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
    signer: Arc<dyn TxSigner<Signature> + Send + Sync + 'static>,
    chain_id: u64,
}

impl Debug for SignerLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Lease {{ address: {} }}", self.address())
    }
}

impl SignerLease {
    /// Create a new signer lease
    pub fn new(
        signer: Arc<dyn TxSigner<Signature> + Send + Sync + 'static>,
        chain_id: u64,
    ) -> Self {
        Self { signer, chain_id }
    }

    /// Get the address of the signer
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Sign a transaction
    pub async fn sign_tx(&self, mut tx: TransactionRequest) -> Result<AnyTxEnvelope> {
        tx.set_chain_id(self.chain_id);
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
    chain_id: u64,
    wallet: EthereumWallet,
    signer_statuses: Arc<RwLock<HashMap<Address, SignerStatus>>>,
    auto_fund: bool,
    funder_settings: Option<FunderSettings>,
    funding_notify: Arc<Notify>,
}

#[derive(Debug, strum::EnumString, PartialEq, Eq)]
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
        } else if num_required > self.addresses().len() {
            return Err(anyhow::anyhow!(
                "Required {num_required} signers but only have {}",
                self.addresses().len()
            ))?;
        }

        let Some(funder_settings) = &self.funder_settings else {
            Err(anyhow::anyhow!(
                "Required {num_required} signers but only have {} and funding is not enabled",
                self.available()
            ))?
        };

        while self.available() < num_required {
            tracing::info!(
                "Waiting for {} signers to be available. Statuses: {:?}",
                num_required,
                self.signer_statuses.read().iter().collect::<Vec<_>>()
            );
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

        Some(SignerLease::new(
            self.wallet.signer_by_address(*address)?.clone(),
            self.chain_id,
        ))
    }

    fn lease_signer_by_address(&self, address: &Address) -> Option<SignerLease> {
        let mut statuses = self.signer_statuses.write();
        let status = statuses.get_mut(address)?;
        if matches!(status, SignerStatus::Available) {
            *status = SignerStatus::Leased;
            Some(SignerLease::new(
                self.wallet.signer_by_address(*address)?.clone(),
                self.chain_id,
            ))
        } else {
            None
        }
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
        chain_id: u64,
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
            let funder_settings = funder_settings.clone();
            let signer_statuses = signer_statuses.clone();
            let funding_notify = funding_notify.clone();

            task_spawner.spawn_critical(
                "funding task",
                Box::pin(async move {
                    let ret = funding::funding_task(
                        funder_settings,
                        provider,
                        signer_statuses,
                        funding_notify,
                    )
                    .await;
                    if let Err(e) = ret {
                        tracing::error!("funding task failed: {e}");
                    }
                }),
            );
        }

        Self {
            chain_id,
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

#[cfg(test)]
mod tests {
    use alloy_primitives::{address, U256};
    use rundler_provider::{MockEvmProvider, ZeroDAGasOracle};
    use rundler_task::TokioTaskExecutor;
    use rundler_types::chain::ChainSpec;

    use super::*;

    fn create_test_manager(signers: Vec<Address>) -> FundingSignerManager {
        let mut wallet = EthereumWallet::default();
        for signer in signers {
            wallet.register_signer(MockTxSigner::new(signer));
        }
        let funder_settings = Some(FunderSettings {
            fund_below_balance: U256::from(100),
            poll_interval: std::time::Duration::from_millis(100),
            chain_spec: ChainSpec::default(),
            multicall3_address: address!("0000000000000000000000000000000000000000"),
            poll_max_retries: 10,
            priority_fee_multiplier: 1.0,
            base_fee_multiplier: 1.0,
            signer: Arc::new(MockTxSigner::new(address!(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            ))),
            da_gas_oracle: Arc::new(ZeroDAGasOracle {}),
            fund_to_balance: U256::from(1000),
        });
        let task_spawner = TokioTaskExecutor::default();
        let provider = MockEvmProvider::default();

        FundingSignerManager::new(1, wallet, funder_settings, true, &task_spawner, provider)
    }

    #[tokio::test]
    async fn test_leasing_signers() {
        let manager = create_test_manager(vec![
            address!("0000000000000000000000000000000000000000"),
            address!("0000000000000000000000000000000000000001"),
        ]);
        let addresses = manager.addresses();
        assert!(!addresses.is_empty());

        // Test general leasing
        let lease = manager
            .lease_signer()
            .expect("Should be able to lease a signer");
        assert!(addresses.contains(&lease.address()));
        assert_eq!(manager.available(), addresses.len() - 1);
        manager.return_lease(lease);
        assert_eq!(manager.available(), addresses.len());

        // Test leasing by address
        let specific_address = addresses[0];
        let specific_lease = manager
            .lease_signer_by_address(&specific_address)
            .expect("Should be able to lease specific signer");
        assert_eq!(specific_lease.address(), specific_address);
        assert_eq!(manager.available(), addresses.len() - 1);
        manager.return_lease(specific_lease);
        assert_eq!(manager.available(), addresses.len());
    }

    #[tokio::test]
    async fn test_updating_balances() {
        let manager = create_test_manager(vec![
            address!("0000000000000000000000000000000000000000"),
            address!("0000000000000000000000000000000000000001"),
            address!("0000000000000000000000000000000000000002"),
            address!("0000000000000000000000000000000000000003"),
        ]);
        let addresses = manager.addresses();
        assert!(!addresses.is_empty());

        // Test balance updates that trigger funding
        let low_balance = U256::from(50); // Below fund_below_balance
        let high_balance = U256::from(200); // Above fund_below_balance

        let mut balances: Vec<_> = addresses
            .iter()
            .map(|&addr| {
                if addr == addresses[0] {
                    (addr, low_balance)
                } else {
                    (addr, high_balance)
                }
            })
            .collect();

        manager.update_balances(balances.clone());

        // Verify status transitions
        {
            let statuses = manager.signer_statuses.read();
            assert_eq!(
                statuses.get(&addresses[0]),
                Some(&SignerStatus::NeedsFunding)
            );
            for addr in &addresses[1..] {
                assert_eq!(statuses.get(addr), Some(&SignerStatus::Available));
            }
        }

        balances[0].1 = high_balance;
        manager.update_balances(balances.clone());
        {
            let statuses = manager.signer_statuses.read();
            assert_eq!(statuses.get(&addresses[0]), Some(&SignerStatus::Available));
        }

        let lease = manager.lease_signer_by_address(&addresses[0]).unwrap();
        balances[0].1 = low_balance;
        manager.update_balances(balances);
        {
            let statuses = manager.signer_statuses.read();
            assert_eq!(
                statuses.get(&addresses[0]),
                Some(&SignerStatus::LeasedNeedsFunding)
            );
        }

        manager.return_lease(lease);
        {
            let statuses = manager.signer_statuses.read();
            assert_eq!(
                statuses.get(&addresses[0]),
                Some(&SignerStatus::NeedsFunding)
            );
        }
    }

    #[tokio::test]
    async fn test_leasing_with_funding_status() {
        let manager = create_test_manager(vec![
            address!("0000000000000000000000000000000000000000"),
            address!("0000000000000000000000000000000000000001"),
        ]);
        let addresses = manager.addresses();
        assert!(!addresses.is_empty());

        // Set up a signer that needs funding
        let balances = addresses
            .iter()
            .map(|&addr| {
                if addr == addresses[0] {
                    (addr, U256::from(50)) // Below threshold
                } else {
                    (addr, U256::from(200)) // Above threshold
                }
            })
            .collect();
        manager.update_balances(balances);

        // Try to lease the signer that needs funding
        assert!(manager.lease_signer_by_address(&addresses[0]).is_none());
    }

    #[derive(Clone)]
    struct MockTxSigner {
        address: Address,
    }

    impl MockTxSigner {
        fn new(address: Address) -> Self {
            Self { address }
        }
    }

    #[async_trait::async_trait]
    impl TxSigner<Signature> for MockTxSigner {
        fn address(&self) -> Address {
            self.address
        }
        async fn sign_transaction(
            &self,
            _tx: &mut dyn alloy_consensus::SignableTransaction<Signature>,
        ) -> alloy_signer::Result<Signature> {
            Ok(Signature::test_signature())
        }
    }
}
