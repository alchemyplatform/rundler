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

use alloy_primitives::U256;
use anyhow::Context;
use futures::{future::BoxFuture, FutureExt};
use rundler_provider::{EntryPoint, Providers as ProvidersT, ProvidersWithEntryPointT};
use rundler_signer::SignerLease;
use rundler_sim::{
    gas::FeeEstimator as FeeEstimatorT,
    simulation::{self, UnsafeSimulator},
    SimulationSettings, Simulator,
};
use rundler_types::{
    chain::ChainSpec,
    pool::{NewHead, Pool as PoolT},
    EntryPointVersion, UserOperation, UserOperationVariant,
};
use rundler_utils::emit::WithEntryPoint;
use tokio::sync::broadcast;

use crate::{
    assigner::Assigner,
    bundle_proposer::{
        BundleProposerImpl, BundleProposerProviders, Settings as BundleProposerSettings,
    },
    bundle_sender::{
        BundleSenderTask, BundleSenderTaskArgs, BundleSenderTaskT, SendBundleResult,
        Settings as BundleSenderSettings,
    },
    emit::BuilderEvent,
    transaction_tracker::{
        Settings as TransactionTrackerSettings, TransactionTracker, TransactionTrackerImpl,
    },
    BuilderSettings, TransactionSenderArgs,
};

#[async_trait::async_trait]
pub(crate) trait BundleSenderTaskFactoryT: Send + Sync {
    async fn new_task(
        &self,
        block_number: u64,
        block_receiver: broadcast::Receiver<NewHead>,
        assigner: Assigner,
        signer: SignerLease,
        builder_settings: &BuilderSettings,
    ) -> anyhow::Result<BoxFuture<'static, SendBundleResult>>;
}

pub(crate) struct BundleSenderTaskFactory<Providers, FeeEstimator, Pool> {
    pub(crate) chain_spec: ChainSpec,
    pub(crate) sender_settings: BundleSenderSettings,
    pub(crate) proposer_settings: BundleProposerSettings,
    pub(crate) sim_settings: SimulationSettings,
    pub(crate) tracker_settings: TransactionTrackerSettings,
    pub(crate) unsafe_mode: bool,
    pub(crate) providers: Providers,
    pub(crate) fee_estimator: FeeEstimator,
    pub(crate) pool: Pool,
    pub(crate) sender_args: TransactionSenderArgs,
    pub(crate) event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,

    // TODO remove these
    pub(crate) provider_client_timeout_seconds: u64,
    pub(crate) rpc_url: String,
}

#[async_trait::async_trait]
impl<Providers, FeeEstimator, Pool> BundleSenderTaskFactoryT
    for BundleSenderTaskFactory<Providers, FeeEstimator, Pool>
where
    Providers: ProvidersT + 'static,
    FeeEstimator: FeeEstimatorT + Clone + 'static,
    Pool: PoolT + Clone + 'static,
{
    async fn new_task(
        &self,
        block_number: u64,
        block_receiver: broadcast::Receiver<NewHead>,
        assigner: Assigner,
        signer: SignerLease,
        builder_settings: &BuilderSettings,
    ) -> anyhow::Result<BoxFuture<'static, SendBundleResult>> {
        let transaction_tracker = self
            .create_transaction_tracker(signer, builder_settings)
            .await?;
        let mut task = match builder_settings.version {
            EntryPointVersion::V0_6 => self.create_builder_v0_6(
                builder_settings,
                assigner,
                transaction_tracker,
                block_number,
                block_receiver,
            )?,
            EntryPointVersion::V0_7 => self.create_builder_v0_7(
                builder_settings,
                assigner,
                transaction_tracker,
                block_number,
                block_receiver,
            )?,
            EntryPointVersion::Unspecified => {
                return Err(anyhow::anyhow!("Entry point version not specified"))
            }
        };

        Ok(async move { task.run().await }.boxed())
    }
}

impl<Providers, FeeEstimator, Pool> BundleSenderTaskFactory<Providers, FeeEstimator, Pool>
where
    Providers: ProvidersT + 'static,
    FeeEstimator: FeeEstimatorT + Clone + 'static,
    Pool: PoolT + Clone + 'static,
{
    async fn create_transaction_tracker(
        &self,
        signer: SignerLease,
        builder_settings: &BuilderSettings,
    ) -> anyhow::Result<Box<dyn TransactionTracker>> {
        // TODO remove this
        let sender = self
            .sender_args
            .clone()
            .into_sender(&self.rpc_url, self.provider_client_timeout_seconds)?;
        let signer_address = signer.address();
        let tracker = TransactionTrackerImpl::new(
            self.providers.evm().clone(),
            sender,
            signer,
            self.tracker_settings.clone(),
            builder_settings.tag_from_ep_version(
                &self.chain_spec,
                builder_settings.version,
                &signer_address,
            ),
        )
        .await?;
        Ok(Box::new(tracker))
    }

    fn create_builder_v0_6(
        &self,
        builder_settings: &BuilderSettings,
        assigner: Assigner,
        transaction_tracker: Box<dyn TransactionTracker>,
        block_number: u64,
        block_receiver: broadcast::Receiver<NewHead>,
    ) -> anyhow::Result<Box<dyn BundleSenderTaskT>> {
        let ep_providers = self
            .providers
            .ep_v0_6_providers()
            .clone()
            .context("entry point v0.6 not supplied")?;

        if self.unsafe_mode {
            Ok(self.create_bundle_builder(
                builder_settings,
                assigner,
                transaction_tracker,
                ep_providers.clone(),
                UnsafeSimulator::new(
                    ep_providers.entry_point().clone(),
                    self.sim_settings.clone(),
                ),
                block_number,
                block_receiver.resubscribe(),
            )?)
        } else {
            Ok(self.create_bundle_builder(
                builder_settings,
                assigner,
                transaction_tracker,
                ep_providers.clone(),
                simulation::new_v0_6_simulator(
                    ep_providers.evm().clone(),
                    ep_providers.entry_point().clone(),
                    self.sim_settings.clone(),
                    builder_settings.mempool_configs.clone(),
                ),
                block_number,
                block_receiver.resubscribe(),
            )?)
        }
    }

    fn create_builder_v0_7(
        &self,
        builder_settings: &BuilderSettings,
        assigner: Assigner,
        transaction_tracker: Box<dyn TransactionTracker>,
        block_number: u64,
        block_receiver: broadcast::Receiver<NewHead>,
    ) -> anyhow::Result<Box<dyn BundleSenderTaskT>> {
        let ep_providers = self
            .providers
            .ep_v0_7_providers()
            .clone()
            .context("entry point v0.7 not supplied")?;

        if self.unsafe_mode {
            Ok(self.create_bundle_builder(
                builder_settings,
                assigner,
                transaction_tracker,
                ep_providers.clone(),
                UnsafeSimulator::new(
                    ep_providers.entry_point().clone(),
                    self.sim_settings.clone(),
                ),
                block_number,
                block_receiver.resubscribe(),
            )?)
        } else {
            Ok(self.create_bundle_builder(
                builder_settings,
                assigner,
                transaction_tracker,
                ep_providers.clone(),
                simulation::new_v0_7_simulator(
                    ep_providers.evm().clone(),
                    ep_providers.entry_point().clone(),
                    self.sim_settings.clone(),
                    builder_settings.mempool_configs.clone(),
                ),
                block_number,
                block_receiver.resubscribe(),
            )?)
        }
    }

    fn create_bundle_builder<UO, EP, S>(
        &self,
        builder_settings: &BuilderSettings,
        assigner: Assigner,
        transaction_tracker: Box<dyn TransactionTracker>,
        ep_providers: EP,
        simulator: S,
        block_number: u64,
        block_receiver: broadcast::Receiver<NewHead>,
    ) -> anyhow::Result<Box<dyn BundleSenderTaskT>>
    where
        UO: UserOperation + From<UserOperationVariant>,
        UserOperationVariant: AsRef<UO>,
        EP: ProvidersWithEntryPointT + 'static,
        S: Simulator<UO = UO> + 'static,
    {
        let submission_proxy = if let Some(proxy) = &builder_settings.submission_proxy {
            let Some(proxy) = self.chain_spec.get_submission_proxy(proxy) else {
                return Err(anyhow::anyhow!(
                    "Proxy {} is not in the known submission proxies",
                    proxy
                ));
            };
            Some(proxy)
        } else {
            None
        };

        let proposer = BundleProposerImpl::new(
            builder_settings.tag(
                ep_providers.entry_point().address(),
                &transaction_tracker.address(),
            ),
            ep_providers.clone(),
            BundleProposerProviders::new(self.pool.clone(), simulator, self.fee_estimator.clone()),
            self.proposer_settings.clone(),
            self.event_sender.clone(),
            transaction_tracker.address(),
            submission_proxy.cloned(),
        );

        Ok(Box::new(BundleSenderTask::new(BundleSenderTaskArgs {
            builder_tag: builder_settings.tag(
                ep_providers.entry_point().address(),
                &transaction_tracker.address(),
            ),
            chain_spec: self.chain_spec.clone(),
            submission_proxy: submission_proxy.cloned(),
            proposer,
            ep_providers: ep_providers.clone(),
            transaction_tracker,
            pool: self.pool.clone(),
            settings: self.sender_settings.clone(),
            event_sender: self.event_sender.clone(),
            block_receiver,
            // TODO put this on transaction tracker
            balance: U256::MAX,
            block_number,
            assigner,
            filter_id: builder_settings.filter_id.clone(),
        })))
    }
}
