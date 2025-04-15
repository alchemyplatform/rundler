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

use std::{net::SocketAddr, str::FromStr, sync::Arc};

use alloy_primitives::Address;
use anyhow::Context;
use clap::Args;
use rundler_builder::{
    self, BloxrouteSenderArgs, BuilderEvent, BuilderEventKind, BuilderSettings, BuilderTask,
    BuilderTaskArgs, FlashbotsSenderArgs, LocalBuilderBuilder, RawSenderArgs,
    TransactionSenderArgs, TransactionSenderKind,
};
use rundler_pbh::PbhSubmissionProxy;
use rundler_pool::RemotePoolClient;
use rundler_provider::Providers;
use rundler_sim::{MempoolConfigs, PriorityFeeMode};
use rundler_task::{
    server::{connect_with_retries_shutdown, format_socket_addr},
    TaskSpawnerExt,
};
use rundler_types::{
    chain::{ChainSpec, ContractRegistry},
    proxy::SubmissionProxy,
    EntryPointVersion,
};
use rundler_utils::emit::{self, WithEntryPoint, EVENT_CHANNEL_CAPACITY};
use serde::Deserialize;
use tokio::sync::broadcast;

use super::{
    proxy::{PassThroughProxy, SubmissionProxyType},
    signer::SignerArgs,
    CommonArgs,
};

const REQUEST_CHANNEL_CAPACITY: usize = 1024;

/// CLI options for the builder
#[derive(Args, Debug)]
#[command(next_help_heading = "BUILDER")]
pub struct BuilderArgs {
    /// Port to listen on for gRPC requests
    #[arg(
        long = "builder.port",
        name = "builder.port",
        env = "BUILDER_PORT",
        default_value = "50051"
    )]
    port: u16,

    /// Host to listen on for gRPC requests
    #[arg(
        long = "builder.host",
        name = "builder.host",
        env = "BUILDER_HOST",
        default_value = "127.0.0.1"
    )]
    host: String,

    #[command(flatten)]
    signer_args: SignerArgs,

    /// Maximum number of ops to include in one bundle.
    #[arg(
        long = "builder.max_bundle_size",
        name = "builder.max_bundle_size",
        env = "BUILDER_MAX_BUNDLE_SIZE",
        default_value = "128"
    )]
    max_bundle_size: u64,

    /// Choice of what sender type to to use for transaction submission.
    /// Defaults to the value of `raw`. Other options include `flashbots`,
    /// `conditional` and `bloxroute`
    #[arg(
        long = "builder.sender",
        name = "builder.sender",
        env = "BUILDER_SENDER",
        value_enum,
        default_value = "raw"
    )]
    pub sender_type: TransactionSenderKind,

    /// If present, the url of the ETH provider that will be used to send
    /// transactions. Defaults to the value of `node_http`.
    ///
    /// Only used when BUILDER_SENDER is "raw"
    #[arg(
        long = "builder.submit_url",
        name = "builder.submit_url",
        env = "BUILDER_SUBMIT_URL"
    )]
    pub submit_url: Option<String>,

    /// Use the conditional RPC endpoint for transaction submission.
    ///
    /// Only used when BUILDER_SENDER is "raw"
    #[arg(
        long = "builder.use_conditional_rpc",
        name = "builder.use_conditional_rpc",
        env = "BUILDER_USE_CONDITIONAL_RPC",
        default_value = "false"
    )]
    pub use_conditional_rpc: bool,

    /// A list of builders to pass into the Flashbots Relay RPC.
    ///
    /// Only used when BUILDER_SENDER is "flashbots"
    #[arg(
        long = "builder.flashbots_relay_builders",
        name = "builder.flashbots_relay_builders",
        env = "BUILDER_FLASHBOTS_RELAY_BUILDERS",
        value_delimiter = ',',
        default_value = "flashbots"
    )]
    flashbots_relay_builders: Vec<String>,

    /// A private key used to authenticate with the Flashbots relay.
    ///
    /// Only used when BUILDER_SENDER is "flashbots"
    #[arg(
        long = "builder.flashbots_relay_auth_key",
        name = "builder.flashbots_relay_auth_key",
        env = "BUILDER_FLASHBOTS_RELAY_AUTH_KEY",
        value_delimiter = ','
    )]
    flashbots_relay_auth_key: Option<String>,

    /// Auth header to use for Bloxroute polygon_private_tx sender
    ///
    /// Only used when BUILDER_SENDER is "bloxroute"
    #[arg(
        long = "builder.bloxroute_auth_header",
        name = "builder.bloxroute_auth_header",
        env = "BUILDER_BLOXROUTE_AUTH_HEADER"
    )]
    bloxroute_auth_header: Option<String>,

    /// After submitting a bundle transaction, the maximum number of blocks to
    /// wait for that transaction to mine before we try resending with higher
    /// gas fees.
    #[arg(
        long = "builder.max_blocks_to_wait_for_mine",
        name = "builder.max_blocks_to_wait_for_mine",
        env = "BUILDER_MAX_BLOCKS_TO_WAIT_FOR_MINE",
        default_value = "2"
    )]
    max_blocks_to_wait_for_mine: u64,

    /// Percentage amount to increase gas fees when retrying a transaction after
    /// it failed to mine.
    #[arg(
        long = "builder.replacement_fee_percent_increase",
        name = "builder.replacement_fee_percent_increase",
        env = "BUILDER_REPLACEMENT_FEE_PERCENT_INCREASE",
        default_value = "10"
    )]
    replacement_fee_percent_increase: u32,

    /// Maximum number of times to increase gas fees when retrying a cancellation transaction
    /// before giving up.
    #[arg(
        long = "builder.max_cancellation_fee_increases",
        name = "builder.max_cancellation_fee_increases",
        env = "BUILDER_MAX_CANCELLATION_FEE_INCREASES",
        default_value = "15"
    )]
    max_cancellation_fee_increases: u64,

    /// The maximum number of blocks to wait in a replacement underpriced state before issuing
    /// a cancellation transaction.
    #[arg(
        long = "builder.max_replacement_underpriced_blocks",
        name = "builder.max_replacement_underpriced_blocks",
        env = "BUILDER_MAX_REPLACEMENT_UNDERPRICED_BLOCKS",
        default_value = "20"
    )]
    max_replacement_underpriced_blocks: u64,
}

impl BuilderArgs {
    /// Convert the CLI arguments into the arguments for the builder combining
    /// common and builder specific arguments.
    pub async fn to_args(
        &self,
        chain_spec: ChainSpec,
        common: &CommonArgs,
        remote_address: Option<SocketAddr>,
        mempool_configs: Option<MempoolConfigs>,
        entry_point_builders: Option<EntryPointBuilderConfigs>,
    ) -> anyhow::Result<BuilderTaskArgs> {
        let priority_fee_mode = PriorityFeeMode::try_from(
            common.priority_fee_mode_kind.as_str(),
            common.priority_fee_mode_value,
        )?;

        let rpc_url = common.node_http.clone().context("must provide node_http")?;

        let mempool_configs = mempool_configs.unwrap_or_default();
        let mut all_builders = vec![];

        let mut num_builders = 0;

        if !common.disable_entry_point_v0_6 {
            let builders = entry_point_builders
                .as_ref()
                .and_then(|builder_configs| {
                    builder_configs
                        .get_for_entry_point(chain_spec.entry_point_address_v0_6)
                        .map(|ep| {
                            ep.builders
                                .iter()
                                .map(|builder| BuilderSettings {
                                    address: ep.address,
                                    version: EntryPointVersion::V0_6,
                                    mempool_configs: mempool_configs
                                        .get_for_entry_point(chain_spec.entry_point_address_v0_6),
                                    submission_proxy: builder.proxy,
                                    filter_id: builder.filter_id.clone(),
                                })
                                .collect::<Vec<_>>()
                        })
                })
                .unwrap_or_else(|| {
                    vec![BuilderSettings {
                        address: chain_spec.entry_point_address_v0_6,
                        version: EntryPointVersion::V0_6,
                        mempool_configs: mempool_configs
                            .get_for_entry_point(chain_spec.entry_point_address_v0_6),
                        submission_proxy: None,
                        filter_id: None,
                    }]
                });

            // change this name to num_signers, only use a single number, and only with mnemonics
            num_builders += common.num_builders_v0_6;
            all_builders.extend(builders);
        }
        if !common.disable_entry_point_v0_7 {
            let builders = entry_point_builders
                .as_ref()
                .and_then(|builder_configs| {
                    builder_configs
                        .get_for_entry_point(chain_spec.entry_point_address_v0_7)
                        .map(|ep| {
                            ep.builders
                                .iter()
                                .map(|builder| BuilderSettings {
                                    address: ep.address,
                                    version: EntryPointVersion::V0_7,
                                    mempool_configs: mempool_configs
                                        .get_for_entry_point(chain_spec.entry_point_address_v0_7),
                                    submission_proxy: builder.proxy,
                                    filter_id: builder.filter_id.clone(),
                                })
                                .collect::<Vec<_>>()
                        })
                })
                .unwrap_or_else(|| {
                    vec![BuilderSettings {
                        address: chain_spec.entry_point_address_v0_7,
                        version: EntryPointVersion::V0_7,
                        mempool_configs: mempool_configs
                            .get_for_entry_point(chain_spec.entry_point_address_v0_7),
                        filter_id: None,
                        submission_proxy: None,
                    }]
                });

            num_builders += common.num_builders_v0_7;
            all_builders.extend(builders);
        }

        let sender_args = self.sender_args(&chain_spec, &rpc_url)?;
        let signing_scheme = self.signer_args.signing_scheme(num_builders as usize)?;

        let da_gas_tracking_enabled =
            super::lint_da_gas_tracking(common.da_gas_tracking_enabled, &chain_spec);

        let provider_client_timeout_seconds = common.provider_client_timeout_seconds;

        Ok(BuilderTaskArgs {
            builders: all_builders,
            signing_scheme,
            auto_fund: true,
            unsafe_mode: common.unsafe_mode,
            rpc_url,
            max_bundle_size: self.max_bundle_size,
            target_bundle_gas: chain_spec
                .block_gas_limit_mult(common.target_bundle_block_gas_limit_ratio),
            max_bundle_gas: chain_spec
                .block_gas_limit_mult(common.max_bundle_block_gas_limit_ratio),
            bundle_base_fee_overhead_percent: common.bundle_base_fee_overhead_percent,
            bundle_priority_fee_overhead_percent: common.bundle_priority_fee_overhead_percent,
            priority_fee_mode,
            sender_args,
            sim_settings: common.try_into()?,
            max_blocks_to_wait_for_mine: self.max_blocks_to_wait_for_mine,
            replacement_fee_percent_increase: self.replacement_fee_percent_increase,
            max_cancellation_fee_increases: self.max_cancellation_fee_increases,
            max_replacement_underpriced_blocks: self.max_replacement_underpriced_blocks,
            remote_address,
            da_gas_tracking_enabled,
            provider_client_timeout_seconds,
            max_expected_storage_slots: common.max_expected_storage_slots.unwrap_or(usize::MAX),
            chain_spec,
        })
    }

    fn sender_args(
        &self,
        chain_spec: &ChainSpec,
        rpc_url: &str,
    ) -> anyhow::Result<TransactionSenderArgs> {
        match self.sender_type {
            TransactionSenderKind::Raw => Ok(TransactionSenderArgs::Raw(RawSenderArgs {
                submit_url: self.submit_url.clone().unwrap_or_else(|| rpc_url.into()),
                use_conditional_rpc: self.use_conditional_rpc,
            })),
            TransactionSenderKind::Flashbots => {
                if !chain_spec.flashbots_enabled {
                    return Err(anyhow::anyhow!("Flashbots sender is not enabled for chain"));
                }

                Ok(TransactionSenderArgs::Flashbots(FlashbotsSenderArgs {
                    builders: self.flashbots_relay_builders.clone(),
                    relay_url: chain_spec
                        .flashbots_relay_url
                        .clone()
                        .context("should have a relay URL (chain spec: flashbots_relay_url)")?,
                    auth_key: self.flashbots_relay_auth_key.clone().context(
                        "should have a flashbots relay auth key (cli: flashbots_relay_auth_key)",
                    )?,
                }))
            }
            TransactionSenderKind::Bloxroute => {
                if !chain_spec.bloxroute_enabled {
                    return Err(anyhow::anyhow!("Flashbots sender is not enabled for chain"));
                }

                Ok(TransactionSenderArgs::Bloxroute(BloxrouteSenderArgs {
                    header: self
                        .bloxroute_auth_header
                        .clone()
                        .context("should have a bloxroute auth header")?,
                }))
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EntryPointBuilderConfigs {
    // Builder configs per entry point
    entry_points: Vec<EntryPointBuilderConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EntryPointBuilderConfig {
    // Entry point address
    pub(crate) address: Address,
    // Builder configs
    pub(crate) builders: Vec<BuilderConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BuilderConfig {
    // Submitter proxy to use for builders
    pub(crate) proxy: Option<Address>,
    // Type of proxy to use for builders
    pub(crate) proxy_type: Option<String>,
    // Optional filter to apply to the builders
    pub(crate) filter_id: Option<String>,
}

impl EntryPointBuilderConfigs {
    pub(crate) fn get_for_entry_point(&self, address: Address) -> Option<&EntryPointBuilderConfig> {
        self.entry_points.iter().find(|ep| ep.address == address)
    }

    pub(crate) fn set_proxies(&self, chain_spec: &mut ChainSpec) {
        let mut registry = ContractRegistry::<Arc<dyn SubmissionProxy>>::default();

        for entry_point in &self.entry_points {
            for builder in &entry_point.builders {
                if let Some(proxy) = builder.proxy {
                    let proxy_type = if let Some(proxy_type) = &builder.proxy_type {
                        SubmissionProxyType::from_str(proxy_type)
                            .unwrap_or_else(|_| panic!("proxyType not supported: {}", proxy_type))
                    } else {
                        SubmissionProxyType::PassThrough
                    };

                    match proxy_type {
                        SubmissionProxyType::PassThrough => {
                            registry.register(proxy, Arc::new(PassThroughProxy::new(proxy)));
                        }
                        SubmissionProxyType::Pbh => {
                            registry.register(proxy, Arc::new(PbhSubmissionProxy::new(proxy)));
                        }
                    }
                }
            }
        }

        chain_spec.set_submission_proxies(Arc::new(registry));
    }
}

/// CLI options for the Builder server standalone
#[derive(Args, Debug)]
pub struct BuilderCliArgs {
    #[command(flatten)]
    builder: BuilderArgs,

    #[arg(
        long = "builder.pool_url",
        name = "builder.pool_url",
        env = "BUILDER_POOL_URL",
        default_value = "http://localhost:50051",
        global = true
    )]
    pool_url: String,
}

pub async fn spawn_tasks<T: TaskSpawnerExt + 'static>(
    task_spawner: T,
    chain_spec: ChainSpec,
    builder_args: BuilderCliArgs,
    common_args: CommonArgs,
    providers: impl Providers + 'static,
) -> anyhow::Result<()> {
    let BuilderCliArgs {
        builder: builder_args,
        pool_url,
    } = builder_args;

    let (event_sender, event_rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
    task_spawner.spawn_critical(
        "recv and log events",
        Box::pin(emit::receive_and_log_events_with_filter(
            event_rx,
            is_nonspammy_event,
        )),
    );

    let (mempool_config, entry_point_builders) = super::load_configs(&common_args).await?;

    let task_args = builder_args
        .to_args(
            chain_spec.clone(),
            &common_args,
            Some(format_socket_addr(&builder_args.host, builder_args.port).parse()?),
            mempool_config,
            entry_point_builders,
        )
        .await?;

    let pool = connect_with_retries_shutdown(
        "op pool from builder",
        &pool_url,
        |url| RemotePoolClient::connect(url, chain_spec.clone(), Box::new(task_spawner.clone())),
        tokio::signal::ctrl_c(),
    )
    .await?;

    let signer_manager = rundler_signer::new_signer_manager(
        &task_args.signing_scheme,
        task_args.auto_fund,
        &chain_spec,
        providers.evm().clone(),
        providers.da_gas_oracle().clone(),
        &task_spawner,
    )
    .await?;

    let builder_builder = LocalBuilderBuilder::new(
        REQUEST_CHANNEL_CAPACITY,
        signer_manager.clone(),
        Arc::new(pool.clone()),
    );

    BuilderTask::new(
        task_args,
        event_sender,
        builder_builder,
        pool,
        providers,
        signer_manager,
    )
    .spawn(task_spawner)
    .await?;

    Ok(())
}

pub fn is_nonspammy_event(event: &WithEntryPoint<BuilderEvent>) -> bool {
    if let BuilderEventKind::FormedBundle {
        tx_details,
        fee_increase_count,
        ..
    } = &event.event.kind
    {
        if tx_details.is_none() && *fee_increase_count == 0 {
            return false;
        }
    }
    true
}
