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

use alloy_consensus::{SignableTransaction, TxEnvelope, TypedTransaction};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TransactionBuilder;
use alloy_primitives::{Address, PrimitiveSignature, U256};
use anyhow::{bail, Context};
use clap::Args;
use rundler_provider::{DAGasOracle, EvmProvider, Providers, TransactionRequest};
use rundler_signer::{utils, SignerLease};
use rundler_task::TaskSpawnerExt;
use rundler_types::chain::ChainSpec;

use crate::cli::signer::SignerArgs;

#[derive(Debug, Args)]
pub(super) struct DefundSignersArgs {
    /// The number of signers to defund
    #[arg(short, long)]
    count: Option<usize>,

    /// Signer arguments
    #[command(flatten)]
    signer_args: SignerArgs,

    /// Broadcast the defunding transactions
    #[arg(short, long)]
    broadcast: bool,

    /// The address to send the defunding transactions to
    #[arg(short, long, value_parser = parse_address)]
    to: Address,
}

fn parse_address(s: &str) -> Result<Address, String> {
    s.parse()
        .map_err(|e| format!("Invalid address: {s} error: {e:?}"))
}

pub(super) async fn defund_signers(
    mut args: DefundSignersArgs,
    chain_spec: ChainSpec,
    providers: impl Providers + 'static,
    task_spawner: impl TaskSpawnerExt + 'static,
) -> anyhow::Result<()> {
    let Some(fund_to) = args.signer_args.fund_to else {
        anyhow::bail!("Fund to balance not set");
    };
    if args.signer_args.fund_below.is_none() {
        // If fund below is not set, set it to the fund to balance
        // This is not used in this command, but is required by the signer manager
        args.signer_args.fund_below = Some(fund_to);
    }

    let signing_scheme = args.signer_args.signing_scheme(args.count)?;

    let signer_manager = rundler_signer::new_signer_manager(
        &signing_scheme,
        false,
        &chain_spec,
        providers.evm().clone(),
        providers.da_gas_oracle().clone(),
        &task_spawner,
    )
    .await?;

    let balances = providers
        .evm()
        .get_balances(signer_manager.addresses())
        .await?;

    let mut total = U256::ZERO;
    let mut signers_to_defund = vec![];
    for (address, balance) in &balances {
        if *balance > fund_to {
            let to_defund = balance - fund_to;
            let balance = alloy_primitives::utils::format_ether(*balance);
            let to_defund_str = alloy_primitives::utils::format_ether(to_defund);
            println!("Signer: {address:?} Balance: {balance} To defund: {to_defund_str}");
            total += to_defund;
            signers_to_defund.push((address, to_defund));
        }
    }

    println!(
        "Total to defund: {} to address {:?}",
        alloy_primitives::utils::format_ether(total),
        args.to
    );

    if !args.broadcast {
        return Ok(());
    }

    let mut tasks = vec![];
    for (address, amount) in signers_to_defund {
        let signer = signer_manager.lease_signer_by_address(address).unwrap();
        tasks.push(defund_signer(
            signer,
            chain_spec.clone(),
            args.to,
            amount,
            providers.evm().clone(),
            providers.da_gas_oracle().clone(),
            &args.signer_args,
        ));
    }

    let results = futures::future::join_all(tasks).await;
    for result in results {
        match result {
            Ok(_) => {}
            Err(e) => {
                println!("Error defunding signer: {e}");
            }
        }
    }

    println!("Defunding complete");

    let new_balances = providers
        .evm()
        .get_balances(signer_manager.addresses())
        .await?;
    for (address, balance) in &new_balances {
        let balance = alloy_primitives::utils::format_ether(*balance);
        println!("Signer: {address:?} Balance: {balance}");
    }

    Ok(())
}

async fn defund_signer(
    signer: SignerLease,
    chain_spec: ChainSpec,
    to: Address,
    amount: U256,
    provider: impl EvmProvider,
    da_gas_oracle: impl DAGasOracle,
    signer_args: &SignerArgs,
) -> anyhow::Result<()> {
    let (nonce, max_fee_per_gas, priority_fee) = utils::get_nonce_and_fees(
        &provider,
        signer.address(),
        signer_args.funding_txn_base_fee_multiplier,
        signer_args.funding_txn_priority_fee_multiplier,
    )
    .await?;

    let tx = TransactionRequest::default()
        .with_value(amount)
        .with_chain_id(chain_spec.id)
        .with_nonce(nonce)
        .with_from(signer.address())
        .with_to(to)
        .with_max_fee_per_gas(max_fee_per_gas)
        .with_max_priority_fee_per_gas(priority_fee);

    // handle networks that have da gas in gas limit i.e Arbitrum
    let mut gas_limit: u64 = 50_000;
    if chain_spec.include_da_gas_in_gas_limit {
        let Ok(TypedTransaction::Eip1559(tx)) = tx.clone().build_typed_tx() else {
            bail!("failed to build EIP-1559 typed txn")
        };
        let mut data = vec![];
        TxEnvelope::from(tx.into_signed(PrimitiveSignature::test_signature()))
            .encode_2718(&mut data);
        let extra_data_len = data.len() / 4; // overestimate

        let block = provider
            .get_block_number()
            .await
            .context("failed to query for block number")?;

        let da_gas: u64 = da_gas_oracle
            .estimate_da_gas(
                data.into(),
                chain_spec.multicall3_address,
                block.into(),
                max_fee_per_gas,
                extra_data_len,
            )
            .await
            .context("failed to query for da gas data")?
            .0
            .try_into()
            .context("da gas overflow u64")?;

        gas_limit += da_gas;
    }
    let tx = tx.gas_limit(gas_limit);

    let tx_bytes = signer.sign_tx_raw(tx).await?;

    let tx_hash = provider.send_raw_transaction(tx_bytes).await?;
    println!("Defunding transaction {tx_hash} sent");

    let tx_receipt = utils::wait_for_txn(
        &provider,
        tx_hash,
        signer_args.funding_txn_poll_max_retries,
        Duration::from_millis(signer_args.funding_txn_poll_interval_ms),
    )
    .await?;

    tracing::info!("Defunding transaction {tx_hash} mined. Receipt: {tx_receipt:?}");

    Ok(())
}
