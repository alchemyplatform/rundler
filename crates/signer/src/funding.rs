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

use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy_consensus::{SignableTransaction, TxEnvelope, TypedTransaction};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{EthereumWallet, TransactionBuilder, TxSigner};
use alloy_primitives::{Address, Bytes, PrimitiveSignature, U256};
use anyhow::{bail, Context};
use metrics::{Counter, Gauge};
use metrics_derive::Metrics;
use parking_lot::RwLock;
use rundler_contracts::multicall3;
use rundler_provider::{DAGasOracle, EvmProvider, TransactionRequest};
use rundler_types::chain::ChainSpec;
use tokio::sync::Notify;

use crate::{
    manager::{FundingSignerManager, SignerStatus},
    utils,
};

const GAS_BASE: u64 = 50_000;
const GAS_PER_CALL: u64 = 40_000;
const MAX_TO_FUND_IN_BATCH: usize = 128;

#[derive(Clone)]
pub(crate) struct FunderSettings {
    pub fund_below_balance: U256,
    pub fund_to_balance: U256,
    pub chain_spec: ChainSpec,
    pub multicall3_address: Address,
    pub poll_interval: Duration,
    pub poll_max_retries: u64,
    pub priority_fee_multiplier: f64,
    pub base_fee_multiplier: f64,

    pub signer: Arc<dyn TxSigner<PrimitiveSignature> + Send + Sync + 'static>,
    pub da_gas_oracle: Arc<dyn DAGasOracle>,
}

pub(crate) async fn funding_task<P: EvmProvider>(
    settings: FunderSettings,
    provider: P,
    statuses: Arc<RwLock<HashMap<Address, SignerStatus>>>,
    notify: Arc<Notify>,
) -> anyhow::Result<()> {
    let funding_signer_address = settings.signer.address();
    let wallet = EthereumWallet::new(settings.signer.clone());
    let metrics = FunderMetrics::new_with_labels(&[(
        "addr",
        funding_signer_address.to_checksum(Some(settings.chain_spec.id)),
    )]);

    let _ = get_update_funder_balance(&provider, &metrics, funding_signer_address).await;

    // before calling, ensure that multicall3 is deployed
    let code = provider
        .get_code(settings.multicall3_address, None)
        .await
        .context("failed to get multicall3 code")?;
    if code.is_empty() {
        anyhow::bail!(
            "multicall3 is not deployed at {}",
            settings.multicall3_address
        );
    }

    loop {
        tokio::select! {
            // update the funding balance every 60 seconds
            _ = tokio::time::sleep(Duration::from_secs(60)) => {
                let _ = get_update_funder_balance(&provider, &metrics, funding_signer_address).await;
                continue;
            }
            // wait for notify
            _ = notify.notified() => {}
        }

        metrics.funding_attempts.increment(1);
        match funding_task_inner(
            &settings,
            &provider,
            &statuses,
            &wallet,
            funding_signer_address,
            &metrics,
        )
        .await
        {
            Ok(true) => {
                tracing::info!("Funding successful, but funding is still required");
                metrics.funding_reattempts.increment(1);
                notify.notify_one();
            }
            Ok(false) => {
                tracing::info!("Funding successful, no more funding required");
            }
            Err(err) => {
                metrics.funding_errors.increment(1);
                tracing::error!(
                    "Error during funding, retrying after {}ms: {err:?}",
                    settings.poll_interval.as_millis()
                );
                tokio::time::sleep(settings.poll_interval).await;
                notify.notify_one();
            }
        }
    }
}

async fn funding_task_inner<P: EvmProvider>(
    settings: &FunderSettings,
    provider: &P,
    statuses: &Arc<RwLock<HashMap<Address, SignerStatus>>>,
    wallet: &EthereumWallet,
    funding_signer_address: Address,
    metrics: &FunderMetrics,
) -> anyhow::Result<bool> {
    let addresses = statuses.read().keys().cloned().collect::<Vec<_>>();
    let balances = provider.get_balances(addresses.clone()).await?;
    let mut to_fund = balances
        .clone()
        .into_iter()
        .filter_map(|(address, balance)| {
            if balance < settings.fund_below_balance && balance < settings.fund_to_balance {
                Some((address, settings.fund_to_balance - balance))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if to_fund.is_empty() {
        tracing::info!("No funding needed");
        return Ok(FundingSignerManager::update_signer_statuses(
            statuses,
            balances,
            Some(settings),
            false,
        ));
    }

    // sort by amount, descending, break ties by address
    to_fund.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    // limit the amount of funding in a single transaction
    to_fund.truncate(MAX_TO_FUND_IN_BATCH);

    let mut total = to_fund.iter().map(|(_, amount)| amount).sum::<U256>();
    let mut total_to_fund = to_fund.len();
    let funding_balance =
        get_update_funder_balance(provider, metrics, funding_signer_address).await?;

    let (nonce, max_fee_per_gas, priority_fee) = utils::get_nonce_and_fees(
        provider,
        funding_signer_address,
        settings.base_fee_multiplier,
        settings.priority_fee_multiplier,
    )
    .await?;

    let mut gas_limit = GAS_BASE + GAS_PER_CALL * to_fund.len() as u64;
    let mut gas_fee = U256::from(gas_limit) * U256::from(max_fee_per_gas);

    if settings.chain_spec.da_pre_verification_gas {
        let da_gas = estimate_da_gas(
            &provider,
            &settings.da_gas_oracle,
            settings.multicall3_address,
            to_fund.clone(),
            max_fee_per_gas,
        )
        .await?;
        if settings.chain_spec.include_da_gas_in_gas_limit {
            gas_limit += da_gas;
        }
        gas_fee += U256::from(da_gas) * U256::from(max_fee_per_gas);
    }

    let mut total_with_gas = total + gas_fee;

    if total_with_gas > funding_balance {
        tracing::warn!("Not enough funding balance. Funding balance: {funding_balance}, total to fund: {total}. Partial funding will be attempted.");
        while total_with_gas > funding_balance && !to_fund.is_empty() {
            let (_, amount) = to_fund.pop().unwrap();
            total_with_gas -= amount + U256::from(GAS_PER_CALL) * U256::from(max_fee_per_gas);
            total -= amount;
            total_to_fund -= 1;
        }
        if to_fund.is_empty() {
            anyhow::bail!(
                "Not enough funding balance for any funding. Funding balance: {funding_balance}"
            );
        } else {
            tracing::warn!(
                "Partially funding {} of {} addresses",
                to_fund.len(),
                total_to_fund
            );
        }
        gas_limit = GAS_BASE + GAS_PER_CALL * to_fund.len() as u64;
    }

    let num_calls = to_fund.len() as u64;
    let call = create_multicall3_call(to_fund);

    let tx = TransactionRequest::default()
        .with_call(&call)
        .with_value(total)
        .with_chain_id(settings.chain_spec.id)
        .with_nonce(nonce)
        .with_from(funding_signer_address)
        .with_to(settings.multicall3_address)
        .with_max_fee_per_gas(max_fee_per_gas)
        .with_max_priority_fee_per_gas(priority_fee)
        .with_gas_limit(gas_limit)
        .build(&wallet)
        .await?;

    let mut raw_tx = vec![];
    tx.encode_2718(&mut raw_tx);
    let tx_bytes: Bytes = raw_tx.into();

    // wait for the funding to complete, if doesn't mine after max retries
    let tx_hash = provider.send_raw_transaction(tx_bytes).await?;

    let tx_receipt = utils::wait_for_txn(
        provider,
        tx_hash,
        settings.poll_max_retries,
        settings.poll_interval,
    )
    .await?;

    tracing::info!("Funding transaction {tx_hash} mined. Receipt: {tx_receipt:?}");

    metrics.funded_addresses.increment(num_calls);
    let _ = get_update_funder_balance(provider, metrics, funding_signer_address).await;
    let new_balances = provider.get_balances(addresses.clone()).await?;
    Ok(FundingSignerManager::update_signer_statuses(
        statuses,
        new_balances,
        Some(settings),
        true, // kick off another round of funding if balances are still below the threshold
    ))
}

async fn get_update_funder_balance<P: EvmProvider>(
    provider: &P,
    metrics: &FunderMetrics,
    funding_signer_address: Address,
) -> anyhow::Result<U256> {
    match provider.get_balance(funding_signer_address, None).await {
        Ok(balance) => {
            utils::set_balance_gauge(
                &metrics.funding_account_balance,
                funding_signer_address,
                balance,
            );
            Ok(balance)
        }
        Err(err) => {
            anyhow::bail!("Error getting balance for funding account: {err}");
        }
    }
}

fn create_multicall3_call(
    to_fund: impl IntoIterator<Item = (Address, U256)>,
) -> multicall3::Multicall3::aggregate3ValueCall {
    let calls = to_fund
        .into_iter()
        .map(|(address, amount)| multicall3::create_call_value_only(address, amount))
        .collect::<Vec<_>>();
    multicall3::Multicall3::aggregate3ValueCall { calls }
}

async fn estimate_da_gas<P: EvmProvider>(
    provider: &P,
    da_gas_oracle: &Arc<dyn DAGasOracle>,
    multicall3_address: Address,
    to_fund: Vec<(Address, U256)>,
    gas_price: u128,
) -> anyhow::Result<u64> {
    let Ok(TypedTransaction::Eip1559(tx)) = TransactionRequest::default()
        .with_call(&create_multicall3_call(to_fund))
        .with_value(U256::MAX)
        .with_chain_id(u64::MAX)
        .with_nonce(u64::MAX)
        .with_from(multicall3_address)
        .with_to(multicall3_address)
        .with_max_fee_per_gas(gas_price)
        .with_max_priority_fee_per_gas(gas_price)
        .with_gas_limit(u64::MAX)
        .build_typed_tx()
    else {
        bail!("failed to build EIP-1559 typed txn")
    };
    let mut data = vec![];
    TxEnvelope::from(tx.into_signed(PrimitiveSignature::test_signature())).encode_2718(&mut data);
    let extra_data_len = data.len() / 4; // overestimate

    let block = provider
        .get_block_number()
        .await
        .context("failed to query for block number")?;

    da_gas_oracle
        .estimate_da_gas(
            data.into(),
            multicall3_address,
            block.into(),
            gas_price,
            extra_data_len,
        )
        .await
        .context("failed to query for da gas data")?
        .0
        .try_into()
        .context("da gas overflow u64")
}

#[derive(Metrics)]
#[metrics(scope = "funder")]
struct FunderMetrics {
    #[metric(describe = "the number of funding attempts")]
    funding_attempts: Counter,
    #[metric(describe = "tne mumber of funding errors")]
    funding_errors: Counter,
    #[metric(describe = "the number of funding reattempts")]
    funding_reattempts: Counter,
    #[metric(describe = "the number of addresses that were funded")]
    funded_addresses: Counter,
    #[metric(describe = "the balance of the funding account")]
    funding_account_balance: Gauge,
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Transaction;
    use alloy_eips::eip2718::Decodable2718;
    use alloy_network::AnyTxEnvelope;
    use alloy_primitives::{address, bytes, B256};
    use alloy_sol_types::SolInterface;
    use mockall::Sequence;
    use rundler_contracts::multicall3::Multicall3::{Call3Value, Multicall3Calls};
    use rundler_provider::{
        AnyReceiptEnvelope, MockEvmProvider, ReceiptWithBloom, TransactionReceipt, ZeroDAGasOracle,
    };

    use super::*;

    const MOCK_MULTICALL3_CODE: Bytes = bytes!("FFFF");

    #[tokio::test]
    async fn test_funding_one() {
        let mut provider = MockEvmProvider::new();
        set_provider_nonce_and_fees(&mut provider);
        set_provider_balances(
            &mut provider,
            U256::from(1000000),
            vec![(Address::ZERO, U256::from(0))],
            vec![(Address::ZERO, U256::from(2000))],
        );
        set_provider_multicall3_code(&mut provider, MOCK_MULTICALL3_CODE);

        let signer = MockTxSigner::default();
        let wallet = EthereumWallet::new(signer.clone());
        let settings = funding_settings(U256::from(1000), U256::from(2000), signer);

        let statuses = HashMap::from([(Address::ZERO, SignerStatus::NeedsFunding)]);
        let statuses = Arc::new(RwLock::new(statuses));

        set_expected_transaction(
            &mut provider,
            U256::from(2000),
            vec![multicall3::create_call_value_only(
                Address::ZERO,
                U256::from(2000),
            )],
        );

        funding_task_inner(
            &settings,
            &provider,
            &statuses,
            &wallet,
            Address::ZERO,
            &FunderMetrics::default(),
        )
        .await
        .unwrap();

        assert_eq!(
            statuses.read().get(&Address::ZERO),
            Some(&SignerStatus::Available)
        );
    }

    #[tokio::test]
    async fn test_funding_multiple() {
        let address0 = address!("0000000000000000000000000000000000000000");
        let address1 = address!("0000000000000000000000000000000000000001");
        let address2 = address!("0000000000000000000000000000000000000002");

        let mut provider = MockEvmProvider::new();
        set_provider_nonce_and_fees(&mut provider);
        set_provider_balances(
            &mut provider,
            U256::from(1000000),
            vec![
                (address0, U256::from(0)),
                (address1, U256::from(0)),
                (address2, U256::from(2000)),
            ],
            vec![
                (address0, U256::from(2000)),
                (address1, U256::from(2000)),
                (address2, U256::from(2000)),
            ],
        );
        set_provider_multicall3_code(&mut provider, MOCK_MULTICALL3_CODE);

        let signer = MockTxSigner::default();
        let wallet = EthereumWallet::new(signer.clone());
        let settings = funding_settings(U256::from(1000), U256::from(2000), signer);

        let statuses = HashMap::from([
            (address0, SignerStatus::NeedsFunding),
            (address1, SignerStatus::NeedsFunding),
            (address2, SignerStatus::Available),
        ]);
        let statuses = Arc::new(RwLock::new(statuses));

        set_expected_transaction(
            &mut provider,
            U256::from(4000),
            vec![
                multicall3::create_call_value_only(address0, U256::from(2000)),
                multicall3::create_call_value_only(address1, U256::from(2000)),
            ],
        );

        funding_task_inner(
            &settings,
            &provider,
            &statuses,
            &wallet,
            Address::ZERO,
            &FunderMetrics::default(),
        )
        .await
        .unwrap();

        check_statuses(
            &statuses.read(),
            vec![
                (address0, SignerStatus::Available),
                (address1, SignerStatus::Available),
                (address2, SignerStatus::Available),
            ],
        );
    }

    #[tokio::test]
    async fn test_funding_partial() {
        let address0 = address!("0000000000000000000000000000000000000000");
        let address1 = address!("0000000000000000000000000000000000000001");
        let address2 = address!("0000000000000000000000000000000000000002");

        let mut provider = MockEvmProvider::new();
        set_provider_nonce_and_fees(&mut provider);
        set_provider_balances(
            &mut provider,
            U256::from(182000), // 90K gas per call * 2 gas price
            vec![
                (address0, U256::from(0)),
                (address1, U256::from(0)),
                (address2, U256::from(2000)),
            ],
            vec![
                (address0, U256::from(2000)),
                (address1, U256::from(0)), // not enough balance to fund
                (address2, U256::from(2000)),
            ],
        );
        set_provider_multicall3_code(&mut provider, MOCK_MULTICALL3_CODE);

        let signer = MockTxSigner::default();
        let wallet = EthereumWallet::new(signer.clone());
        let settings = funding_settings(U256::from(1000), U256::from(2000), signer);

        let statuses = HashMap::from([
            (address0, SignerStatus::NeedsFunding),
            (address1, SignerStatus::NeedsFunding),
            (address2, SignerStatus::Available),
        ]);
        let statuses = Arc::new(RwLock::new(statuses));

        set_expected_transaction(
            &mut provider,
            U256::from(2000),
            vec![multicall3::create_call_value_only(
                address0,
                U256::from(2000),
            )],
        );

        funding_task_inner(
            &settings,
            &provider,
            &statuses,
            &wallet,
            Address::ZERO,
            &FunderMetrics::default(),
        )
        .await
        .unwrap();

        check_statuses(
            &statuses.read(),
            vec![
                (address0, SignerStatus::Available),
                (address1, SignerStatus::NeedsFunding),
                (address2, SignerStatus::Available),
            ],
        );
    }

    #[tokio::test]
    async fn test_funding_no_multicall3() {
        let mut provider = MockEvmProvider::new();
        set_provider_nonce_and_fees(&mut provider);
        provider
            .expect_get_balance()
            .returning(move |_, _| Ok(U256::from(1000000)));
        set_provider_multicall3_code(&mut provider, Bytes::new()); // empty multicall3 code

        let signer = MockTxSigner::default();
        let settings = funding_settings(U256::from(1000), U256::from(2000), signer);

        let statuses = HashMap::from([(Address::ZERO, SignerStatus::NeedsFunding)]);
        let statuses = Arc::new(RwLock::new(statuses));
        let notify = Arc::new(Notify::new());

        // this should error because multicall3 is not deployed
        let result = funding_task(settings, provider, statuses, notify).await;
        assert!(result.is_err());
    }

    fn check_statuses(
        statuses: &HashMap<Address, SignerStatus>,
        expected_statuses: Vec<(Address, SignerStatus)>,
    ) {
        for (address, status) in expected_statuses {
            assert_eq!(statuses.get(&address), Some(&status));
        }
    }

    fn check_tx_calls(tx: Bytes, total_value: U256, expected_calls: Vec<Call3Value>) -> bool {
        let tx_bytes = tx.to_vec();
        let tx_envelope = AnyTxEnvelope::decode_2718(&mut tx_bytes.as_slice()).unwrap();
        if tx_envelope.value() != total_value {
            return false;
        }
        let tx_data = tx_envelope.input();
        let calls = Multicall3Calls::abi_decode(tx_data, true).unwrap();
        let Multicall3Calls::aggregate3Value(calls) = calls else {
            return false;
        };

        if expected_calls.len() != calls.calls.len() {
            return false;
        }

        for (expected_call, call) in expected_calls.iter().zip(calls.calls.iter()) {
            if expected_call.target != call.target
                || expected_call.value != call.value
                || expected_call.callData != call.callData
                || expected_call.allowFailure != call.allowFailure
            {
                return false;
            }
        }

        true
    }

    #[derive(Clone, Default)]
    struct MockTxSigner {}

    #[async_trait::async_trait]
    impl TxSigner<PrimitiveSignature> for MockTxSigner {
        fn address(&self) -> Address {
            Address::ZERO
        }
        async fn sign_transaction(
            &self,
            _tx: &mut dyn alloy_consensus::SignableTransaction<PrimitiveSignature>,
        ) -> alloy_signer::Result<PrimitiveSignature> {
            Ok(PrimitiveSignature::test_signature())
        }
    }

    fn funding_settings(
        fund_below: U256,
        fund_to: U256,
        singer: impl TxSigner<PrimitiveSignature> + Send + Sync + 'static,
    ) -> FunderSettings {
        FunderSettings {
            fund_below_balance: fund_below,
            fund_to_balance: fund_to,
            signer: Arc::new(singer),
            da_gas_oracle: Arc::new(ZeroDAGasOracle {}),
            chain_spec: ChainSpec::default(),
            multicall3_address: Address::ZERO,
            poll_interval: Duration::from_secs(1),
            poll_max_retries: 10,
            priority_fee_multiplier: 1.0,
            base_fee_multiplier: 1.0,
        }
    }

    fn set_expected_transaction(
        provider: &mut MockEvmProvider,
        total_value: U256,
        expected_calls: Vec<Call3Value>,
    ) {
        provider
            .expect_send_raw_transaction()
            .once()
            .withf(move |tx| check_tx_calls(tx.clone(), total_value, expected_calls.clone()))
            .returning(|_| Ok(B256::ZERO));
        provider
            .expect_get_transaction_receipt()
            .returning(|_| Ok(Some(transaction_receipt())));
    }

    fn set_provider_balances(
        provider: &mut MockEvmProvider,
        funder_balance: U256,
        balances_before: Vec<(Address, U256)>,
        balances_after: Vec<(Address, U256)>,
    ) {
        provider
            .expect_get_balance()
            .returning(move |_, _| Ok(funder_balance));
        let mut seq = Sequence::new();
        provider
            .expect_get_balances()
            .once()
            .in_sequence(&mut seq)
            .returning(move |_| Ok(balances_before.clone()));

        if !balances_after.is_empty() {
            provider
                .expect_get_balances()
                .once()
                .in_sequence(&mut seq)
                .returning(move |_| Ok(balances_after.clone()));
        }
    }

    fn set_provider_nonce_and_fees(provider: &mut MockEvmProvider) {
        provider.expect_get_transaction_count().returning(|_| Ok(1));
        provider.expect_get_max_priority_fee().returning(|| Ok(1));
        provider.expect_get_pending_base_fee().returning(|| Ok(1));
    }

    fn set_provider_multicall3_code(provider: &mut MockEvmProvider, code: Bytes) {
        provider
            .expect_get_code()
            .returning(move |_, _| Ok(code.clone()));
    }

    fn transaction_receipt() -> TransactionReceipt {
        TransactionReceipt {
            inner: AnyReceiptEnvelope {
                inner: ReceiptWithBloom::default(),
                r#type: 0,
            },
            transaction_hash: B256::ZERO,
            transaction_index: None,
            block_hash: None,
            block_number: None,
            gas_used: 0,
            effective_gas_price: 0,
            blob_gas_used: None,
            blob_gas_price: None,
            from: Address::ZERO,
            to: None,
            contract_address: None,
            authorization_list: None,
        }
    }
}
