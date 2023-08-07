use std::{cmp::min, sync::Arc};

use anyhow::{ensure, Context};
use ethers::{
    contract::ContractError,
    providers::{JsonRpcClient, Middleware, Provider},
    types::{Address, Block, BlockId, BlockNumber, Bytes, Filter, Log, H160, H256, U256},
};
#[cfg(test)]
use mockall::automock;
use tonic::async_trait;

use crate::common::{
    contracts::{
        i_aggregator::IAggregator, i_entry_point::IEntryPoint, node_interface::NodeInterface,
        ovm_gas_price_oracle::OVM_GasPriceOracle,
    },
    types::UserOperation,
};

const ARBITRUM_NITRO_NODE_INTERFACE_ADDRESS: Address = H160([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc8,
]);

const OPTIMISM_BEDROCK_GAS_ORACLE_ADDRESS: Address = H160([
    0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0F,
]);

#[cfg_attr(test, automock)]
#[async_trait]
pub trait ProviderLike: Send + Sync + 'static {
    async fn get_block_number(&self) -> anyhow::Result<u64>;

    async fn get_block<T: Into<BlockId> + Send + Sync + 'static>(
        &self,
        block_hash_or_number: T,
    ) -> anyhow::Result<Option<Block<H256>>>;

    async fn get_balance(&self, address: Address, block: Option<BlockId>) -> anyhow::Result<U256>;

    async fn get_latest_block_hash(&self) -> anyhow::Result<H256>;

    async fn get_base_fee(&self) -> anyhow::Result<U256>;

    async fn get_max_priority_fee(&self) -> anyhow::Result<U256>;

    async fn get_code(&self, address: Address, block_hash: Option<H256>) -> anyhow::Result<Bytes>;

    async fn get_transaction_count(&self, address: Address) -> anyhow::Result<U256>;

    async fn get_logs(&self, filter: &Filter) -> anyhow::Result<Vec<Log>>;

    async fn aggregate_signatures(
        self: Arc<Self>,
        aggregator_address: Address,
        ops: Vec<UserOperation>,
    ) -> anyhow::Result<Option<Bytes>>;

    async fn calc_arbitrum_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        op: UserOperation,
    ) -> anyhow::Result<U256>;

    async fn calc_optimism_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        op: UserOperation,
    ) -> anyhow::Result<U256>;
}

#[async_trait]
impl<C: JsonRpcClient + 'static> ProviderLike for Provider<C> {
    // We implement `ProviderLike` for `Provider` rather than for all
    // `Middleware` because forming a `PendingTransaction` specifically requires
    // a `Provider`.

    async fn get_block_number(&self) -> anyhow::Result<u64> {
        Ok(Middleware::get_block_number(self)
            .await
            .context("should get block number from provider")?
            .as_u64())
    }

    async fn get_block<T: Into<BlockId> + Send + Sync + 'static>(
        &self,
        block_hash_or_number: T,
    ) -> anyhow::Result<Option<Block<H256>>> {
        Middleware::get_block(self, block_hash_or_number)
            .await
            .context("should get block from provider")
    }

    async fn get_balance(&self, address: Address, block: Option<BlockId>) -> anyhow::Result<U256> {
        Middleware::get_balance(self, address, block)
            .await
            .context("should get balance from provider")
    }

    async fn get_latest_block_hash(&self) -> anyhow::Result<H256> {
        Middleware::get_block(self, BlockId::Number(BlockNumber::Latest))
            .await
            .context("should load block to get hash")?
            .context("block should exist to get latest hash")?
            .hash
            .context("hash should be present on block")
    }

    async fn get_base_fee(&self) -> anyhow::Result<U256> {
        Middleware::get_block(self, BlockNumber::Latest)
            .await
            .context("should load latest block to get base fee")?
            .context("latest block should exist")?
            .base_fee_per_gas
            .context("latest block should have a nonempty base fee")
    }

    async fn get_max_priority_fee(&self) -> anyhow::Result<U256> {
        self.request("eth_maxPriorityFeePerGas", ())
            .await
            .context("should get max priority fee from provider")
    }

    async fn get_logs(&self, filter: &Filter) -> anyhow::Result<Vec<Log>> {
        Middleware::get_logs(self, filter)
            .await
            .context("provider should get logs")
    }

    async fn aggregate_signatures(
        self: Arc<Self>,
        aggregator_address: Address,
        ops: Vec<UserOperation>,
    ) -> anyhow::Result<Option<Bytes>> {
        let aggregator = IAggregator::new(aggregator_address, self);
        // TODO: Cap the gas here.
        let result = aggregator.aggregate_signatures(ops).call().await;
        match result {
            Ok(bytes) => Ok(Some(bytes)),
            Err(ContractError::Revert(_)) => Ok(None),
            Err(error) => Err(error).context("aggregator contract should aggregate signatures")?,
        }
    }

    async fn get_code(&self, address: Address, block_hash: Option<H256>) -> anyhow::Result<Bytes> {
        Middleware::get_code(self, address, block_hash.map(|b| b.into()))
            .await
            .context("provider should get contract code")
    }

    async fn get_transaction_count(&self, address: Address) -> anyhow::Result<U256> {
        Middleware::get_transaction_count(self, address, None)
            .await
            .context("provider should get transaction count")
    }

    async fn calc_arbitrum_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        op: UserOperation,
    ) -> anyhow::Result<U256> {
        let entry_point = IEntryPoint::new(entry_point_address, Arc::clone(&self));
        let data = entry_point
            .handle_ops(vec![op], Address::random())
            .calldata()
            .context("should get calldata for entry point handle ops")?;

        let arb_node = NodeInterface::new(ARBITRUM_NITRO_NODE_INTERFACE_ADDRESS, self);
        let gas = arb_node
            .gas_estimate_l1_component(entry_point_address, false, data)
            .call()
            .await?;
        Ok(U256::from(gas.0))
    }

    async fn calc_optimism_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        op: UserOperation,
    ) -> anyhow::Result<U256> {
        ensure!(
            op.max_fee_per_gas != U256::zero(),
            "max fee per gas must be nonzero for gas estimation on optimism"
        );
        let max_fee = op.max_fee_per_gas;
        let max_prio_fee = op.max_priority_fee_per_gas;

        let entry_point = IEntryPoint::new(entry_point_address, Arc::clone(&self));
        let data = entry_point
            .handle_ops(vec![op], Address::random())
            .calldata()
            .context("should get calldata for entry point handle ops")?;

        let gas_oracle =
            OVM_GasPriceOracle::new(OPTIMISM_BEDROCK_GAS_ORACLE_ADDRESS, Arc::clone(&self));

        let (l1_gas, l2_base_fee) = tokio::try_join!(
            async {
                let l1_gas = gas_oracle.get_l1_fee(data).call().await?;
                Ok(l1_gas)
            },
            self.get_base_fee()
        )?;

        let l2_price = min(max_fee, l2_base_fee + max_prio_fee);
        Ok(l1_gas / l2_price)
    }
}
