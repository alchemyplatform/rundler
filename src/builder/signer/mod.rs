use std::sync::Arc;

use ethers::{
    abi::Address,
    providers::{JsonRpcClient, Middleware, Provider},
};

mod aws;
pub use aws::*;

pub async fn monitor_account_balance<C: JsonRpcClient>(addr: Address, provider: Arc<Provider<C>>) {
    loop {
        let balance = provider.get_balance(addr, None).await.unwrap();
        let eth_balance = balance.as_u64() as f64 / 1e18;
        tracing::info!("account {addr:?} balance: {}", eth_balance);
        metrics::gauge!("bundle_builder_account_balance", eth_balance, "addr" => addr.to_string());
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}
