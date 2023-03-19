use crate::common::contracts::entry_point::EntryPoint;
use crate::common::contracts::simple_account::SimpleAccount;
use crate::common::contracts::simple_account_factory::SimpleAccountFactory;
use crate::common::contracts::verifying_paymaster::VerifyingPaymaster;
use crate::common::eth;
use crate::common::types::UserOperation;
use anyhow::Context;
use ethers::core::k256::ecdsa::SigningKey;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{Address, TransactionRequest, U256};
use ethers::utils;
use std::env;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

pub const CHAIN_ID: u32 = 1337;
pub const DEPLOYER_ACCOUNT_ID: u8 = 1;
pub const BUNDLER_ACCOUNT_ID: u8 = 2;
pub const WALLET_OWNER_ACCOUNT_ID: u8 = 3;
pub const PAYMASTER_SIGNER_ACCOUNT_ID: u8 = 4;

/// Creates a provider that connects to a locally running Geth node on its
/// default port of 8545.
pub fn new_local_provider() -> Arc<Provider<Http>> {
    // Set low interval because Geth node in --dev mode mines very quickly once
    // it sees a transaction. By default, the provider waits seven seconds to
    // poll for new blocks, which is excruciating while testing.
    let provider = Provider::<Http>::try_from("http://localhost:8545")
        .expect("localhost url should parse")
        .interval(Duration::from_millis(100));
    Arc::new(provider)
}

/// Given a provider connected to a Geth node in --dev mode, grants a large
/// amount of ETH to the specified address.
pub async fn grant_eth(provider: &Provider<Http>, to: Address) -> anyhow::Result<()> {
    // A Geth node in --dev mode has one account with massive amounts of ETH.
    let funder_address = *provider
        .get_accounts()
        .await
        .context("should be able to get accounts from node")?
        .first()
        .context("a Geth node in dev mode should have one account")?;
    // 1000 ETH ought to be enough for anyone.
    let value = utils::parse_ether(1000).unwrap();
    let tx = provider.send_transaction(
        TransactionRequest::pay(to, value).from(funder_address),
        None,
    );
    eth::await_mined_tx(tx, "grant ETH").await?;
    Ok(())
}

/// Creates a client that can send transactions and sign them with a secret
/// based on a fixed id. Can be used to generate accounts with deterministic
/// addresses for testing.
pub fn new_test_client(
    provider: Arc<Provider<Http>>,
    test_account_id: u8,
) -> Arc<SignerMiddleware<Arc<Provider<Http>>, LocalWallet>> {
    let wallet = new_test_wallet(test_account_id);
    Arc::new(SignerMiddleware::new(provider, wallet))
}

/// Creates a wallet whose secret is based on a fixed id. Differs from
/// `new_test_client` in that a wallet on its own can only sign messages but
/// not send transactions.
pub fn new_test_wallet(test_account_id: u8) -> LocalWallet {
    let bytes = test_signing_key_bytes(test_account_id);
    let key = SigningKey::from_bytes(&bytes).expect("should create signing key for test wallet");
    LocalWallet::from(key).with_chain_id(CHAIN_ID)
}

pub fn test_signing_key_bytes(test_account_id: u8) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[31] = test_account_id;
    bytes
}

/// An alternative to the default user op with gas values prefilled.
pub fn base_user_op() -> UserOperation {
    UserOperation {
        call_gas_limit: 1_000_000.into(),
        verification_gas_limit: 1_000_000.into(),
        pre_verification_gas: 1_000_000.into(),
        max_fee_per_gas: 100.into(),
        max_priority_fee_per_gas: 5.into(),
        ..UserOperation::default()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct DevAddresses {
    pub entry_point_address: Address,
    pub factory_address: Address,
    pub wallet_address: Address,
    pub paymaster_address: Address,
}

impl DevAddresses {
    pub fn write_to_env_file(&self) -> anyhow::Result<()> {
        let mut env_file = std::fs::File::create(".env")?;
        writeln!(
            env_file,
            "DEV_ENTRY_POINT_ADDRESS={:?}",
            self.entry_point_address
        )?;
        writeln!(
            env_file,
            "DEV_WALLET_FACTORY_ADDRESS={:?}",
            self.factory_address
        )?;
        writeln!(env_file, "DEV_WALLET_ADDRESS={:?}", self.wallet_address)?;
        writeln!(
            env_file,
            "DEV_PAYMASTER_ADDRESS={:?}",
            self.paymaster_address
        )?;
        Ok(())
    }

    pub fn new_from_env() -> anyhow::Result<Self> {
        Ok(Self {
            entry_point_address: address_from_env_var("DEV_ENTRY_POINT_ADDRESS")?,
            factory_address: address_from_env_var("DEV_WALLET_FACTORY_ADDRESS")?,
            wallet_address: address_from_env_var("DEV_WALLET_ADDRESS")?,
            paymaster_address: address_from_env_var("DEV_PAYMASTER_ADDRESS")?,
        })
    }
}

fn address_from_env_var(key: &str) -> anyhow::Result<Address> {
    env::var(key)
        .with_context(|| format!("should have environment variable {key}"))?
        .parse()
        .with_context(|| format!("should parse address from environment variable {key}"))
}

pub async fn deploy_dev_contracts() -> anyhow::Result<DevAddresses> {
    let provider = new_local_provider();
    let deployer_client = new_test_client(Arc::clone(&provider), DEPLOYER_ACCOUNT_ID);
    let bundler_client = new_test_client(Arc::clone(&provider), BUNDLER_ACCOUNT_ID);
    let wallet_owner_eoa = new_test_wallet(WALLET_OWNER_ACCOUNT_ID);
    let paymaster_signer_address = new_test_wallet(PAYMASTER_SIGNER_ACCOUNT_ID).address();
    grant_eth(&provider, deployer_client.address()).await?;
    grant_eth(&provider, bundler_client.address()).await?;
    let entry_point_deployer = EntryPoint::deploy(Arc::clone(&deployer_client), ());
    let entry_point = eth::await_contract_deployment(entry_point_deployer, "EntryPoint").await?;
    let entry_point = eth::connect_contract(&entry_point, Arc::clone(&bundler_client));
    let factory_deployer =
        SimpleAccountFactory::deploy(Arc::clone(&deployer_client), entry_point.address());
    let factory = eth::await_contract_deployment(factory_deployer, "SimpleAccountFactory").await?;
    let factory = eth::connect_contract(&factory, Arc::clone(&bundler_client));
    let paymaster_deployer = VerifyingPaymaster::deploy(
        Arc::clone(&deployer_client),
        (entry_point.address(), paymaster_signer_address),
    );
    let paymaster =
        eth::await_contract_deployment(paymaster_deployer, "VerifyingPaymaster").await?;
    let salt = U256::from(1);
    let wallet_address = factory
        .get_address(wallet_owner_eoa.address(), salt)
        .call()
        .await
        .context("factory's get_address should return the counterfactual address")?;
    grant_eth(&provider, wallet_address).await?;
    let init_code = eth::compact_call_data(
        factory.address(),
        factory.create_account(wallet_owner_eoa.address(), salt),
    );
    let mut op = UserOperation {
        sender: wallet_address,
        init_code,
        ..base_user_op()
    };
    let op_hash = entry_point
        .get_user_op_hash(op.clone())
        .call()
        .await
        .context("entry point should compute hash of user operation")?;
    let signature = wallet_owner_eoa
        .sign_message(op_hash)
        .await
        .context("user eoa should sign op hash")?;
    op.signature = signature.to_vec().into();
    let call = entry_point.handle_ops(vec![op], bundler_client.address());
    eth::await_mined_tx(call.send(), "deploy wallet using entry point").await?;
    Ok(DevAddresses {
        entry_point_address: entry_point.address(),
        factory_address: factory.address(),
        wallet_address,
        paymaster_address: paymaster.address(),
    })
}

pub type SimpleSignerMiddleware = SignerMiddleware<Arc<Provider<Http>>, LocalWallet>;

#[derive(Debug)]
pub struct DevClients {
    pub provider: Arc<Provider<Http>>,
    pub bundler_client: Arc<SimpleSignerMiddleware>,
    pub entry_point: EntryPoint<SimpleSignerMiddleware>,
    pub factory: SimpleAccountFactory<Provider<Http>>,
    pub wallet: SimpleAccount<Provider<Http>>,
    pub paymaster: VerifyingPaymaster<Provider<Http>>,
    pub wallet_owner_signer: LocalWallet,
    pub paymaster_signer: LocalWallet,
}

impl DevClients {
    pub fn new(addresses: DevAddresses) -> Self {
        let DevAddresses {
            entry_point_address,
            factory_address,
            wallet_address,
            paymaster_address,
        } = addresses;
        let provider = new_local_provider();
        let bundler_client = new_test_client(Arc::clone(&provider), BUNDLER_ACCOUNT_ID);
        let wallet_owner_client = new_test_client(Arc::clone(&provider), WALLET_OWNER_ACCOUNT_ID);
        let entry_point = EntryPoint::new(entry_point_address, Arc::clone(&bundler_client));
        let factory = SimpleAccountFactory::new(factory_address, Arc::clone(&provider));
        let wallet = SimpleAccount::new(wallet_address, Arc::clone(&provider));
        let paymaster = VerifyingPaymaster::new(paymaster_address, Arc::clone(&provider));
        let wallet_owner_signer = wallet_owner_client.signer().clone();
        let paymaster_signer = new_test_wallet(PAYMASTER_SIGNER_ACCOUNT_ID);
        Self {
            provider,
            bundler_client,
            entry_point,
            factory,
            wallet,
            paymaster,
            wallet_owner_signer,
            paymaster_signer,
        }
    }

    pub fn new_from_env() -> anyhow::Result<Self> {
        let addresses = DevAddresses::new_from_env()?;
        Ok(Self::new(addresses))
    }
}
