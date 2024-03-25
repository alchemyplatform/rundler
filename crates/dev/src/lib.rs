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

#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
//! Development utilities for the Rundler project.

use std::{
    collections::HashMap,
    env, error,
    fs::File,
    future::Future,
    io::{self, BufRead, Write},
    ops::Deref,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use ethers::{
    abi::AbiEncode,
    contract::{builders::ContractCall, Contract, ContractDeployer, ContractError},
    core::k256::ecdsa::SigningKey,
    middleware::SignerMiddleware,
    providers::{Http, JsonRpcClient, Middleware, PendingTransaction, Provider},
    signers::{LocalWallet, Signer},
    types::{Address, Bytes, NameOrAddress, TransactionReceipt, TransactionRequest, H256, U256},
    utils::{self, hex, keccak256},
};
use rundler_types::{
    contracts::v0_6::{
        i_entry_point::IEntryPoint, simple_account::SimpleAccount,
        simple_account_factory::SimpleAccountFactory, verifying_paymaster::VerifyingPaymaster,
    },
    v0_6, UserOperation,
};

/// Chain ID used by Geth in --dev mode.
pub const DEV_CHAIN_ID: u64 = 1337;
/// Account ID used by the deployer account.
pub const DEPLOYER_ACCOUNT_ID: u8 = 1;
/// Account ID used by the bundler account.
pub const BUNDLER_ACCOUNT_ID: u8 = 2;
/// Account ID used by the wallet owner account.
pub const WALLET_OWNER_ACCOUNT_ID: u8 = 3;
/// Account ID used by the paymaster signer account.
pub const PAYMASTER_SIGNER_ACCOUNT_ID: u8 = 4;

/// Waits for a pending transaction to be mined, providing appropriate error
/// messages for each point of failure.
pub async fn await_mined_tx<'a, Fut, C, Err>(
    tx: Fut,
    action: &str,
) -> anyhow::Result<TransactionReceipt>
where
    Fut: Future<Output = Result<PendingTransaction<'a, C>, Err>>,
    C: JsonRpcClient + 'a,
    Err: error::Error + Send + Sync + 'static,
{
    tx.await
        .with_context(|| format!("should send transaction to {action}"))?
        .await
        .with_context(|| format!("should wait for transaction to {action}"))?
        .with_context(|| format!("transaction to {action} should not be dropped"))
}

/// Waits for a contract deployment, providing appropriate error messages.
pub async fn await_contract_deployment<M, C>(
    deployer: Result<ContractDeployer<M, C>, ContractError<M>>,
    contract_name: &str,
) -> anyhow::Result<C>
where
    M: Middleware + 'static,
    C: From<Contract<M>>,
{
    deployer
        .with_context(|| format!("should create deployer for {contract_name}"))?
        .send()
        .await
        .with_context(|| format!("should deploy {contract_name}"))
}

/// Changes out a contract object's signer and returns a new contract of the
/// same type. Needed because although the general-purpose `Contract` has a
/// `.connect()` method to do this, specialized contract objects do not.
pub fn connect_contract<M, C>(contract: &C, provider: Arc<M>) -> C
where
    M: Clone + Middleware,
    C: Deref<Target = Contract<M>> + From<Contract<M>>,
{
    contract.connect(provider).into()
}

/// Packs an address followed by call data into a single `Bytes`. This is used
/// in ERC-4337 for calling wallets, factories, and paymasters.
pub fn compact_call_data<M, D>(address: Address, call: ContractCall<M, D>) -> Bytes {
    let mut bytes = address.as_bytes().to_vec();
    if let Some(call_data) = call.tx.data() {
        bytes.extend(call_data);
    }
    bytes.into()
}

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
    let funder_address = get_funder_address(provider).await?;
    let value = thousand_eth();
    let tx = provider.send_transaction(
        TransactionRequest::pay(to, value).from(funder_address),
        None,
    );
    await_mined_tx(tx, "grant ETH").await?;
    Ok(())
}

/// A Geth node in --dev mode starts with one account with massive amounts of
/// ETH. This returns that address.
pub async fn get_funder_address(provider: &Provider<Http>) -> anyhow::Result<Address> {
    Ok(*provider
        .get_accounts()
        .await
        .context("should be able to get accounts from node")?
        .first()
        .context("a Geth node in dev mode should have one account")?)
}

/// 1000 ETH ought to be enough for anyone.
fn thousand_eth() -> U256 {
    utils::parse_ether(1000).unwrap()
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
    let key =
        SigningKey::from_bytes(&bytes.into()).expect("should create signing key for test wallet");
    LocalWallet::from(key).with_chain_id(DEV_CHAIN_ID)
}

/// Creates a signing key whose secret is based on a fixed id
pub fn test_signing_key_bytes(test_account_id: u8) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[31] = test_account_id;
    bytes
}

/// An alternative to the default user op with gas values prefilled.
pub fn base_user_op() -> v0_6::UserOperation {
    v0_6::UserOperation {
        call_gas_limit: 1_000_000.into(),
        verification_gas_limit: 1_000_000.into(),
        pre_verification_gas: 1_000_000.into(),
        max_fee_per_gas: 100.into(),
        max_priority_fee_per_gas: 5.into(),
        ..v0_6::UserOperation::default()
    }
}

/// A collection of addresses for the development contracts.
#[derive(Copy, Clone, Debug)]
pub struct DevAddresses {
    /// The address of the entry point contract.
    pub entry_point_address: Address,
    /// The address of the dev account factory contract.
    pub factory_address: Address,
    /// The address of the dev wallet contract.
    pub wallet_address: Address,
    /// The address of the dev paymaster contract.
    pub paymaster_address: Address,
}

impl DevAddresses {
    /// Write the addresses to a `.env` file.
    pub fn write_to_env_file(&self) -> anyhow::Result<()> {
        let file = File::open(".env")?;
        let mut vars = io::BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
            .collect::<HashMap<String, String>>();

        vars.insert(
            "DEV_ENTRY_POINT_ADDRESS".to_string(),
            format!("{:?}", self.entry_point_address),
        );
        vars.insert(
            "DEV_WALLET_FACTORY_ADDRESS".to_string(),
            format!("{:?}", self.factory_address),
        );
        vars.insert(
            "DEV_WALLET_ADDRESS".to_string(),
            format!("{:?}", self.wallet_address),
        );
        vars.insert(
            "DEV_PAYMASTER_ADDRESS".to_string(),
            format!("{:?}", self.paymaster_address),
        );

        let mut vars = vars.into_iter().collect::<Vec<(_, _)>>();
        vars.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));

        let mut env_file = File::create(".env")?;
        for (key, value) in vars.iter() {
            writeln!(env_file, "{}={}", key, value)?;
        }

        Ok(())
    }

    /// Creates a new collection of addresses for the development contracts from env
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

/// Deploy all of the development contracts to a local Geth node in --dev mode.
pub async fn deploy_dev_contracts(entry_point_bytecode: &str) -> anyhow::Result<DevAddresses> {
    let provider = new_local_provider();
    let deployer_client = new_test_client(Arc::clone(&provider), DEPLOYER_ACCOUNT_ID);
    let bundler_client = new_test_client(Arc::clone(&provider), BUNDLER_ACCOUNT_ID);
    let wallet_owner_eoa = new_test_wallet(WALLET_OWNER_ACCOUNT_ID);
    let paymaster_signer_address = new_test_wallet(PAYMASTER_SIGNER_ACCOUNT_ID).address();
    grant_eth(&provider, deployer_client.address()).await?;
    grant_eth(&provider, bundler_client.address()).await?;

    let deterministic_deploy = DeterministicDeployProxy::new(Arc::clone(&deployer_client)).await?;

    // entry point
    let entry_point_address = deterministic_deploy
        .deploy_bytecode(entry_point_bytecode, 0)
        .await?;
    let entry_point = IEntryPoint::new(entry_point_address, Arc::clone(&deployer_client));

    // TODO use deterministic deployment
    // account factory
    let factory_deployer =
        SimpleAccountFactory::deploy(Arc::clone(&deployer_client), entry_point.address());
    let factory = await_contract_deployment(factory_deployer, "SimpleAccountFactory").await?;
    let factory = connect_contract(&factory, Arc::clone(&bundler_client));

    // paymaster
    let paymaster_deployer = VerifyingPaymaster::deploy(
        Arc::clone(&deployer_client),
        (entry_point.address(), paymaster_signer_address),
    );
    let paymaster = await_contract_deployment(paymaster_deployer, "VerifyingPaymaster").await?;

    let funder_address = get_funder_address(&provider).await?;
    let call = paymaster
        .deposit()
        .from(funder_address)
        .value(thousand_eth());
    await_mined_tx(call.send(), "deposit funds for paymaster").await?;
    let salt = U256::from(1);
    let wallet_address = factory
        .get_address(wallet_owner_eoa.address(), salt)
        .call()
        .await
        .context("factory's get_address should return the counterfactual address")?;
    grant_eth(&provider, wallet_address).await?;
    let init_code = compact_call_data(
        factory.address(),
        factory.create_account(wallet_owner_eoa.address(), salt),
    );

    let mut op = v0_6::UserOperation {
        sender: wallet_address,
        init_code,
        ..base_user_op()
    };
    let op_hash = op.hash(entry_point.address(), DEV_CHAIN_ID);
    let signature = wallet_owner_eoa
        .sign_message(op_hash)
        .await
        .context("user eoa should sign op hash")?;
    op.signature = signature.to_vec().into();
    let call = entry_point.handle_ops(vec![op], bundler_client.address());
    await_mined_tx(call.send(), "deploy wallet using entry point").await?;

    Ok(DevAddresses {
        entry_point_address: entry_point.address(),
        factory_address: factory.address(),
        wallet_address,
        paymaster_address: paymaster.address(),
    })
}

/// Alias for the signer middleware type used
pub type SimpleSignerMiddleware = SignerMiddleware<Arc<Provider<Http>>, LocalWallet>;

/// A collection of clients for interacting with the development contracts.
#[derive(Debug)]
pub struct DevClients {
    /// The provider used by all clients.
    pub provider: Arc<Provider<Http>>,
    /// The client used by the bundler.
    pub bundler_client: Arc<SimpleSignerMiddleware>,
    /// The entry point contract.
    pub entry_point: IEntryPoint<SimpleSignerMiddleware>,
    /// The account factory contract.
    pub factory: SimpleAccountFactory<Provider<Http>>,
    /// The wallet contract.
    pub wallet: SimpleAccount<Provider<Http>>,
    /// The paymaster contract.
    pub paymaster: VerifyingPaymaster<Provider<Http>>,
    /// The wallet owner signer.
    pub wallet_owner_signer: LocalWallet,
    /// The paymaster signer.
    pub paymaster_signer: LocalWallet,
}

impl DevClients {
    /// Creates a new collection of clients for interacting with the development contracts.
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
        let entry_point = IEntryPoint::new(entry_point_address, Arc::clone(&bundler_client));
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

    /// New from environment variables.
    pub fn new_from_env() -> anyhow::Result<Self> {
        let addresses = DevAddresses::new_from_env()?;
        Ok(Self::new(addresses))
    }

    /// Adds a signature to a user operation.
    pub async fn add_signature(
        &self,
        op: &mut v0_6::UserOperation,
        use_paymaster: bool,
    ) -> anyhow::Result<()> {
        if use_paymaster {
            // For the paymaster op hash to work correctly, our paymasterAndData
            // field must be the correct length, which is space for an address,
            // ABI-encoding of two ints, and a 65-byte signature.
            op.paymaster_and_data = [0_u8; 20 + 64 + 65].into();
            let valid_after = 0;
            let valid_until = 0;
            // Yes, the paymaster really takes valid_until before valid_after.
            let paymaster_op_hash = self
                .paymaster
                .get_hash(op.clone(), valid_until, valid_after)
                .await
                .context("should call paymaster to get op hash")?;
            let paymaster_signature = self
                .paymaster_signer
                .sign_message(paymaster_op_hash)
                .await
                .context("should sign paymaster op hash")?;
            let mut paymaster_and_data = self.paymaster.address().as_bytes().to_vec();
            paymaster_and_data.extend(AbiEncode::encode((valid_until, valid_after)));
            paymaster_and_data.extend(paymaster_signature.to_vec());
            op.paymaster_and_data = paymaster_and_data.into()
        }
        let op_hash = op.hash(self.entry_point.address(), DEV_CHAIN_ID);
        let signature = self
            .wallet_owner_signer
            .sign_message(op_hash)
            .await
            .context("wallet owner should sign op hash")?;
        op.signature = signature.to_vec().into();
        Ok(())
    }

    /// Creates a new user operation on the wallet
    pub async fn new_wallet_op<M, D>(
        &self,
        call: ContractCall<M, D>,
        value: U256,
    ) -> anyhow::Result<v0_6::UserOperation> {
        self.new_wallet_op_internal(call, value, false).await
    }

    /// Creates a new user operation on the wallet with a paymaster
    pub async fn new_wallet_op_with_paymaster<M, D>(
        &self,
        call: ContractCall<M, D>,
        value: U256,
    ) -> anyhow::Result<v0_6::UserOperation> {
        self.new_wallet_op_internal(call, value, true).await
    }

    async fn new_wallet_op_internal<M, D>(
        &self,
        call: ContractCall<M, D>,
        value: U256,
        use_paymaster: bool,
    ) -> anyhow::Result<v0_6::UserOperation> {
        let tx = &call.tx;
        let inner_call_data = Bytes::clone(
            tx.data()
                .context("call executed by wallet should have call data")?,
        );
        let &to = tx
            .to_addr()
            .context("call executed by wallet should have to address")?;
        let nonce = self
            .wallet
            .get_nonce()
            .await
            .context("should read nonce from wallet")?;
        let call_data = Bytes::clone(
            self.wallet
                .execute(to, value, inner_call_data)
                .tx
                .data()
                .context("wallet execute should have call data")?,
        );
        let mut op = v0_6::UserOperation {
            sender: self.wallet.address(),
            call_data,
            nonce,
            ..base_user_op()
        };
        self.add_signature(&mut op, use_paymaster).await?;
        Ok(op)
    }
}

// https://github.com/Arachnid/deterministic-deployment-proxy
struct DeterministicDeployProxy<M, S> {
    client: Arc<SignerMiddleware<M, S>>,
}

impl<M: Middleware + 'static, S: Signer + 'static> DeterministicDeployProxy<M, S> {
    const PROXY_ADDRESS: &'static str = "0x4e59b44847b379578588920ca78fbf26c0b4956c";
    const DEPLOYMENT_TRANSACTION: &'static str = "0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222";
    const DEPLOYMENT_SIGNER: &'static str = "0x3fab184622dc19b6109349b94811493bf2a45362";
    const DEPLOYMENT_GAS_PRICE: u64 = 100_000_000_000;
    const DEPLOYMENT_GAS_LIMIT: u64 = 100_000;

    /// Creates a new deterministic deploy proxy.
    async fn new(client: Arc<SignerMiddleware<M, S>>) -> anyhow::Result<Self> {
        let ret = Self { client };
        ret.deploy_deployer().await?;
        Ok(ret)
    }

    /// Deploys a contract with a deterministic address.
    async fn deploy_bytecode(&self, bytecode: &str, salt: u64) -> anyhow::Result<Address> {
        let addr = self.deploy_bytecode_address(bytecode, salt)?;
        if self.is_deployed(addr).await? {
            return Ok(addr);
        }

        let data = hex::decode(format!("{}{}", &Self::format_salt(salt), &bytecode[2..]))?;
        let tx = TransactionRequest::new().to(Self::PROXY_ADDRESS).data(data);

        let _ = self
            .client
            .send_transaction(tx, None)
            .await?
            .await?
            .context("should deploy bytecode")?;

        Ok(addr)
    }

    /// Computes the address of a contract with a deterministic address.
    fn deploy_bytecode_address(&self, bytecode: &str, salt: u64) -> anyhow::Result<Address> {
        let code_hash = hex::encode(keccak256(hex::decode(&bytecode[2..])?));
        let x = keccak256(hex::decode(format!(
            "ff{}{}{}",
            &Self::PROXY_ADDRESS[2..],
            &Self::format_salt(salt),
            code_hash
        ))?);
        Ok(Address::from_slice(&x[12..]))
    }

    async fn deploy_deployer(&self) -> anyhow::Result<()> {
        if self.is_deployed(Self::PROXY_ADDRESS).await? {
            return Ok(());
        }

        // fund the proxy
        let funds = U256::from(Self::DEPLOYMENT_GAS_PRICE * Self::DEPLOYMENT_GAS_LIMIT);
        let deployment_signer = Self::DEPLOYMENT_SIGNER.parse::<Address>()?;
        let tx = TransactionRequest::pay(deployment_signer, funds).from(self.client.address());
        let _ = self
            .client
            .send_transaction(tx, None)
            .await?
            .await?
            .context("should send funding transaction")?;

        // deploy the deployer
        let tx = Bytes::from(
            hex::decode(&Self::DEPLOYMENT_TRANSACTION[2..])
                .context("should decode deployment transaction")?,
        );
        let _ = self
            .client
            .send_raw_transaction(tx)
            .await?
            .await?
            .context("should send deployment transaction")?;

        if self.is_deployed(Self::PROXY_ADDRESS).await? {
            Ok(())
        } else {
            anyhow::bail!("deployer is not deployed")
        }
    }

    async fn is_deployed<T>(&self, addr: T) -> anyhow::Result<bool>
    where
        T: Into<NameOrAddress> + Send + Sync,
    {
        let code = self
            .client
            .get_code(addr, None)
            .await
            .context("should get proxy code")?;
        Ok(!code.is_empty())
    }

    fn format_salt(salt: u64) -> String {
        format!("{:?}", H256::from_low_u64_be(salt))[2..].to_owned()
    }
}
