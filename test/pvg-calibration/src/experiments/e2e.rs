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

//! E6: end to end through a running rundler.
//!
//! The harness acts as a wallet. It builds user operations for real account implementations,
//! takes every gas field from rundler's `eth_estimateUserOperationGas`, signs, and submits with
//! `eth_sendUserOperation`. Against EntryPoint v0.7: LightAccount v2, MultiOwnerLightAccount v2,
//! ModularAccount v2, and EIP-7702 delegation to SemiModularAccount7702. Against v0.6:
//! LightAccount v1.1, SimpleAccount v0.6 and MultiOwnerModularAccount v1. Rundler builds and sends the bundles. For each
//! mined bundle the experiment compares what the EntryPoint charged the ops (paid to the
//! bundler's beneficiary) with what the bundler paid for the transaction:
//!
//! ```text
//! margin = Σ actualGasCost − receipt.gasUsed × effectiveGasPrice
//! ```
//!
//! A negative margin means the bundler lost money on the bundle.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_network::TransactionBuilder;
use alloy_primitives::{Address, B256, Bytes, I256, U128, U256, address, eip191_hash_message, hex};
use alloy_provider::Provider;
use alloy_rpc_client::{ClientBuilder, RpcClient};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_macro::sol;
use alloy_sol_types::{SolCall, SolEvent};
use anyhow::{Context, bail};
use rundler_contracts::v0_7::IEntryPoint;
use rundler_types::{
    EntryPointVersion, UserOperation as _, UserOperationVariant, authorization::Eip7702Auth,
    chain::ChainSpec, v0_6 as uo_v0_6, v0_7 as uo_v0_7,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    fixtures::{self, EpVersion, Fixtures},
    harness::Harness,
};

sol! {
    interface ILightAccountFactory {
        function getAddress(address owner, uint256 salt) external view returns (address);
        function createAccount(address owner, uint256 salt) external returns (address);
    }
    interface IMultiOwnerLightAccountFactory {
        function getAddress(address[] owners, uint256 salt) external view returns (address);
        function createAccount(address[] owners, uint256 salt) external returns (address);
    }
    interface IModularAccountFactory {
        function getAddressSemiModular(address owner, uint256 salt) external view returns (address);
        function createSemiModularAccount(address owner, uint256 salt) external returns (address);
    }
    interface IMultiOwnerModularAccountFactory {
        function getAddress(uint256 salt, address[] owners) external view returns (address);
        function createAccount(uint256 salt, address[] owners) external returns (address);
    }
    interface IAccountExecute {
        function execute(address dest, uint256 value, bytes data) external;
    }
}

const LIGHT_ACCOUNT_FACTORY: Address = address!("0000000000400CdFef5E2714E63d8040b700BC24");
const MULTI_OWNER_LIGHT_ACCOUNT_FACTORY: Address =
    address!("000000000019d2Ee9F2729A65AfE20bb0020AefC");
const MODULAR_ACCOUNT_FACTORY: Address = address!("00000000000017c61b5bEe81050EC8eFc9c6fecd");
const SEMI_MODULAR_ACCOUNT_7702: Address = address!("69007702764179f14F51cdce752f4f775d74E139");
/// EntryPoint v0.6 account factories. LightAccountFactory v1.1.0 and SimpleAccountFactory share
/// the `(owner, salt)` interface of `ILightAccountFactory`.
const LIGHT_ACCOUNT_V1_1_FACTORY: Address = address!("00004EC70002a32400f8ae005A26081065620D20");
const SIMPLE_ACCOUNT_V0_6_FACTORY: Address = address!("9406Cc6185a346906296840746125a0E44976454");
const MULTI_OWNER_MODULAR_ACCOUNT_FACTORY: Address =
    address!("000000e92D78D90000007F0082006FDA09BD5f11");

/// ECDSA-shaped dummy signature for estimation (as aa-sdk uses).
const DUMMY_ECDSA: [u8; 65] = hex!(
    "fffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c"
);
/// ModularAccount v2 nonce key: fallback validation (entity 0), global validation flag.
const MODULAR_ACCOUNT_GLOBAL_FALLBACK_NONCE_KEY: u64 = 1;

/// A self-paying sender is funded with this much gas at the op's `maxFeePerGas` before its first
/// op; covers the prefund with headroom. Funding and deposits scale with the fee because the
/// harness cannot recover them (owners are throwaway keys, probe paymasters cannot withdraw).
const SELF_PAY_FUNDING_GAS: u128 = 10_000_000;
/// The paymaster deposit kept for the sponsored scenarios, in gas at the current fee.
const PAYMASTER_DEPOSIT_GAS: u128 = 100_000_000;
/// How long to wait for rundler to mine a submitted op.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    LightAccount,
    MultiOwnerLightAccount,
    ModularAccountV2,
    /// EOA delegated (EIP-7702) to SemiModularAccount7702
    Sma7702,
    /// LightAccount v1.1.0 (EntryPoint v0.6)
    LightAccountV1_1,
    /// eth-infinitism SimpleAccount (EntryPoint v0.6)
    SimpleAccountV0_6,
    /// MultiOwnerModularAccount v1 (EntryPoint v0.6)
    MultiOwnerModularAccount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Payer {
    /// No paymaster; the sender pays from its own balance (deposit starts at zero)
    SelfPay,
    /// The probe paymaster sponsors the op
    Paymaster,
}

/// A wallet account the harness controls.
struct Account {
    kind: Kind,
    owner: PrivateKeySigner,
    sender: Address,
    /// Factory call to deploy the account, until its first op has mined
    factory: Option<(Address, Bytes)>,
    nonce_key: u64,
}

#[derive(Debug, Clone, Serialize)]
struct Estimate {
    pre_verification_gas: u128,
    verification_gas_limit: u128,
    call_gas_limit: u128,
    paymaster_verification_gas_limit: Option<u128>,
}

#[derive(Debug, Serialize)]
struct OpResult {
    scenario: String,
    kind: Kind,
    payer: Payer,
    deploy_in_op: bool,
    authorization: bool,
    sender: Address,
    estimate: Option<Estimate>,
    user_op_hash: Option<B256>,
    tx_hash: Option<B256>,
    success: Option<bool>,
    actual_gas_used: Option<u128>,
    actual_gas_cost: Option<U256>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct BundleResult {
    tx_hash: B256,
    ops: usize,
    scenarios: Vec<String>,
    gas_used: u64,
    effective_gas_price: u128,
    /// What the bundler paid: gasUsed × effectiveGasPrice
    cost_wei: U256,
    /// What the EntryPoint charged the ops (paid to the beneficiary)
    charged_wei: U256,
    /// charged − cost; negative means the bundler lost money
    margin_wei: I256,
    /// Σ actualGasUsed − gasUsed: the margin in gas, independent of the price difference between
    /// the ops' gas price and the bundle transaction's
    margin_gas: i128,
}

#[derive(Debug, Serialize)]
pub struct Report {
    experiment: &'static str,
    bundler_rpc_url: String,
    fixtures: Fixtures,
    ops: Vec<OpResult>,
    bundles: Vec<BundleResult>,
}

struct Client<'a> {
    harness: &'a Harness,
    fixtures: &'a Fixtures,
    spec: ChainSpec,
    bundler: RpcClient,
}

pub async fn run(
    harness: &Harness,
    fixtures: &Fixtures,
    chain_id: u64,
    bundler_rpc_url: &str,
) -> anyhow::Result<Report> {
    let bundler = ClientBuilder::default().http(bundler_rpc_url.parse()?);
    let client = Client {
        harness,
        fixtures,
        spec: ChainSpec {
            id: chain_id,
            ..ChainSpec::default()
        },
        bundler,
    };
    client.ensure_paymaster_deposit().await?;

    let mut ops = Vec::new();
    match fixtures.entry_point_version {
        EpVersion::V0_6 => run_v0_6(&client, &mut ops).await?,
        EpVersion::V0_7 => run_v0_7(&client, &mut ops).await?,
    }

    let bundles = client.bundles(&ops).await?;
    for b in &bundles {
        eprintln!(
            "bundle {} ops={} gas_used={} margin_gas={} margin_wei={} [{}]",
            b.tx_hash,
            b.ops,
            b.gas_used,
            b.margin_gas,
            b.margin_wei,
            b.scenarios.join(", ")
        );
    }

    Ok(Report {
        experiment: "e6-end-to-end",
        bundler_rpc_url: bundler_rpc_url.to_string(),
        fixtures: fixtures.clone(),
        ops,
        bundles,
    })
}

/// Single-op bundles (one op mined before the next is sent), then one multi-op bundle.
async fn run_v0_7(client: &Client<'_>, ops: &mut Vec<OpResult>) -> anyhow::Result<()> {
    for (name, kind, payer) in [
        (
            "light-account/deploy/self-pay",
            Kind::LightAccount,
            Payer::SelfPay,
        ),
        (
            "light-account/deploy/paymaster",
            Kind::LightAccount,
            Payer::Paymaster,
        ),
        (
            "multi-owner-light-account/deploy/self-pay",
            Kind::MultiOwnerLightAccount,
            Payer::SelfPay,
        ),
        (
            "modular-account-v2/deploy/self-pay",
            Kind::ModularAccountV2,
            Payer::SelfPay,
        ),
        (
            "modular-account-v2/deploy/paymaster",
            Kind::ModularAccountV2,
            Payer::Paymaster,
        ),
    ] {
        let follow_up =
            (name == "light-account/deploy/self-pay").then_some("light-account/deployed/self-pay");
        client
            .submit_scenario(ops, name, kind, payer, follow_up)
            .await?;
    }

    // EIP-7702: an EOA that does not exist yet (sponsored), and a funded EOA paying for itself.
    for (name, payer) in [
        ("sma-7702/empty-authority/paymaster", Payer::Paymaster),
        ("sma-7702/funded-authority/self-pay", Payer::SelfPay),
    ] {
        let mut account = client.new_account(Kind::Sma7702).await?;
        if payer == Payer::SelfPay {
            client.fund(account.sender).await?;
        }
        let auth = client.sign_delegation(&account.owner).await?;
        ops.push(
            client
                .submit_and_wait(name, &mut account, payer, Some(auth))
                .await,
        );
        if payer == Payer::SelfPay {
            // Already delegated: no authorization needed any more.
            ops.push(
                client
                    .submit_and_wait("sma-7702/delegated/self-pay", &mut account, payer, None)
                    .await,
            );
        }
    }

    ops.extend(
        client
            .submit_batch("batch/light-account/deploy/self-pay", Kind::LightAccount)
            .await?,
    );
    Ok(())
}

/// As [`run_v0_7`], with v0.6 accounts and no EIP-7702 scenarios.
async fn run_v0_6(client: &Client<'_>, ops: &mut Vec<OpResult>) -> anyhow::Result<()> {
    for (name, kind, payer) in [
        (
            "light-account-v1.1/deploy/self-pay",
            Kind::LightAccountV1_1,
            Payer::SelfPay,
        ),
        (
            "light-account-v1.1/deploy/paymaster",
            Kind::LightAccountV1_1,
            Payer::Paymaster,
        ),
        (
            "simple-account/deploy/self-pay",
            Kind::SimpleAccountV0_6,
            Payer::SelfPay,
        ),
        (
            "simple-account/deploy/paymaster",
            Kind::SimpleAccountV0_6,
            Payer::Paymaster,
        ),
        (
            "multi-owner-modular-account/deploy/self-pay",
            Kind::MultiOwnerModularAccount,
            Payer::SelfPay,
        ),
    ] {
        let follow_up = (name == "light-account-v1.1/deploy/self-pay")
            .then_some("light-account-v1.1/deployed/self-pay");
        client
            .submit_scenario(ops, name, kind, payer, follow_up)
            .await?;
    }

    ops.extend(
        client
            .submit_batch(
                "batch/light-account-v1.1/deploy/self-pay",
                Kind::LightAccountV1_1,
            )
            .await?,
    );
    Ok(())
}

impl Client<'_> {
    /// One op from a new account (funded first when it pays for itself). With `follow_up`, a
    /// second op from the same, now deployed, account (its deposit is no longer zero).
    async fn submit_scenario(
        &self,
        ops: &mut Vec<OpResult>,
        name: &str,
        kind: Kind,
        payer: Payer,
        follow_up: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut account = self.new_account(kind).await?;
        if payer == Payer::SelfPay {
            self.fund(account.sender).await?;
        }
        ops.push(self.submit_and_wait(name, &mut account, payer, None).await);
        if let Some(follow_up) = follow_up {
            ops.push(
                self.submit_and_wait(follow_up, &mut account, payer, None)
                    .await,
            );
        }
        Ok(())
    }

    async fn ensure_paymaster_deposit(&self) -> anyhow::Result<()> {
        let ep = self.fixtures.entry_point;
        let pm = self.fixtures.paymaster;
        let deposit = fixtures::deposit_of(self.harness, ep, pm).await?;
        let (max_fee, _) = self.fees().await?;
        let target = U256::from(PAYMASTER_DEPOSIT_GAS * max_fee);
        if deposit < target {
            fixtures::deposit_to(self.harness, ep, pm, target - deposit).await?;
        }
        Ok(())
    }

    async fn fund(&self, address: Address) -> anyhow::Result<()> {
        let (max_fee, _) = self.fees().await?;
        let outcome = self
            .harness
            .send(
                TransactionRequest::default()
                    .with_to(address)
                    .with_value(U256::from(SELF_PAY_FUNDING_GAS * max_fee)),
            )
            .await?;
        anyhow::ensure!(outcome.success, "funding {address} reverted");
        Ok(())
    }

    async fn eth_call<C: SolCall>(&self, to: Address, call: C) -> anyhow::Result<C::Return> {
        let ret = self
            .harness
            .provider
            .call(
                TransactionRequest::default()
                    .with_to(to)
                    .with_input(call.abi_encode()),
            )
            .await?;
        Ok(C::abi_decode_returns(&ret)?)
    }

    async fn new_account(&self, kind: Kind) -> anyhow::Result<Account> {
        let owner = PrivateKeySigner::random();
        let o = owner.address();
        let salt = U256::ZERO;
        let (sender, factory, nonce_key) = match kind {
            Kind::LightAccount => {
                let sender = self
                    .eth_call(
                        LIGHT_ACCOUNT_FACTORY,
                        ILightAccountFactory::getAddressCall { owner: o, salt },
                    )
                    .await?;
                let data = ILightAccountFactory::createAccountCall { owner: o, salt }.abi_encode();
                (sender, Some((LIGHT_ACCOUNT_FACTORY, data.into())), 0)
            }
            Kind::MultiOwnerLightAccount => {
                let owners = vec![o];
                let sender = self
                    .eth_call(
                        MULTI_OWNER_LIGHT_ACCOUNT_FACTORY,
                        IMultiOwnerLightAccountFactory::getAddressCall {
                            owners: owners.clone(),
                            salt,
                        },
                    )
                    .await?;
                let data =
                    IMultiOwnerLightAccountFactory::createAccountCall { owners, salt }.abi_encode();
                (
                    sender,
                    Some((MULTI_OWNER_LIGHT_ACCOUNT_FACTORY, data.into())),
                    0,
                )
            }
            Kind::ModularAccountV2 => {
                let sender = self
                    .eth_call(
                        MODULAR_ACCOUNT_FACTORY,
                        IModularAccountFactory::getAddressSemiModularCall { owner: o, salt },
                    )
                    .await?;
                let data = IModularAccountFactory::createSemiModularAccountCall { owner: o, salt }
                    .abi_encode();
                (
                    sender,
                    Some((MODULAR_ACCOUNT_FACTORY, data.into())),
                    MODULAR_ACCOUNT_GLOBAL_FALLBACK_NONCE_KEY,
                )
            }
            Kind::Sma7702 => (o, None, MODULAR_ACCOUNT_GLOBAL_FALLBACK_NONCE_KEY),
            Kind::LightAccountV1_1 | Kind::SimpleAccountV0_6 => {
                let factory = if kind == Kind::LightAccountV1_1 {
                    LIGHT_ACCOUNT_V1_1_FACTORY
                } else {
                    SIMPLE_ACCOUNT_V0_6_FACTORY
                };
                let sender = self
                    .eth_call(
                        factory,
                        ILightAccountFactory::getAddressCall { owner: o, salt },
                    )
                    .await?;
                let data = ILightAccountFactory::createAccountCall { owner: o, salt }.abi_encode();
                (sender, Some((factory, data.into())), 0)
            }
            Kind::MultiOwnerModularAccount => {
                let owners = vec![o];
                let sender = self
                    .eth_call(
                        MULTI_OWNER_MODULAR_ACCOUNT_FACTORY,
                        IMultiOwnerModularAccountFactory::getAddressCall {
                            salt,
                            owners: owners.clone(),
                        },
                    )
                    .await?;
                let data = IMultiOwnerModularAccountFactory::createAccountCall { salt, owners }
                    .abi_encode();
                (
                    sender,
                    Some((MULTI_OWNER_MODULAR_ACCOUNT_FACTORY, data.into())),
                    0,
                )
            }
        };
        Ok(Account {
            kind,
            owner,
            sender,
            factory,
            nonce_key,
        })
    }

    async fn sign_delegation(&self, owner: &PrivateKeySigner) -> anyhow::Result<Eip7702Auth> {
        let nonce = self
            .harness
            .provider
            .get_transaction_count(owner.address())
            .await?;
        let auth = Authorization {
            chain_id: U256::from(self.spec.id),
            address: SEMI_MODULAR_ACCOUNT_7702,
            nonce,
        };
        let signature = owner.sign_hash_sync(&auth.signature_hash())?;
        let signed: SignedAuthorization = auth.into_signed(signature);
        Ok(Eip7702Auth::from(signed))
    }

    async fn nonce(&self, account: &Account) -> anyhow::Result<U256> {
        sol! {
            interface INonceManager {
                function getNonce(address sender, uint192 key) external view returns (uint256);
            }
        }
        self.eth_call(
            self.fixtures.entry_point,
            INonceManager::getNonceCall {
                sender: account.sender,
                key: alloy_primitives::aliases::U192::from(account.nonce_key),
            },
        )
        .await
    }

    fn signature_prefix(kind: Kind) -> &'static [u8] {
        match kind {
            Kind::LightAccount | Kind::MultiOwnerLightAccount => &[0x00],
            // ModularAccount v2: final signature segment marker, then the EOA signature type
            Kind::ModularAccountV2 | Kind::Sma7702 => &[0xFF, 0x00],
            // v0.6 accounts take the bare ECDSA signature
            Kind::LightAccountV1_1 | Kind::SimpleAccountV0_6 | Kind::MultiOwnerModularAccount => {
                &[]
            }
        }
    }

    fn dummy_signature(kind: Kind) -> Bytes {
        let mut sig = Self::signature_prefix(kind).to_vec();
        sig.extend_from_slice(&DUMMY_ECDSA);
        sig.into()
    }

    async fn fees(&self) -> anyhow::Result<(u128, u128)> {
        let priority: U128 = self
            .bundler
            .request("rundler_maxPriorityFeePerGas", ())
            .await
            .context("rundler_maxPriorityFeePerGas")?;
        let base_fee = self
            .harness
            .provider
            .get_block(alloy_rpc_types_eth::BlockId::latest())
            .await?
            .and_then(|b| b.header.base_fee_per_gas)
            .unwrap_or(1) as u128;
        let priority = priority.to::<u128>();
        Ok((base_fee * 2 + priority, priority))
    }

    /// Builds the op with rundler's gas estimate and a real signature.
    async fn build(
        &self,
        account: &Account,
        payer: Payer,
        auth: Option<&Eip7702Auth>,
    ) -> anyhow::Result<(UserOperationVariant, Estimate)> {
        let nonce = self.nonce(account).await?;
        let (max_fee, priority) = self.fees().await?;
        let call_data: Bytes = IAccountExecute::executeCall {
            dest: Address::repeat_byte(0x11),
            value: U256::ZERO,
            data: Bytes::new(),
        }
        .abi_encode()
        .into();
        let version = self.fixtures.entry_point_version;
        let paymaster = self.fixtures.paymaster;

        let mut request = json!({
            "sender": account.sender,
            "nonce": nonce,
            "callData": call_data,
            "maxFeePerGas": U128::from(max_fee),
            "maxPriorityFeePerGas": U128::from(priority),
            "signature": Self::dummy_signature(account.kind),
        });
        match version {
            EpVersion::V0_6 => {
                request["initCode"] = json!(Self::init_code(account));
                request["paymasterAndData"] = json!(if payer == Payer::Paymaster {
                    Bytes::copy_from_slice(paymaster.as_slice())
                } else {
                    Bytes::new()
                });
            }
            EpVersion::V0_7 => {
                if let Some((factory, data)) = &account.factory {
                    request["factory"] = json!(factory);
                    request["factoryData"] = json!(data);
                }
                if payer == Payer::Paymaster {
                    request["paymaster"] = json!(paymaster);
                    request["paymasterData"] = json!(Bytes::new());
                    request["paymasterPostOpGasLimit"] = json!(U128::ZERO);
                }
            }
        }
        if let Some(auth) = auth {
            request["eip7702Auth"] = serde_json::to_value(auth)?;
        }
        let estimate: Value = self
            .bundler
            .request(
                "eth_estimateUserOperationGas",
                (request, self.fixtures.entry_point),
            )
            .await
            .context("eth_estimateUserOperationGas")?;
        let field = |name: &str| -> anyhow::Result<u128> {
            let v: U128 = serde_json::from_value(estimate[name].clone())
                .with_context(|| format!("estimate field {name}: {estimate}"))?;
            Ok(v.to::<u128>())
        };
        let estimate = Estimate {
            pre_verification_gas: field("preVerificationGas")?,
            verification_gas_limit: field("verificationGasLimit")?,
            call_gas_limit: field("callGasLimit")?,
            paymaster_verification_gas_limit: estimate
                .get("paymasterVerificationGasLimit")
                .filter(|v| !v.is_null())
                .map(|_| field("paymasterVerificationGasLimit"))
                .transpose()?,
        };

        let assemble = |signature: Bytes| -> UserOperationVariant {
            match version {
                EpVersion::V0_6 => {
                    let mut builder = uo_v0_6::UserOperationBuilder::new(
                        &self.spec,
                        uo_v0_6::UserOperationRequiredFields {
                            sender: account.sender,
                            nonce,
                            init_code: Self::init_code(account),
                            call_data: call_data.clone(),
                            call_gas_limit: estimate.call_gas_limit,
                            verification_gas_limit: estimate.verification_gas_limit,
                            pre_verification_gas: estimate.pre_verification_gas,
                            max_fee_per_gas: max_fee,
                            max_priority_fee_per_gas: priority,
                            paymaster_and_data: if payer == Payer::Paymaster {
                                Bytes::copy_from_slice(paymaster.as_slice())
                            } else {
                                Bytes::new()
                            },
                            signature,
                        },
                    );
                    if let Some(auth) = auth {
                        builder = builder.authorization_tuple(auth.clone());
                    }
                    builder.build().into()
                }
                EpVersion::V0_7 => {
                    let mut builder = uo_v0_7::UserOperationBuilder::new(
                        &self.spec,
                        EntryPointVersion::V0_7,
                        uo_v0_7::UserOperationRequiredFields {
                            sender: account.sender,
                            nonce,
                            call_data: call_data.clone(),
                            call_gas_limit: estimate.call_gas_limit,
                            verification_gas_limit: estimate.verification_gas_limit,
                            pre_verification_gas: estimate.pre_verification_gas,
                            max_priority_fee_per_gas: priority,
                            max_fee_per_gas: max_fee,
                            signature,
                        },
                    );
                    if let Some((factory, data)) = &account.factory {
                        builder = builder.factory(*factory, data.clone());
                    }
                    if payer == Payer::Paymaster {
                        builder = builder.paymaster(
                            paymaster,
                            estimate
                                .paymaster_verification_gas_limit
                                .unwrap_or_default(),
                            0,
                            Bytes::new(),
                        );
                    }
                    if let Some(auth) = auth {
                        builder = builder.authorization_tuple(auth.clone());
                    }
                    builder.build().into()
                }
            }
        };

        // The signature is not part of the hash. Every account here signs the EIP-191 hash of the
        // userOpHash.
        let hash = assemble(Bytes::new()).hash();
        let ecdsa = account.owner.sign_hash_sync(&eip191_hash_message(hash))?;
        let mut signature = Self::signature_prefix(account.kind).to_vec();
        signature.extend_from_slice(&ecdsa.as_bytes());
        Ok((assemble(signature.into()), estimate))
    }

    /// v0.6 `initCode`: factory address followed by the factory call, or empty once deployed.
    fn init_code(account: &Account) -> Bytes {
        account
            .factory
            .as_ref()
            .map(|(factory, data)| [factory.as_slice(), data.as_ref()].concat().into())
            .unwrap_or_default()
    }

    fn rpc_op(op: &UserOperationVariant) -> anyhow::Result<Value> {
        let mut v = json!({
            "sender": op.sender(),
            "nonce": op.nonce(),
            "callData": op.call_data(),
            "callGasLimit": U128::from(op.call_gas_limit()),
            "verificationGasLimit": U128::from(op.verification_gas_limit()),
            "preVerificationGas": U256::from(op.pre_verification_gas()),
            "maxFeePerGas": U128::from(op.max_fee_per_gas()),
            "maxPriorityFeePerGas": U128::from(op.max_priority_fee_per_gas()),
            "signature": op.signature(),
        });
        match op {
            UserOperationVariant::V0_6(op) => {
                v["initCode"] = json!(op.init_code());
                v["paymasterAndData"] = json!(op.paymaster_and_data());
            }
            UserOperationVariant::V0_7(op) => {
                if let Some(factory) = op.factory() {
                    v["factory"] = json!(factory);
                    v["factoryData"] = json!(op.factory_data());
                }
                if let Some(paymaster) = op.paymaster() {
                    v["paymaster"] = json!(paymaster);
                    v["paymasterVerificationGasLimit"] =
                        json!(U128::from(op.paymaster_verification_gas_limit()));
                    v["paymasterPostOpGasLimit"] =
                        json!(U128::from(op.paymaster_post_op_gas_limit()));
                    v["paymasterData"] = json!(op.paymaster_data());
                }
            }
        }
        if let Some(auth) = op.authorization_tuple() {
            v["eip7702Auth"] = serde_json::to_value(auth)?;
        }
        Ok(v)
    }

    async fn send(&self, op: &UserOperationVariant) -> anyhow::Result<B256> {
        let hash: B256 = self
            .bundler
            .request(
                "eth_sendUserOperation",
                (Self::rpc_op(op)?, self.fixtures.entry_point),
            )
            .await
            .context("eth_sendUserOperation")?;
        if hash != op.hash() {
            bail!("rundler returned hash {hash}, expected {}", op.hash());
        }
        Ok(hash)
    }

    async fn wait_receipt(&self, hash: B256) -> anyhow::Result<Value> {
        let start = Instant::now();
        loop {
            let receipt: Value = self
                .bundler
                .request("eth_getUserOperationReceipt", (hash,))
                .await
                .context("eth_getUserOperationReceipt")?;
            if !receipt.is_null() {
                return Ok(receipt);
            }
            if start.elapsed() > RECEIPT_TIMEOUT {
                bail!("op {hash} not mined after {RECEIPT_TIMEOUT:?}");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    fn op_result(name: &str, account: &Account, payer: Payer, auth: bool) -> OpResult {
        OpResult {
            scenario: name.to_string(),
            kind: account.kind,
            payer,
            deploy_in_op: account.factory.is_some(),
            authorization: auth,
            sender: account.sender,
            estimate: None,
            user_op_hash: None,
            tx_hash: None,
            success: None,
            actual_gas_used: None,
            actual_gas_cost: None,
            error: None,
        }
    }

    fn fill_receipt(result: &mut OpResult, receipt: &Value) -> anyhow::Result<()> {
        let u = |name: &str| -> anyhow::Result<U256> {
            serde_json::from_value(receipt[name].clone())
                .with_context(|| format!("receipt field {name}"))
        };
        result.tx_hash = Some(
            serde_json::from_value(receipt["receipt"]["transactionHash"].clone())
                .context("receipt transactionHash")?,
        );
        result.success = receipt["success"].as_bool();
        result.actual_gas_used = Some(u("actualGasUsed")?.to::<u128>());
        result.actual_gas_cost = Some(u("actualGasCost")?);
        Ok(())
    }

    async fn submit_and_wait(
        &self,
        name: &str,
        account: &mut Account,
        payer: Payer,
        auth: Option<Eip7702Auth>,
    ) -> OpResult {
        let mut result = Self::op_result(name, account, payer, auth.is_some());
        let outcome: anyhow::Result<()> = async {
            let (op, estimate) = self.build(account, payer, auth.as_ref()).await?;
            result.estimate = Some(estimate);
            let hash = self.send(&op).await?;
            result.user_op_hash = Some(hash);
            let receipt = self.wait_receipt(hash).await?;
            Self::fill_receipt(&mut result, &receipt)?;
            Ok(())
        }
        .await;
        if let Err(e) = outcome {
            eprintln!("{name}: FAILED: {e:#}");
            result.error = Some(format!("{e:#}"));
        } else {
            // Deployed now; later ops from this account carry no initCode.
            account.factory = None;
            eprintln!(
                "{name}: mined in {} actualGasUsed={} pvg={}",
                result.tx_hash.unwrap_or_default(),
                result.actual_gas_used.unwrap_or_default(),
                result
                    .estimate
                    .as_ref()
                    .map(|e| e.pre_verification_gas)
                    .unwrap_or_default()
            );
        }
        result
    }

    /// Several self-paying deployments of `kind` submitted together, for one multi-op bundle.
    async fn submit_batch(&self, name: &str, kind: Kind) -> anyhow::Result<Vec<OpResult>> {
        const BATCH: usize = 3;
        let mut accounts = Vec::new();
        for _ in 0..BATCH {
            let account = self.new_account(kind).await?;
            self.fund(account.sender).await?;
            accounts.push(account);
        }
        let mut results = Vec::new();
        let mut pending = Vec::new();
        for account in &accounts {
            let mut result = Self::op_result(name, account, Payer::SelfPay, false);
            match self.build(account, Payer::SelfPay, None).await {
                Ok((op, estimate)) => {
                    result.estimate = Some(estimate);
                    pending.push((results.len(), op));
                }
                Err(e) => result.error = Some(format!("{e:#}")),
            }
            results.push(result);
        }
        // Send all before waiting so they land in the same bundle.
        let mut hashes = Vec::new();
        for (i, op) in &pending {
            match self.send(op).await {
                Ok(hash) => {
                    results[*i].user_op_hash = Some(hash);
                    hashes.push((*i, hash));
                }
                Err(e) => results[*i].error = Some(format!("{e:#}")),
            }
        }
        for (i, hash) in hashes {
            match self.wait_receipt(hash).await {
                Ok(receipt) => {
                    if let Err(e) = Self::fill_receipt(&mut results[i], &receipt) {
                        results[i].error = Some(format!("{e:#}"));
                    }
                }
                Err(e) => results[i].error = Some(format!("{e:#}")),
            }
        }
        for r in &results {
            eprintln!(
                "{name}: tx={:?} actualGasUsed={:?} error={:?}",
                r.tx_hash, r.actual_gas_used, r.error
            );
        }
        Ok(results)
    }

    /// Groups mined ops by bundle transaction and computes the bundler's margin on each.
    async fn bundles(&self, ops: &[OpResult]) -> anyhow::Result<Vec<BundleResult>> {
        let mut by_tx: BTreeMap<B256, Vec<String>> = BTreeMap::new();
        for op in ops {
            if let Some(tx) = op.tx_hash {
                by_tx.entry(tx).or_default().push(op.scenario.clone());
            }
        }
        let mut bundles = Vec::new();
        for (tx_hash, scenarios) in by_tx {
            let receipt = self
                .harness
                .provider
                .get_transaction_receipt(tx_hash)
                .await?
                .with_context(|| format!("no receipt for {tx_hash}"))?;
            let mut charged = U256::ZERO;
            let mut actual_gas_used = 0_u128;
            let mut count = 0;
            for log in receipt.inner.logs() {
                if log.address() == self.fixtures.entry_point
                    && log.topic0() == Some(&IEntryPoint::UserOperationEvent::SIGNATURE_HASH)
                {
                    let ev = log
                        .log_decode::<IEntryPoint::UserOperationEvent>()?
                        .inner
                        .data;
                    charged += ev.actualGasCost;
                    actual_gas_used += ev.actualGasUsed.to::<u128>();
                    count += 1;
                }
            }
            let cost = U256::from(receipt.gas_used) * U256::from(receipt.effective_gas_price);
            bundles.push(BundleResult {
                tx_hash,
                ops: count,
                scenarios,
                gas_used: receipt.gas_used,
                effective_gas_price: receipt.effective_gas_price,
                cost_wei: cost,
                charged_wei: charged,
                margin_wei: I256::try_from(charged)? - I256::try_from(cost)?,
                margin_gas: actual_gas_used as i128 - receipt.gas_used as i128,
            });
        }
        Ok(bundles)
    }
}
