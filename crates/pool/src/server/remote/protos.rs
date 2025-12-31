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

use alloy_primitives::{Address, B256};
use anyhow::{anyhow, Context};
use rundler_task::grpc::protos::{from_bytes, ConversionError, ToProtoBytes};
use rundler_types::{
    authorization::Eip7702Auth,
    chain::ChainSpec,
    da::{
        BedrockDAGasData as RundlerBedrockDAGasData, DAGasData as RundlerDAGasData,
        NitroDAGasData as RundlerNitroDAGasData,
    },
    pool::{
        AddressUpdate as PoolAddressUpdate, NewHead as PoolNewHead,
        PaymasterMetadata as PoolPaymasterMetadata, PoolOperation,
        PoolOperationSummary as RundlerPoolOperationSummary, PreconfInfo as RundlerPreconfInfo,
        Reputation as PoolReputation, ReputationStatus as PoolReputationStatus,
        StakeStatus as RundlerStakeStatus,
    },
    v0_6, v0_7, BundlerSponsorship as RundlerBundlerSponsorship, Entity as RundlerEntity,
    EntityInfos, EntityType as RundlerEntityType, EntityUpdate as RundlerEntityUpdate,
    EntityUpdateType as RundlerEntityUpdateType, EntryPointVersion as RundlerEntryPointVersion,
    StakeInfo as RundlerStakeInfo, UserOperation as _,
    UserOperationPermissions as RundlerUserOperationPermissions, UserOperationVariant,
    ValidTimeRange,
};

tonic::include_proto!("op_pool");

pub const OP_POOL_FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("op_pool_descriptor");

impl From<&UserOperationVariant> for UserOperation {
    fn from(op: &UserOperationVariant) -> Self {
        match op {
            UserOperationVariant::V0_6(op) => op.into(),
            UserOperationVariant::V0_7(op) => op.into(),
        }
    }
}

impl From<&v0_6::UserOperation> for UserOperation {
    fn from(op: &v0_6::UserOperation) -> Self {
        let authorization_tuple = op
            .authorization_tuple()
            .map(|authorization| AuthorizationTuple::from(authorization.clone()));
        let op = UserOperationV06 {
            sender: op.sender().to_proto_bytes(),
            nonce: op.nonce().to_proto_bytes(),
            init_code: op.init_code().to_proto_bytes(),
            call_data: op.call_data().to_proto_bytes(),
            call_gas_limit: op.call_gas_limit().to_proto_bytes(),
            verification_gas_limit: op.verification_gas_limit().to_proto_bytes(),
            pre_verification_gas: op.pre_verification_gas().to_proto_bytes(),
            max_fee_per_gas: op.max_fee_per_gas().to_proto_bytes(),
            max_priority_fee_per_gas: op.max_priority_fee_per_gas().to_proto_bytes(),
            paymaster_and_data: op.paymaster_and_data().to_proto_bytes(),
            signature: op.signature().to_proto_bytes(),
            authorization_tuple,
            aggregator: op
                .aggregator()
                .map(|a| a.to_proto_bytes())
                .unwrap_or_default(),
        };
        UserOperation {
            uo: Some(user_operation::Uo::V06(op)),
        }
    }
}

pub trait TryUoFromProto<T>: Sized {
    fn try_uo_from_proto(value: T, chain_spec: &ChainSpec) -> Result<Self, ConversionError>;
}

impl From<AuthorizationTuple> for Eip7702Auth {
    fn from(value: AuthorizationTuple) -> Self {
        Eip7702Auth {
            chain_id: value.chain_id,
            address: from_bytes(&value.address).unwrap_or_default(),
            nonce: value.nonce,
            y_parity: value.y_parity as u8,
            r: from_bytes(&value.r).unwrap_or_default(),
            s: from_bytes(&value.s).unwrap_or_default(),
        }
    }
}

impl From<Eip7702Auth> for AuthorizationTuple {
    fn from(value: Eip7702Auth) -> Self {
        AuthorizationTuple {
            chain_id: value.chain_id,
            address: value.address.to_proto_bytes(),
            nonce: value.nonce,
            y_parity: value.y_parity.into(),
            r: value.r.to_proto_bytes(),
            s: value.s.to_proto_bytes(),
        }
    }
}
impl TryUoFromProto<UserOperationV06> for v0_6::UserOperation {
    fn try_uo_from_proto(
        op: UserOperationV06,
        chain_spec: &ChainSpec,
    ) -> Result<Self, ConversionError> {
        let mut builder = v0_6::UserOperationBuilder::new(
            chain_spec,
            v0_6::UserOperationRequiredFields {
                sender: from_bytes(&op.sender)?,
                nonce: from_bytes(&op.nonce)?,
                init_code: op.init_code.into(),
                call_data: op.call_data.into(),
                call_gas_limit: from_bytes(&op.call_gas_limit)?,
                verification_gas_limit: from_bytes(&op.verification_gas_limit)?,
                pre_verification_gas: from_bytes(&op.pre_verification_gas)?,
                max_fee_per_gas: from_bytes(&op.max_fee_per_gas)?,
                max_priority_fee_per_gas: from_bytes(&op.max_priority_fee_per_gas)?,
                paymaster_and_data: op.paymaster_and_data.into(),
                signature: op.signature.into(),
            },
        );

        if let Some(auth) = &op.authorization_tuple {
            builder = builder.authorization_tuple(Eip7702Auth::from(auth.clone()));
        }

        if !op.aggregator.is_empty() {
            builder = builder.aggregator(from_bytes(&op.aggregator)?);
        }

        Ok(builder.build())
    }
}

impl From<&v0_7::UserOperation> for UserOperation {
    fn from(op: &v0_7::UserOperation) -> Self {
        let op = UserOperationV07 {
            sender: op.sender().to_proto_bytes(),
            nonce: op.nonce().to_proto_bytes(),
            call_data: op.call_data().to_proto_bytes(),
            call_gas_limit: op.call_gas_limit().to_proto_bytes(),
            verification_gas_limit: op.verification_gas_limit().to_proto_bytes(),
            pre_verification_gas: op.pre_verification_gas().to_proto_bytes(),
            max_fee_per_gas: op.max_fee_per_gas().to_proto_bytes(),
            max_priority_fee_per_gas: op.max_priority_fee_per_gas().to_proto_bytes(),
            signature: op.signature().to_proto_bytes(),
            paymaster: op
                .paymaster()
                .map(|p| p.to_proto_bytes())
                .unwrap_or_default(),
            paymaster_data: op.paymaster_data().to_proto_bytes(),
            paymaster_verification_gas_limit: op
                .paymaster_verification_gas_limit()
                .to_proto_bytes(),
            paymaster_post_op_gas_limit: op.paymaster_post_op_gas_limit().to_proto_bytes(),
            factory: op.factory().map(|f| f.to_proto_bytes()).unwrap_or_default(),
            factory_data: op.factory_data().to_proto_bytes(),
            entry_point: op.entry_point().to_proto_bytes(),
            chain_id: op.chain_id(),
            authorization_tuple: op
                .authorization_tuple()
                .map(|authorization| AuthorizationTuple::from(authorization.clone())),
            aggregator: op
                .aggregator()
                .map(|a| a.to_proto_bytes())
                .unwrap_or_default(),
            entry_point_version: EntryPointVersion::from(op.entry_point_version()).into(),
        };
        UserOperation {
            uo: Some(user_operation::Uo::V07(op)),
        }
    }
}

impl TryUoFromProto<UserOperationV07> for v0_7::UserOperation {
    fn try_uo_from_proto(
        op: UserOperationV07,
        chain_spec: &ChainSpec,
    ) -> Result<Self, ConversionError> {
        let authorization_tuple = op
            .authorization_tuple
            .as_ref()
            .map(|authorization| Eip7702Auth::from(authorization.clone()));

        let ep_version = EntryPointVersion::try_from(op.entry_point_version)
            .map_err(|_| ConversionError::InvalidEnumValue(op.entry_point_version))?;

        let mut builder = v0_7::UserOperationBuilder::new(
            chain_spec,
            ep_version.try_into()?,
            v0_7::UserOperationRequiredFields {
                sender: from_bytes(&op.sender)?,
                nonce: from_bytes(&op.nonce)?,
                call_data: op.call_data.into(),
                call_gas_limit: from_bytes(&op.call_gas_limit)?,
                verification_gas_limit: from_bytes(&op.verification_gas_limit)?,
                pre_verification_gas: from_bytes(&op.pre_verification_gas)?,
                max_priority_fee_per_gas: from_bytes(&op.max_priority_fee_per_gas)?,
                max_fee_per_gas: from_bytes(&op.max_fee_per_gas)?,
                signature: op.signature.into(),
            },
        );

        if !op.paymaster.is_empty() {
            builder = builder.paymaster(
                from_bytes(&op.paymaster)?,
                from_bytes(&op.paymaster_verification_gas_limit)?,
                from_bytes(&op.paymaster_post_op_gas_limit)?,
                op.paymaster_data.into(),
            );
        }
        if !op.factory.is_empty() {
            builder = builder.factory(from_bytes(&op.factory)?, op.factory_data.into());
        }
        if let Some(auth) = authorization_tuple {
            builder = builder.authorization_tuple(auth);
        }
        if !op.aggregator.is_empty() {
            builder = builder.aggregator(from_bytes(&op.aggregator)?);
        }

        Ok(builder.build())
    }
}

impl TryUoFromProto<UserOperation> for UserOperationVariant {
    fn try_uo_from_proto(
        op: UserOperation,
        chain_spec: &ChainSpec,
    ) -> Result<Self, ConversionError> {
        let op = op
            .uo
            .expect("User operation should contain user operation oneof");

        match op {
            user_operation::Uo::V06(op) => Ok(UserOperationVariant::V0_6(
                v0_6::UserOperation::try_uo_from_proto(op, chain_spec)?,
            )),
            user_operation::Uo::V07(op) => Ok(UserOperationVariant::V0_7(
                v0_7::UserOperation::try_uo_from_proto(op, chain_spec)?,
            )),
        }
    }
}

impl TryFrom<EntityType> for RundlerEntityType {
    type Error = ConversionError;

    fn try_from(entity: EntityType) -> Result<Self, Self::Error> {
        match entity {
            EntityType::Unspecified => Err(ConversionError::InvalidEnumValue(entity as i32)),
            EntityType::Account => Ok(RundlerEntityType::Account),
            EntityType::Paymaster => Ok(RundlerEntityType::Paymaster),
            EntityType::Aggregator => Ok(RundlerEntityType::Aggregator),
            EntityType::Factory => Ok(RundlerEntityType::Factory),
        }
    }
}

pub const MISSING_ENTITY_ERR_STR: &str = "Entity update should contain entity";
impl TryFrom<&EntityUpdate> for RundlerEntityUpdate {
    type Error = anyhow::Error;

    fn try_from(entity_update: &EntityUpdate) -> Result<Self, Self::Error> {
        let entity = (&(entity_update
            .entity
            .clone()
            .context(MISSING_ENTITY_ERR_STR)?))
            .try_into()?;
        let update_type = RundlerEntityUpdateType::try_from(entity_update.update_type)
            .map_err(|_| ConversionError::InvalidEnumValue(entity_update.update_type))?;
        let value = Some(entity_update.value).filter(|&v| v != 0);
        Ok(RundlerEntityUpdate {
            entity,
            update_type,
            value,
        })
    }
}

impl From<RundlerEntityType> for EntityType {
    fn from(entity: RundlerEntityType) -> Self {
        match entity {
            RundlerEntityType::Account => EntityType::Account,
            RundlerEntityType::Paymaster => EntityType::Paymaster,
            RundlerEntityType::Aggregator => EntityType::Aggregator,
            RundlerEntityType::Factory => EntityType::Factory,
        }
    }
}

impl From<Option<RundlerEntityType>> for EntityType {
    fn from(entity: Option<RundlerEntityType>) -> Self {
        if let Some(e) = entity {
            match e {
                RundlerEntityType::Account => EntityType::Account,
                RundlerEntityType::Paymaster => EntityType::Paymaster,
                RundlerEntityType::Aggregator => EntityType::Aggregator,
                RundlerEntityType::Factory => EntityType::Factory,
            }
        } else {
            EntityType::Unspecified
        }
    }
}

impl TryFrom<&Entity> for RundlerEntity {
    type Error = ConversionError;

    fn try_from(entity: &Entity) -> Result<Self, ConversionError> {
        Ok(RundlerEntity {
            kind: EntityType::try_from(entity.kind)
                .map_err(|_| ConversionError::InvalidEnumValue(entity.kind))?
                .try_into()?,
            address: from_bytes(&entity.address)?,
        })
    }
}

impl From<&RundlerEntity> for Entity {
    fn from(entity: &RundlerEntity) -> Self {
        Entity {
            kind: EntityType::from(entity.kind).into(),
            address: entity.address.to_proto_bytes(),
        }
    }
}

impl From<RundlerEntityUpdateType> for EntityUpdateType {
    fn from(update_type: RundlerEntityUpdateType) -> Self {
        match update_type {
            RundlerEntityUpdateType::UnstakedInvalidation => EntityUpdateType::UnstakedInvalidation,
            RundlerEntityUpdateType::StakedInvalidation => EntityUpdateType::StakedInvalidation,
            RundlerEntityUpdateType::PaymasterOpsSeenDecrement => {
                EntityUpdateType::PaymasterOpsSeenDecrement
            }
        }
    }
}

impl From<&RundlerEntityUpdate> for EntityUpdate {
    fn from(entity_update: &RundlerEntityUpdate) -> Self {
        EntityUpdate {
            entity: Some(Entity::from(&entity_update.entity)),
            update_type: EntityUpdateType::from(entity_update.update_type).into(),
            value: entity_update.value.unwrap_or_default(),
        }
    }
}

impl From<PoolReputationStatus> for ReputationStatus {
    fn from(status: PoolReputationStatus) -> Self {
        match status {
            PoolReputationStatus::Ok => ReputationStatus::Ok,
            PoolReputationStatus::Throttled => ReputationStatus::Throttled,
            PoolReputationStatus::Banned => ReputationStatus::Banned,
        }
    }
}

impl TryFrom<ReputationStatus> for PoolReputationStatus {
    type Error = ConversionError;

    fn try_from(status: ReputationStatus) -> Result<Self, Self::Error> {
        match status {
            ReputationStatus::Ok => Ok(PoolReputationStatus::Ok),
            ReputationStatus::Throttled => Ok(PoolReputationStatus::Throttled),
            ReputationStatus::Banned => Ok(PoolReputationStatus::Banned),
            ReputationStatus::Unspecified => Err(ConversionError::InvalidEnumValue(status as i32)),
        }
    }
}

impl From<PoolReputation> for Reputation {
    fn from(rep: PoolReputation) -> Self {
        Reputation {
            address: rep.address.to_proto_bytes(),
            ops_seen: rep.ops_seen,
            ops_included: rep.ops_included,
        }
    }
}

impl TryFrom<Reputation> for PoolReputation {
    type Error = ConversionError;

    fn try_from(op: Reputation) -> Result<Self, Self::Error> {
        Ok(Self {
            address: from_bytes(&op.address)?,
            ops_seen: op.ops_seen,
            ops_included: op.ops_included,
        })
    }
}

const EMPTY_STAKE_INFO_ERROR: &str = "Stake info cannot be empty";
impl TryFrom<StakeStatus> for RundlerStakeStatus {
    type Error = anyhow::Error;
    fn try_from(stake_status: StakeStatus) -> Result<Self, Self::Error> {
        if let Some(stake_info) = stake_status.stake_info {
            return Ok(RundlerStakeStatus {
                is_staked: stake_status.is_staked,
                stake_info: RundlerStakeInfo {
                    stake: from_bytes(&stake_info.stake)?,
                    unstake_delay_sec: stake_info.unstake_delay_sec,
                },
            });
        }

        Err(anyhow!(EMPTY_STAKE_INFO_ERROR))
    }
}

impl From<RundlerStakeStatus> for StakeStatus {
    fn from(stake_status: RundlerStakeStatus) -> Self {
        StakeStatus {
            is_staked: stake_status.is_staked,
            stake_info: Some(StakeInfo {
                stake: stake_status.stake_info.stake.to_proto_bytes(),
                unstake_delay_sec: stake_status.stake_info.unstake_delay_sec,
            }),
        }
    }
}

impl From<&PoolOperation> for MempoolOp {
    fn from(op: &PoolOperation) -> Self {
        MempoolOp {
            uo: Some(UserOperation::from(&op.uo)),
            entry_point: op.entry_point.to_proto_bytes(),
            aggregator: op.aggregator.map_or(vec![], |a| a.to_proto_bytes()),
            valid_after: op.valid_time_range.valid_after.seconds_since_epoch(),
            valid_until: op.valid_time_range.valid_until.seconds_since_epoch(),
            expected_code_hash: op.expected_code_hash.to_proto_bytes(),
            sim_block_hash: op.sim_block_hash.to_proto_bytes(),
            account_is_staked: op.account_is_staked,
            da_gas_data: Some(DaGasData::from(&op.da_gas_data)),
            filter_id: op.filter_id.clone().unwrap_or_default(),
            permissions: Some(op.perms.clone().into()),
            sender_is_7702: op.sender_is_7702,
        }
    }
}

impl From<&RundlerPreconfInfo> for PreconfInfo {
    fn from(info: &RundlerPreconfInfo) -> Self {
        PreconfInfo {
            tx_hash: info.tx_hash.to_proto_bytes(),
        }
    }
}

impl TryFrom<PreconfInfo> for RundlerPreconfInfo {
    type Error = ConversionError;

    fn try_from(info: PreconfInfo) -> Result<Self, Self::Error> {
        let ret = RundlerPreconfInfo {
            tx_hash: from_bytes(&info.tx_hash)?,
        };
        Ok(ret)
    }
}

impl From<&RundlerDAGasData> for DaGasData {
    fn from(data: &RundlerDAGasData) -> Self {
        match data {
            RundlerDAGasData::Empty => DaGasData {
                data: Some(da_gas_data::Data::Empty(EmptyGasData {})),
            },
            RundlerDAGasData::Nitro(data) => DaGasData {
                data: Some(da_gas_data::Data::Nitro(NitroDaGasData {
                    units: data.units.to_proto_bytes(),
                })),
            },
            RundlerDAGasData::Bedrock(data) => DaGasData {
                data: Some(da_gas_data::Data::Bedrock(BedrockDaGasData {
                    units: data.units.to_proto_bytes(),
                })),
            },
        }
    }
}

impl TryFrom<DaGasData> for RundlerDAGasData {
    type Error = ConversionError;

    fn try_from(data: DaGasData) -> Result<Self, Self::Error> {
        let ret = match data.data {
            Some(da_gas_data::Data::Empty(_)) => RundlerDAGasData::Empty,
            Some(da_gas_data::Data::Nitro(NitroDaGasData { units })) => {
                RundlerDAGasData::Nitro(RundlerNitroDAGasData {
                    units: from_bytes(&units)?,
                })
            }
            Some(da_gas_data::Data::Bedrock(BedrockDaGasData { units })) => {
                RundlerDAGasData::Bedrock(RundlerBedrockDAGasData {
                    units: from_bytes(&units)?,
                })
            }
            None => RundlerDAGasData::Empty,
        };

        Ok(ret)
    }
}

pub const MISSING_USER_OP_ERR_STR: &str = "Mempool op should contain user operation";
impl TryUoFromProto<MempoolOp> for PoolOperation {
    fn try_uo_from_proto(op: MempoolOp, chain_spec: &ChainSpec) -> Result<Self, ConversionError> {
        let uo = UserOperationVariant::try_uo_from_proto(
            op.uo.context(MISSING_USER_OP_ERR_STR)?,
            chain_spec,
        )?;

        let entry_point = from_bytes(&op.entry_point)?;

        let aggregator: Option<Address> = if op.aggregator.is_empty() {
            None
        } else {
            Some(from_bytes(&op.aggregator)?)
        };

        let valid_time_range = ValidTimeRange::new(op.valid_after.into(), op.valid_until.into());

        let expected_code_hash = B256::from_slice(&op.expected_code_hash);
        let sim_block_hash = B256::from_slice(&op.sim_block_hash);
        let filter_id = if op.filter_id.is_empty() {
            None
        } else {
            Some(op.filter_id)
        };

        Ok(PoolOperation {
            uo,
            entry_point,
            aggregator,
            valid_time_range,
            expected_code_hash,
            sim_block_hash,
            sim_block_number: 0,
            account_is_staked: op.account_is_staked,
            entity_infos: EntityInfos::default(),
            da_gas_data: op
                .da_gas_data
                .context("DA gas data should be set")?
                .try_into()?,
            filter_id,
            perms: op
                .permissions
                .context("Permissions should be set")?
                .try_into()?,
            sender_is_7702: op.sender_is_7702,
        })
    }
}

impl TryFrom<NewHead> for PoolNewHead {
    type Error = ConversionError;

    fn try_from(new_head: NewHead) -> Result<Self, Self::Error> {
        Ok(Self {
            block_hash: from_bytes(&new_head.block_hash)?,
            block_number: new_head.block_number,
            address_updates: new_head
                .address_updates
                .into_iter()
                .map(PoolAddressUpdate::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl From<PoolNewHead> for NewHead {
    fn from(head: PoolNewHead) -> Self {
        Self {
            block_hash: head.block_hash.to_proto_bytes(),
            block_number: head.block_number,
            address_updates: head
                .address_updates
                .into_iter()
                .map(AddressUpdate::from)
                .collect(),
        }
    }
}

impl TryFrom<AddressUpdate> for PoolAddressUpdate {
    type Error = ConversionError;

    fn try_from(update: AddressUpdate) -> Result<Self, Self::Error> {
        Ok(Self {
            address: from_bytes(&update.address)?,
            nonce: update.nonce,
            balance: from_bytes(&update.balance)?,
            mined_tx_hashes: update
                .mined_tx_hashes
                .into_iter()
                .map(|h| from_bytes(&h))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl From<PoolAddressUpdate> for AddressUpdate {
    fn from(update: PoolAddressUpdate) -> Self {
        Self {
            address: update.address.to_proto_bytes(),
            nonce: update.nonce,
            balance: update.balance.to_proto_bytes(),
            mined_tx_hashes: update
                .mined_tx_hashes
                .into_iter()
                .map(|h| h.to_proto_bytes())
                .collect(),
        }
    }
}

impl TryFrom<PaymasterBalance> for PoolPaymasterMetadata {
    type Error = ConversionError;

    fn try_from(paymaster_balance: PaymasterBalance) -> Result<Self, Self::Error> {
        Ok(Self {
            address: from_bytes(&paymaster_balance.address)?,
            confirmed_balance: from_bytes(&paymaster_balance.confirmed_balance)?,
            pending_balance: from_bytes(&paymaster_balance.pending_balance)?,
        })
    }
}

impl From<PoolPaymasterMetadata> for PaymasterBalance {
    fn from(paymaster_metadata: PoolPaymasterMetadata) -> Self {
        Self {
            address: paymaster_metadata.address.to_vec(),
            confirmed_balance: paymaster_metadata.confirmed_balance.to_proto_bytes(),
            pending_balance: paymaster_metadata.pending_balance.to_proto_bytes(),
        }
    }
}

impl TryFrom<UserOperationPermissions> for RundlerUserOperationPermissions {
    type Error = ConversionError;

    fn try_from(permissions: UserOperationPermissions) -> Result<Self, Self::Error> {
        Ok(Self {
            trusted: permissions.trusted,
            max_allowed_in_pool_for_sender: permissions
                .max_allowed_in_pool_for_sender
                .map(|c| c as usize),
            underpriced_accept_pct: permissions.underpriced_accept_pct,
            underpriced_bundle_pct: permissions.underpriced_bundle_pct,
            bundler_sponsorship: permissions
                .bundler_sponsorship
                .map(|s| s.try_into())
                .transpose()?,
            eip7702_disabled: permissions.eip7702_disabled,
        })
    }
}

impl From<RundlerUserOperationPermissions> for UserOperationPermissions {
    fn from(permissions: RundlerUserOperationPermissions) -> Self {
        Self {
            trusted: permissions.trusted,
            max_allowed_in_pool_for_sender: permissions
                .max_allowed_in_pool_for_sender
                .map(|c| c as u64),
            underpriced_accept_pct: permissions.underpriced_accept_pct,
            underpriced_bundle_pct: permissions.underpriced_bundle_pct,
            bundler_sponsorship: permissions.bundler_sponsorship.map(|s| s.into()),
            eip7702_disabled: permissions.eip7702_disabled,
        }
    }
}

impl TryFrom<BundlerSponsorship> for RundlerBundlerSponsorship {
    type Error = ConversionError;

    fn try_from(sponsorship: BundlerSponsorship) -> Result<Self, Self::Error> {
        Ok(Self {
            max_cost: from_bytes(&sponsorship.max_cost)?,
            valid_until: sponsorship.valid_until,
        })
    }
}

impl From<RundlerBundlerSponsorship> for BundlerSponsorship {
    fn from(sponsorship: RundlerBundlerSponsorship) -> Self {
        Self {
            max_cost: sponsorship.max_cost.to_proto_bytes(),
            valid_until: sponsorship.valid_until,
        }
    }
}

impl From<RundlerPoolOperationSummary> for PoolOperationSummary {
    fn from(summary: RundlerPoolOperationSummary) -> Self {
        Self {
            hash: summary.hash.to_proto_bytes(),
            entry_point: summary.entry_point.to_proto_bytes(),
            sender: summary.sender.to_proto_bytes(),
            sim_block_number: summary.sim_block_number,
        }
    }
}

impl TryFrom<PoolOperationSummary> for RundlerPoolOperationSummary {
    type Error = ConversionError;

    fn try_from(summary: PoolOperationSummary) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: from_bytes(&summary.hash)?,
            entry_point: from_bytes(&summary.entry_point)?,
            sender: from_bytes(&summary.sender)?,
            sim_block_number: summary.sim_block_number,
        })
    }
}

impl From<RundlerEntryPointVersion> for EntryPointVersion {
    fn from(version: RundlerEntryPointVersion) -> Self {
        match version {
            RundlerEntryPointVersion::V0_6 => EntryPointVersion::V06,
            RundlerEntryPointVersion::V0_7 => EntryPointVersion::V07,
            RundlerEntryPointVersion::V0_8 => EntryPointVersion::V08,
            RundlerEntryPointVersion::V0_9 => EntryPointVersion::V09,
        }
    }
}

impl TryFrom<EntryPointVersion> for RundlerEntryPointVersion {
    type Error = ConversionError;

    fn try_from(version: EntryPointVersion) -> Result<Self, Self::Error> {
        match version {
            EntryPointVersion::V06 => Ok(RundlerEntryPointVersion::V0_6),
            EntryPointVersion::V07 => Ok(RundlerEntryPointVersion::V0_7),
            EntryPointVersion::V08 => Ok(RundlerEntryPointVersion::V0_8),
            EntryPointVersion::V09 => Ok(RundlerEntryPointVersion::V0_9),
            EntryPointVersion::Unspecified => {
                Err(ConversionError::InvalidEnumValue(version as i32))
            }
        }
    }
}
