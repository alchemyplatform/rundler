use anyhow::Context;
use ethers::types::{Address, H256};

use super::mempool::{ExpectedStorageSlot, PoolOperation};
use crate::common::{
    protos::{
        op_pool::{Entity as ProtoEntity, MempoolOp, StorageSlot, UserOperation},
        to_le_bytes, ConversionError, ProtoBytes,
    },
    types::ValidTimeRange,
};

impl TryFrom<&PoolOperation> for MempoolOp {
    type Error = anyhow::Error;

    fn try_from(op: &PoolOperation) -> Result<Self, Self::Error> {
        Ok(MempoolOp {
            uo: Some(UserOperation::from(&op.uo)),
            aggregator: op.aggregator.map_or(vec![], |a| a.as_bytes().to_vec()),
            valid_after: op.valid_time_range.valid_after.seconds_since_epoch(),
            valid_until: op.valid_time_range.valid_until.seconds_since_epoch(),
            expected_code_hash: op.expected_code_hash.as_bytes().to_vec(),
            sim_block_hash: op.sim_block_hash.as_bytes().to_vec(),
            entities_needing_stake: op
                .entities_needing_stake
                .iter()
                .map(|e| ProtoEntity::from(*e).into())
                .collect(),
            expected_storage_slots: op.expected_storage_slots.iter().map(|s| s.into()).collect(),
            account_is_staked: op.account_is_staked,
        })
    }
}

pub const MISSING_USER_OP_ERR_STR: &str = "Mempool op should contain user operation";
impl TryFrom<MempoolOp> for PoolOperation {
    type Error = anyhow::Error;

    fn try_from(op: MempoolOp) -> Result<Self, Self::Error> {
        let uo = op.uo.context(MISSING_USER_OP_ERR_STR)?.try_into()?;

        let aggregator: Option<Address> = if op.aggregator.is_empty() {
            None
        } else {
            Some(ProtoBytes(&op.aggregator).try_into()?)
        };

        let valid_time_range = ValidTimeRange::new(op.valid_after.into(), op.valid_until.into());

        let expected_storage_slots = op
            .expected_storage_slots
            .into_iter()
            .map(|s| (&s).try_into())
            .collect::<Result<Vec<_>, _>>()?;

        let expected_code_hash = H256::from_slice(&op.expected_code_hash);
        let sim_block_hash = H256::from_slice(&op.sim_block_hash);
        let entities_needing_stake = op
            .entities_needing_stake
            .into_iter()
            .map(|e| {
                let pe = ProtoEntity::from_i32(e).ok_or(ConversionError::InvalidEntity(e))?;
                pe.try_into()
            })
            .collect::<Result<Vec<_>, ConversionError>>()?;

        Ok(PoolOperation {
            uo,
            aggregator,
            valid_time_range,
            expected_code_hash,
            entities_needing_stake,
            expected_storage_slots,
            sim_block_hash,
            account_is_staked: op.account_is_staked,
        })
    }
}

impl TryFrom<&StorageSlot> for ExpectedStorageSlot {
    type Error = anyhow::Error;

    fn try_from(ss: &StorageSlot) -> Result<Self, Self::Error> {
        let address = ProtoBytes(&ss.address).try_into()?;
        let slot = ProtoBytes(&ss.slot).try_into()?;
        let expected_value = if ss.value.is_empty() {
            None
        } else {
            Some(ProtoBytes(&ss.value).try_into()?)
        };

        Ok(ExpectedStorageSlot {
            address,
            slot,
            expected_value,
        })
    }
}

impl From<&ExpectedStorageSlot> for StorageSlot {
    fn from(ess: &ExpectedStorageSlot) -> Self {
        StorageSlot {
            address: ess.address.as_bytes().to_vec(),
            slot: to_le_bytes(ess.slot),
            value: ess.expected_value.map_or(vec![], to_le_bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use ethers::types::U256;

    use super::*;
    use crate::common::{contracts::shared_types, protos::op_pool, types::Timestamp};

    const TEST_ADDRESS_ARR: [u8; 20] = [
        0x11, 0xAB, 0xB0, 0x5d, 0x9A, 0xd3, 0x18, 0xbf, 0x65, 0x65, 0x26, 0x72, 0xB1, 0x3b, 0x1d,
        0xcb, 0x0E, 0x6D, 0x4a, 0x32,
    ];
    const TEST_ADDRESS_STR: &str = "0x11aBB05d9Ad318bf65652672B13b1dcB0E6D4a32";

    #[test]
    fn test_mempool_op_to_pool_op() {
        let now_secs = Timestamp::now().seconds_since_epoch();

        let mempool_op = MempoolOp {
            uo: Some(op_pool::UserOperation {
                sender: TEST_ADDRESS_ARR.to_vec(),
                nonce: vec![0; 32],
                call_gas_limit: vec![0; 32],
                verification_gas_limit: vec![0; 32],
                pre_verification_gas: vec![0; 32],
                max_fee_per_gas: vec![0; 32],
                max_priority_fee_per_gas: vec![0; 32],
                ..Default::default()
            }),
            aggregator: TEST_ADDRESS_ARR.to_vec(),
            valid_after: now_secs,
            valid_until: now_secs,
            expected_code_hash: vec![0; 32],
            sim_block_hash: vec![0; 32],
            entities_needing_stake: vec![],
            expected_storage_slots: vec![op_pool::StorageSlot {
                address: TEST_ADDRESS_ARR.to_vec(),
                slot: vec![0; 32],
                value: vec![0; 32],
            }],
            account_is_staked: false,
        };

        let pool_op: PoolOperation = mempool_op.try_into().unwrap();

        assert_eq!(pool_op.uo.sender, TEST_ADDRESS_STR.parse().unwrap());
        assert_eq!(pool_op.aggregator, Some(TEST_ADDRESS_STR.parse().unwrap()));
        assert_eq!(pool_op.expected_code_hash, H256::zero());
        assert_eq!(
            pool_op.expected_storage_slots[0],
            ExpectedStorageSlot {
                address: TEST_ADDRESS_STR.parse().unwrap(),
                slot: U256::zero(),
                expected_value: Some(U256::zero()),
            }
        );
    }

    #[test]
    fn test_pool_op_to_mempool_op() {
        let now = Timestamp::now();
        let expected_ss = ExpectedStorageSlot {
            address: TEST_ADDRESS_STR.parse().unwrap(),
            slot: 1234.into(),
            expected_value: Some(12345.into()),
        };
        let pool_op = PoolOperation {
            uo: shared_types::UserOperation {
                ..Default::default()
            },
            aggregator: Some(TEST_ADDRESS_STR.parse().unwrap()),
            valid_time_range: ValidTimeRange::new(now, now),
            expected_code_hash: H256::random(),
            entities_needing_stake: vec![],
            sim_block_hash: H256::random(),
            expected_storage_slots: vec![ExpectedStorageSlot {
                address: TEST_ADDRESS_STR.parse().unwrap(),
                slot: 1234.into(),
                expected_value: Some(12345.into()),
            }],
            account_is_staked: false,
        };

        let mempool_op: MempoolOp = (&pool_op).try_into().unwrap();

        assert_eq!(
            mempool_op.uo,
            Some(op_pool::UserOperation {
                sender: vec![0; 20],
                nonce: vec![0; 32],
                call_gas_limit: vec![0; 32],
                verification_gas_limit: vec![0; 32],
                pre_verification_gas: vec![0; 32],
                max_fee_per_gas: vec![0; 32],
                max_priority_fee_per_gas: vec![0; 32],
                ..Default::default()
            })
        );
        assert_eq!(mempool_op.aggregator, TEST_ADDRESS_ARR.to_vec());
        assert_eq!(mempool_op.valid_after, now.seconds_since_epoch());
        assert_eq!(mempool_op.valid_until, now.seconds_since_epoch());
        assert_eq!(
            mempool_op.expected_storage_slots[0],
            (&expected_ss).try_into().unwrap()
        );
    }

    #[test]
    fn test_storage_slot_from_expected_storage_slot() {
        let ess_w_ev = ExpectedStorageSlot {
            address: Address::random(),
            slot: 1234.into(),
            expected_value: Some(12345.into()),
        };

        let ss: StorageSlot = (&ess_w_ev).into();

        assert_eq!(ss.address, ess_w_ev.address.as_bytes().to_vec());
        assert_eq!(ss.slot[0..4], [210, 4, 0, 0]);
        assert_eq!(ss.value[0..4], [57, 48, 0, 0]);

        let ess_wo_ev = ExpectedStorageSlot {
            address: Address::random(),
            slot: 1234.into(),
            expected_value: None,
        };

        let ss: StorageSlot = (&ess_wo_ev).into();
        assert_eq!(ss.value, Vec::<u8>::new());
    }

    #[test]
    fn test_expected_storage_slot_to_storage_slot() {
        let mut slot_bytes: [u8; 32] = [0; 32];
        U256::from(1234).to_little_endian(&mut slot_bytes);
        let slot_vec = slot_bytes.to_vec();

        let mut value_bytes: [u8; 32] = [0; 32];
        U256::from(12345).to_little_endian(&mut value_bytes);
        let value_vec = value_bytes.to_vec();

        let mut ss = StorageSlot {
            address: TEST_ADDRESS_ARR.into(),
            slot: slot_vec,
            value: value_vec,
        };

        let ess: ExpectedStorageSlot = (&ss).try_into().unwrap();

        assert_eq!(ess.address, TEST_ADDRESS_STR.parse().unwrap());
        assert_eq!(ess.slot, 1234.into());
        assert_eq!(ess.expected_value, Some(12345.into()));

        ss.value = vec![];
        let ess: ExpectedStorageSlot = (&ss).try_into().unwrap();

        assert_eq!(ess.address, TEST_ADDRESS_STR.parse().unwrap());
        assert_eq!(ess.slot, 1234.into());
        assert_eq!(ess.expected_value, None);
    }
}
