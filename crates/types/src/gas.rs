use ethers::types::{transaction::eip2718::TypedTransaction, U256};
use rundler_utils::math;

/// Gas fees for a user operation or transaction
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GasFees {
    /// EIP-1559 max fee per gas
    pub max_fee_per_gas: U256,
    /// EIP-1559 max priority fee per gas
    pub max_priority_fee_per_gas: U256,
}

impl From<&TypedTransaction> for GasFees {
    fn from(tx: &TypedTransaction) -> Self {
        match tx {
            TypedTransaction::Eip1559(tx) => Self {
                max_fee_per_gas: tx.max_fee_per_gas.unwrap_or_default(),
                max_priority_fee_per_gas: tx.max_priority_fee_per_gas.unwrap_or_default(),
            },
            _ => Self::default(),
        }
    }
}

impl GasFees {
    /// Increase the gas fees by a percentage
    pub fn increase_by_percent(self, percent: u64) -> Self {
        Self {
            max_fee_per_gas: math::increase_by_percent(self.max_fee_per_gas, percent),
            max_priority_fee_per_gas: math::increase_by_percent(
                self.max_priority_fee_per_gas,
                percent,
            ),
        }
    }
}
