use ethers::providers::JsonRpcError;

/// Error enumeration for the Provider trait
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// JSON-RPC error
    #[error(transparent)]
    JsonRpcError(#[from] JsonRpcError),
    /// Contract Error
    #[error("Contract Error: {0}")]
    ContractError(String),
    /// Internal errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
