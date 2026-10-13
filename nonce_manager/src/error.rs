//! Error types for nonce management

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NonceError {
    /// DynamoDB failure. Carries a rendered message rather than the concrete SDK
    /// error type: each DynamoDB operation returns a distinct `SdkError<OpError>`,
    /// so there is no single generic error type to hold, and the crate never needs
    /// to match on a structured DynamoDB error above the storage layer (the storage
    /// layer inspects cancellation reasons itself and maps them to the precise
    /// variants below, e.g. `MaxPendingExceeded` / `WalletNotInitialized`).
    #[error("DynamoDB error: {0}")]
    Dynamo(String),

    #[error("Ethereum RPC error: {0}")]
    Rpc(#[from] alloy::transports::TransportError),

    #[error("Wallet not initialized: {0}")]
    WalletNotInitialized(String),

    #[error("Max pending transactions exceeded for wallet {wallet}: {count}/{max}")]
    MaxPendingExceeded {
        wallet: String,
        count: u64,
        max: u64,
    },

    #[error("Nonce gap detected at nonce {0}")]
    NonceGap(u64),

    #[error("Nonce sync error: local={local}, on_chain={on_chain}")]
    SyncDrift { local: u64, on_chain: u64 },

    #[error("Cannot release nonce {0}: not the last reserved")]
    CannotRelease(u64),

    #[error("Broadcast outcome is ambiguous for nonce {nonce}: {message}")]
    AmbiguousBroadcast { nonce: u64, message: String },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid signed transaction: {0}")]
    InvalidSignedTx(String),

    /// Startup configuration failure (e.g. the RPC endpoint secret is missing or malformed).
    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, NonceError>;
