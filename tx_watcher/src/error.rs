//! Error types for the transaction watcher

use thiserror::Error;

#[derive(Error, Debug)]
pub enum WatcherError {
    #[error("RPC error: {0}")]
    Rpc(#[from] alloy::transports::TransportError),

    #[error("Nonce manager error: {0}")]
    NonceManager(#[from] nonce_manager::NonceError),

    #[error("Store error: {0}")]
    Store(String),

    #[error("Subscription error: {0}")]
    Subscription(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, WatcherError>;
