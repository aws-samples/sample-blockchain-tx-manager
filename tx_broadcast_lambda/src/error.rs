//! Error types for the Lambda function

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LambdaError {
    #[error("RPC error: {0}")]
    Rpc(#[from] alloy::transports::TransportError),

    #[error("Nonce manager error: {0}")]
    NonceManager(#[from] nonce_manager::NonceError),

    #[error("Signer error: {0}")]
    Signer(String),

    #[error("Simulation failed: {0}")]
    #[allow(dead_code)]
    SimulationFailed(String),

    #[error("Broadcast failed: {0}")]
    #[allow(dead_code)]
    BroadcastFailed(String),

    #[error("Gas estimation failed: {0}")]
    GasEstimationFailed(String),

    #[error("Insufficient funds: {0}")]
    #[allow(dead_code)]
    InsufficientFunds(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Unauthorized: {0}")]
    #[allow(dead_code)]
    Unauthorized(String),

    #[error("DynamoDB error: {0}")]
    #[allow(dead_code)]
    DynamoDb(String),

    #[error("AWS error: {0}")]
    Aws(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, LambdaError>;
