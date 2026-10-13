//! Signing error types

use std::fmt;

/// Result type for signing operations
pub type SignerResult<T> = Result<T, SignerError>;

/// Errors that can occur during signing operations
#[derive(Debug)]
#[allow(dead_code)]
pub enum SignerError {
    /// Signer not found for the requested address
    NotFound(String),

    /// Configuration error
    Config(String),

    /// AWS service error (Secrets Manager)
    Aws(String),

    /// External API error (Coinbase, etc.)
    ExternalApi(String),

    /// Cryptographic error (invalid signature, key format)
    Crypto(String),

    /// Network/connectivity error
    Network(String),

    /// Rate limit exceeded
    RateLimited(String),

    /// Authentication/authorization error
    Unauthorized(String),

    /// The signing operation timed out
    Timeout(String),

    /// Backend-specific error
    Backend(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerError::NotFound(msg) => write!(f, "Signer not found: {}", msg),
            SignerError::Config(msg) => write!(f, "Configuration error: {}", msg),
            SignerError::Aws(msg) => write!(f, "AWS error: {}", msg),
            SignerError::ExternalApi(msg) => write!(f, "External API error: {}", msg),
            SignerError::Crypto(msg) => write!(f, "Cryptographic error: {}", msg),
            SignerError::Network(msg) => write!(f, "Network error: {}", msg),
            SignerError::RateLimited(msg) => write!(f, "Rate limited: {}", msg),
            SignerError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            SignerError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            SignerError::Backend(msg) => write!(f, "Backend error: {}", msg),
        }
    }
}

impl std::error::Error for SignerError {}

impl SignerError {
    /// Check if this error is retryable
    #[allow(dead_code)]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            SignerError::Network(_) | SignerError::RateLimited(_) | SignerError::Timeout(_)
        )
    }
}
