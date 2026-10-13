//! Modular transaction signing abstraction
//!
//! This module provides a trait-based signing interface that supports multiple backends:
//! - `SecretsManagerSigner`: Private keys stored in AWS Secrets Manager
//! - `CoinbaseSigner`: Coinbase Developer Platform API
//! - `NitroSigner`: AWS Nitro Enclave signing
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        SignerProvider                           │
//! │  (Manages multiple signers, routes by address)                  │
//! └─────────────────────────────────────────────────────────────────┘
//!                                  │
//!          ┌───────────────────────┼───────────────────────┐
//!          ▼                       ▼                       ▼
//! ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
//! │ SecretsManager  │   │ Coinbase Signer │   │  Nitro Signer   │
//! │    Signer       │   │                 │   │                 │
//! └─────────────────┘   └─────────────────┘   └─────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use signing::{SignerProvider, SignerConfig};
//!
//! // Configure signers
//! let config = SignerConfig::from_env();
//! let provider = SignerProvider::new(config).await?;
//!
//! // Get a signer for an address
//! let signer = provider.get_signer(address).await?;
//!
//! // Sign a transaction hash
//! let signature = signer.sign_hash(tx_hash).await?;
//! ```

mod config;
mod error;
mod provider;
mod traits;

// Backend implementations
mod secrets_manager;

#[cfg(feature = "coinbase")]
mod coinbase;

#[cfg(feature = "nitro")]
mod nitro;

#[cfg(feature = "nitro")]
mod nitro_auth;

// Re-exports for public API
#[allow(unused_imports)]
pub use config::{SignerBackend, SignerConfig, SignerMapping};
#[allow(unused_imports)]
pub use error::{SignerError, SignerResult};
pub use provider::SignerProvider;
#[allow(unused_imports)]
pub use traits::{AlloyCompatibleSigner, AlloySignerWrapper, SignerInfo, TransactionSigner};

// Backend re-exports
#[allow(unused_imports)]
pub use secrets_manager::SecretsManagerSigner;

#[cfg(feature = "coinbase")]
#[allow(unused_imports)]
pub use coinbase::{CoinbaseAddressSigner, CoinbaseSigner, WalletCredentials};

#[cfg(feature = "nitro")]
#[allow(unused_imports)]
pub use nitro::{NitroAuth, NitroConfig, NitroSigner};
