//! Signer configuration
//!
//! Supports multiple signing backends with flexible configuration.

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Signing backend type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignerBackend {
    /// AWS Secrets Manager (private keys stored as JSON)
    SecretsManager,
    /// Coinbase Developer Platform
    #[cfg(feature = "coinbase")]
    Coinbase,
    /// AWS Nitro Enclave
    #[cfg(feature = "nitro")]
    NitroEnclave,
}

impl Default for SignerBackend {
    fn default() -> Self {
        #[cfg(feature = "nitro")]
        return SignerBackend::NitroEnclave;
        #[cfg(not(feature = "nitro"))]
        return SignerBackend::SecretsManager;
    }
}

/// Nitro Enclave configuration
#[cfg(feature = "nitro")]
#[derive(Debug, Clone)]
pub struct NitroEnclaveConfig {
    /// HTTPS endpoint for the Nitro signing service
    pub endpoint: String,
    /// Secret ID of the wallet the signing service is deployed with.
    ///
    /// Used only as a label in logs and `SignerInfo`. The service selects the wallet from
    /// its own configuration and ignores anything the client sends, so this cannot be used
    /// to choose a wallet — run a second deployment for a second wallet.
    pub secret_id: String,
}

/// Mapping of an address to its signing backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerMapping {
    /// The Ethereum address
    pub address: Address,
    /// The backend to use for this address
    pub backend: SignerBackend,
    /// Backend-specific configuration
    #[serde(default)]
    pub config: HashMap<String, String>,
}

/// Overall signer configuration
#[derive(Debug, Clone)]
pub struct SignerConfig {
    /// Default backend for addresses not explicitly mapped
    pub default_backend: SignerBackend,

    /// Explicit address-to-backend mappings
    pub mappings: Vec<SignerMapping>,

    // Backend-specific configs
    /// AWS Secrets Manager secret name (for SecretsManager backend)
    pub secrets_manager_secret_name: Option<String>,

    /// Coinbase API configuration
    #[cfg(feature = "coinbase")]
    pub coinbase_config: Option<CoinbaseConfig>,

    /// Nitro Enclave configuration
    #[cfg(feature = "nitro")]
    pub nitro_config: Option<NitroEnclaveConfig>,
}

/// Coinbase Developer Platform configuration
#[cfg(feature = "coinbase")]
#[derive(Debug, Clone)]
pub struct CoinbaseConfig {
    /// CDP API key name (kid in JWT)
    pub api_key_name: String,
    /// CDP API private key (PEM format, ES256)
    pub api_key_secret: String,
    /// Wallet secret name (kid in JWT for wallet operations)
    pub wallet_secret_name: String,
    /// Wallet secret private key (PEM format, ES256)
    pub wallet_secret: String,
}

impl SignerConfig {
    /// Load configuration from environment variables
    ///
    /// Environment variables:
    /// - `SIGNER_BACKEND`: Default backend (`nitro`/`nitro_enclave`, `secrets_manager`/
    ///   `secretsmanager`, `coinbase`); unrecognised or absent falls back to the compiled
    ///   default (`nitro` when that feature is on)
    /// - `SECRETS_NAME`: AWS Secrets Manager secret name for the `secrets_manager` backend
    /// - `SIGNER_MAPPINGS`: JSON array of SignerMapping objects
    /// - `CDP_API_KEY_NAME` / `CDP_API_KEY_SECRET_ARN`: Coinbase API key name and the
    ///   Secrets Manager ARN of its PEM
    /// - `CDP_WALLET_SECRET_NAME` / `CDP_WALLET_SECRET_ARN`: Coinbase wallet secret name
    ///   and the Secrets Manager ARN of its PEM
    /// - `NITRO_ENDPOINT` / `NITRO_SECRET_ID`: Nitro signing service endpoint and wallet label
    pub fn from_env() -> Self {
        let default_backend = std::env::var("SIGNER_BACKEND")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "secrets_manager" | "secretsmanager" => Some(SignerBackend::SecretsManager),
                #[cfg(feature = "coinbase")]
                "coinbase" => Some(SignerBackend::Coinbase),
                #[cfg(feature = "nitro")]
                "nitro" | "nitro_enclave" => Some(SignerBackend::NitroEnclave),
                _ => None,
            })
            .unwrap_or_default();

        let mappings: Vec<SignerMapping> = std::env::var("SIGNER_MAPPINGS")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let secrets_manager_secret_name = std::env::var("SECRETS_NAME").ok();

        #[cfg(feature = "coinbase")]
        let coinbase_config = {
            let api_key_name = std::env::var("CDP_API_KEY_NAME").ok();
            // CDP_API_KEY_SECRET_ARN and CDP_WALLET_SECRET_ARN are the preferred variants:
            // they hold AWS Secrets Manager ARNs that CoinbaseSigner::new resolves at
            // initialization time, keeping raw PEM material out of Lambda env vars.
            // The plain CDP_API_KEY_SECRET / CDP_WALLET_SECRET fallbacks are gated to
            // debug builds only — raw PEM env vars must not be readable in production.
            let api_key_secret = std::env::var("CDP_API_KEY_SECRET_ARN").ok();
            #[cfg(debug_assertions)]
            let api_key_secret =
                api_key_secret.or_else(|| std::env::var("CDP_API_KEY_SECRET").ok());
            let wallet_secret_name = std::env::var("CDP_WALLET_SECRET_NAME").ok();
            let wallet_secret = std::env::var("CDP_WALLET_SECRET_ARN").ok();
            #[cfg(debug_assertions)]
            let wallet_secret = wallet_secret.or_else(|| std::env::var("CDP_WALLET_SECRET").ok());

            match (
                api_key_name,
                api_key_secret,
                wallet_secret_name,
                wallet_secret,
            ) {
                (Some(api_name), Some(api_secret), Some(wallet_name), Some(wallet_sec)) => {
                    Some(CoinbaseConfig {
                        api_key_name: api_name,
                        api_key_secret: api_secret,
                        wallet_secret_name: wallet_name,
                        wallet_secret: wallet_sec,
                    })
                }
                _ => None,
            }
        };

        #[cfg(feature = "nitro")]
        let nitro_config = {
            let endpoint = std::env::var("NITRO_ENDPOINT").ok();
            let secret_id = std::env::var("NITRO_SECRET_ID").ok();

            match (endpoint, secret_id) {
                (Some(ep), Some(secret)) => Some(NitroEnclaveConfig {
                    endpoint: ep,
                    secret_id: secret,
                }),
                _ => None,
            }
        };

        Self {
            default_backend,
            mappings,
            secrets_manager_secret_name,
            #[cfg(feature = "coinbase")]
            coinbase_config,
            #[cfg(feature = "nitro")]
            nitro_config,
        }
    }

    /// Get the backend for a specific address
    pub fn backend_for_address(&self, address: &Address) -> SignerBackend {
        self.mappings
            .iter()
            .find(|m| &m.address == address)
            .map(|m| m.backend.clone())
            .unwrap_or_else(|| self.default_backend.clone())
    }
}
