//! AWS Secrets Manager signing backend
//!
//! Retrieves private keys from Secrets Manager and creates local signers.

use super::error::{SignerError, SignerResult};
use super::traits::{SignerInfo, TransactionSigner};
use alloy::primitives::{Address, B256};
use alloy::signers::Signature;
use alloy::signers::{Signer, local::PrivateKeySigner};
use async_trait::async_trait;
use aws_sdk_secretsmanager::Client as SecretsClient;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Secret format in AWS Secrets Manager
/// Expected JSON: { "0xAddress1": "privateKey1", "0xAddress2": "privateKey2" }
#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct SecretKeys(HashMap<String, String>);

/// Individual signer wrapping a PrivateKeySigner
#[allow(dead_code)]
pub struct SecretsManagerAddressSigner {
    inner: PrivateKeySigner,
    address: Address,
    secret_name: String,
}

impl SecretsManagerAddressSigner {
    fn new(inner: PrivateKeySigner, secret_name: String) -> Self {
        let address = inner.address();
        Self {
            inner,
            address,
            secret_name,
        }
    }
}

#[async_trait]
impl TransactionSigner for SecretsManagerAddressSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            address: self.address,
            name: Some(format!("SM:{}", self.secret_name)),
            backend: "secrets_manager".to_string(),
            supports_batch: false,
        }
    }

    async fn sign_hash(&self, hash: B256) -> SignerResult<Signature> {
        self.inner
            .sign_hash(&hash)
            .await
            .map_err(|e| SignerError::Crypto(e.to_string()))
    }

    async fn health_check(&self) -> SignerResult<()> {
        // Local signer is always healthy
        Ok(())
    }
}

/// Secrets Manager signer that manages multiple addresses
pub struct SecretsManagerSigner {
    /// Secret name in AWS Secrets Manager
    secret_name: String,
    /// Loaded signers by address
    signers: HashMap<Address, Arc<SecretsManagerAddressSigner>>,
}

impl SecretsManagerSigner {
    /// Create a new Secrets Manager signer
    pub async fn new(secret_name: String) -> SignerResult<Self> {
        info!(secret_name = %secret_name, "Loading keys from Secrets Manager");

        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = SecretsClient::new(&aws_config);

        let secret = client
            .get_secret_value()
            .secret_id(&secret_name)
            .send()
            .await
            .map_err(|e| SignerError::Aws(format!("Failed to get secret: {}", e)))?;

        let secret_string = secret
            .secret_string()
            .ok_or_else(|| SignerError::Aws("Secret has no string value".to_string()))?;

        let keys: SecretKeys = serde_json::from_str(secret_string)
            .map_err(|e| SignerError::Aws(format!("Failed to parse secret JSON: {}", e)))?;

        let mut signers = HashMap::new();

        for (address_str, private_key) in keys.0 {
            let address: Address = address_str
                .parse()
                .map_err(|e| SignerError::Aws(format!("Invalid address {}: {}", address_str, e)))?;

            // Remove 0x prefix if present
            let key_hex = private_key.strip_prefix("0x").unwrap_or(&private_key);

            let signer: PrivateKeySigner = key_hex.parse().map_err(|e| {
                SignerError::Crypto(format!("Invalid private key for {}: {}", address, e))
            })?;

            // Verify the address matches
            if signer.address() != address {
                return Err(SignerError::Crypto(format!(
                    "Address mismatch: expected {}, derived {}",
                    address,
                    signer.address()
                )));
            }

            debug!(address = ?address, "Loaded signer from Secrets Manager");
            let wrapped = SecretsManagerAddressSigner::new(signer, secret_name.clone());
            signers.insert(address, Arc::new(wrapped));
        }

        info!(count = signers.len(), "Loaded signers from Secrets Manager");

        Ok(Self {
            secret_name,
            signers,
        })
    }

    /// Get a signer for a specific address
    pub fn get_signer_for_address(
        &self,
        address: Address,
    ) -> SignerResult<Arc<dyn TransactionSigner>> {
        self.signers
            .get(&address)
            .cloned()
            .map(|s| s as Arc<dyn TransactionSigner>)
            .ok_or_else(|| {
                SignerError::NotFound(format!(
                    "No key for {} in secret {}",
                    address, self.secret_name
                ))
            })
    }

    /// Check if this backend has a signer for the address
    #[allow(dead_code)]
    pub fn has_address(&self, address: Address) -> bool {
        self.signers.contains_key(&address)
    }

    /// List all addresses managed by this backend
    #[allow(dead_code)]
    pub fn addresses(&self) -> Vec<Address> {
        self.signers.keys().cloned().collect()
    }

    /// Health check - verify we can still access the secret
    #[allow(dead_code)]
    pub async fn health_check(&self) -> SignerResult<()> {
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = SecretsClient::new(&aws_config);

        client
            .describe_secret()
            .secret_id(&self.secret_name)
            .send()
            .await
            .map_err(|e| SignerError::Aws(format!("Health check failed: {}", e)))?;

        Ok(())
    }
}

// Implement TransactionSigner for the multi-address manager (uses first address)
#[async_trait]
impl TransactionSigner for SecretsManagerSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            address: self.signers.keys().next().cloned().unwrap_or(Address::ZERO),
            name: Some(format!("SM:{}", self.secret_name)),
            backend: "secrets_manager".to_string(),
            supports_batch: false,
        }
    }

    async fn sign_hash(&self, _hash: B256) -> SignerResult<Signature> {
        Err(SignerError::Config(
            "Use get_signer_for_address() to get a specific signer".to_string(),
        ))
    }
}
