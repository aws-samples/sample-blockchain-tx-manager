//! Signer provider - manages multiple signing backends
//!
//! Routes signing requests to the appropriate backend based on address.
//! Supports per-request credentials for segregated accounts.

use super::config::{SignerBackend, SignerConfig};
use super::error::{SignerError, SignerResult};
use super::secrets_manager::SecretsManagerSigner;
use super::traits::{SignerInfo, TransactionSigner};
use crate::types::SignerCredentials;
use alloy::primitives::Address;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Provider that manages multiple signers and routes by address
pub struct SignerProvider {
    /// Configuration
    config: SignerConfig,
    /// Cached signers by address
    signers: RwLock<HashMap<Address, Arc<dyn TransactionSigner>>>,
    /// Secrets Manager signer (if configured)
    secrets_manager: Option<Arc<SecretsManagerSigner>>,
    /// Coinbase signer (if configured)
    #[cfg(feature = "coinbase")]
    coinbase_signer: Option<Arc<super::coinbase::CoinbaseSigner>>,
    /// Nitro Enclave config (if configured)
    #[cfg(feature = "nitro")]
    nitro_config: Option<super::config::NitroEnclaveConfig>,
    /// Execution-role credentials, used to build SigV4 identity proofs for the Nitro
    /// signing service. Resolved once so each signing request does not re-walk the
    /// provider chain.
    #[cfg(feature = "nitro")]
    aws_credentials: Option<Arc<dyn aws_credential_types::provider::ProvideCredentials>>,
}

impl SignerProvider {
    /// Create a new signer provider from configuration
    pub async fn new(config: SignerConfig) -> SignerResult<Self> {
        info!("Initializing SignerProvider");

        // Only initialize Secrets Manager if it's the default backend or explicitly needed
        // Skip if Nitro is the default to avoid parsing errors on Nitro secrets
        let secrets_manager = if let Some(ref secret_name) = config.secrets_manager_secret_name
            && config.default_backend == SignerBackend::SecretsManager
        {
            info!(secret_name = %secret_name, "Initializing Secrets Manager signer");
            match SecretsManagerSigner::new(secret_name.clone()).await {
                Ok(sm) => Some(Arc::new(sm)),
                Err(e) => {
                    // Log but don't fail - other backends may still work
                    tracing::warn!("Failed to initialize Secrets Manager: {}", e);
                    None
                }
            }
        } else {
            None
        };

        #[cfg(feature = "coinbase")]
        let coinbase_signer = if let Some(ref cb_config) = config.coinbase_config {
            info!("Initializing Coinbase signer");
            Some(Arc::new(
                super::coinbase::CoinbaseSigner::new(cb_config.clone()).await?,
            ))
        } else {
            None
        };

        #[cfg(feature = "nitro")]
        let nitro_config = config.nitro_config.clone();

        #[cfg(feature = "nitro")]
        let aws_credentials: Option<
            Arc<dyn aws_credential_types::provider::ProvideCredentials>,
        > = if nitro_config.is_some() {
            let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            match configured_nitro_auth_role(std::env::var("NITRO_AUTH_ROLE_ARN").ok()) {
                // A dedicated signing-client role was configured: assume it so the SigV4
                // identity proof carries that role's assumed-role ARN, which is what the
                // signing service's allowlist pins. Log the mode and the role ARN only —
                // never the resolved credentials.
                Some(role_arn) => {
                    info!(
                        auth_identity = "assumed_role",
                        role_arn = %role_arn,
                        "Nitro signing auth: assuming dedicated signing-client role for SigV4 identity proofs"
                    );
                    let provider = aws_config::sts::AssumeRoleProvider::builder(role_arn)
                        .configure(&sdk_config)
                        .session_name("tx-manager-nitro-auth")
                        .build()
                        .await;
                    Some(Arc::new(provider) as Arc<_>)
                }
                // No signing-client role configured: fall back to the execution role's own
                // credentials. This keeps the Nitro stack's own invoke Lambda and the local
                // tests working, where the execution role is already on the allowlist.
                None => {
                    info!(
                        auth_identity = "execution_role",
                        "Nitro signing auth: using default execution-role credentials for SigV4 identity proofs"
                    );
                    sdk_config
                        .credentials_provider()
                        .map(|provider| Arc::new(provider) as Arc<_>)
                }
            }
        } else {
            None
        };

        Ok(Self {
            config,
            signers: RwLock::new(HashMap::new()),
            secrets_manager,
            #[cfg(feature = "coinbase")]
            coinbase_signer,
            #[cfg(feature = "nitro")]
            nitro_config,
            #[cfg(feature = "nitro")]
            aws_credentials,
        })
    }

    /// Create from environment variables
    pub async fn from_env() -> SignerResult<Self> {
        Self::new(SignerConfig::from_env()).await
    }

    /// Build a Nitro signer for `address`.
    ///
    /// The signing service selects which wallet signs, so no secret id is sent; the
    /// configured id is passed through only as a label for logs and `SignerInfo`.
    #[cfg(feature = "nitro")]
    async fn build_nitro_signer(
        &self,
        address: Address,
    ) -> SignerResult<Arc<dyn TransactionSigner>> {
        let nitro_cfg = self
            .nitro_config
            .as_ref()
            .ok_or_else(|| SignerError::Config("Nitro Enclave not configured".to_string()))?;

        let config = super::nitro::NitroConfig::from_env(nitro_cfg.endpoint.clone())?;

        Ok(Arc::new(super::nitro::NitroSigner::with_credentials(
            address,
            &config,
            nitro_cfg.secret_id.clone(),
            self.aws_credentials.clone(),
        )?))
    }

    /// Get a signer for the given address
    ///
    /// Uses credentials from environment/config. For per-request credentials,
    /// use `get_signer_with_credentials()` instead.
    #[allow(dead_code)]
    pub async fn get_signer(&self, address: Address) -> SignerResult<Arc<dyn TransactionSigner>> {
        self.get_signer_with_credentials(address, None).await
    }

    /// Get a signer for the given address with optional per-request credentials
    ///
    /// # Arguments
    /// * `address` - The address to get a signer for
    /// * `credentials` - Optional per-request credentials for segregated accounts
    ///
    /// When credentials are provided:
    /// - For Coinbase: Uses the wallet secret from credentials instead of env config
    /// - For SecretsManager: Loads from the specified secret ARN
    pub async fn get_signer_with_credentials(
        &self,
        address: Address,
        credentials: Option<&SignerCredentials>,
    ) -> SignerResult<Arc<dyn TransactionSigner>> {
        // If credentials are provided, create a fresh signer (don't cache per-user signers)
        if let Some(creds) = credentials {
            return self.create_signer_from_credentials(address, creds).await;
        }

        // Check cache first (only for environment-based credentials)
        {
            let cache = self.signers.read().await;
            if let Some(signer) = cache.get(&address) {
                return Ok(signer.clone());
            }
        }

        // Determine backend and create signer
        let backend = self.config.backend_for_address(&address);
        debug!(?address, ?backend, "Creating signer for address");

        let signer: Arc<dyn TransactionSigner> = match backend {
            SignerBackend::SecretsManager => {
                let sm = self.secrets_manager.as_ref().ok_or_else(|| {
                    SignerError::Config("Secrets Manager not configured".to_string())
                })?;

                // Get the specific signer for this address from the SM backend
                sm.get_signer_for_address(address)?
            }

            #[cfg(feature = "coinbase")]
            SignerBackend::Coinbase => {
                let cb = self
                    .coinbase_signer
                    .as_ref()
                    .ok_or_else(|| SignerError::Config("Coinbase not configured".to_string()))?;

                // Verify Coinbase manages this address
                if !cb.has_address(address).await? {
                    return Err(SignerError::NotFound(format!(
                        "Coinbase wallet doesn't control {}",
                        address
                    )));
                }

                // Create address-specific signer (uses config credentials)
                Arc::new(super::coinbase::CoinbaseAddressSigner::new(
                    cb.clone(),
                    address,
                ))
            }

            #[cfg(feature = "nitro")]
            SignerBackend::NitroEnclave => self.build_nitro_signer(address).await?,

            #[allow(unreachable_patterns)]
            _ => {
                return Err(SignerError::Config(format!(
                    "Backend {:?} not available (feature not enabled)",
                    backend
                )));
            }
        };

        // Cache the signer
        {
            let mut cache = self.signers.write().await;
            cache.insert(address, signer.clone());
        }

        Ok(signer)
    }

    /// Create a signer from per-request credentials (segregated accounts)
    async fn create_signer_from_credentials(
        &self,
        address: Address,
        credentials: &SignerCredentials,
    ) -> SignerResult<Arc<dyn TransactionSigner>> {
        debug!(?address, backend = %credentials.backend, "Creating signer from per-request credentials");

        match credentials.backend.to_lowercase().as_str() {
            #[cfg(feature = "coinbase")]
            "coinbase" => {
                let cb = self.coinbase_signer.as_ref().ok_or_else(|| {
                    SignerError::Config("Coinbase not configured (API key required)".to_string())
                })?;

                // Create signer with per-request wallet credentials
                let signer = if let Some(ref secret_arn) = credentials.wallet_secret_arn {
                    // Load from Secrets Manager ARN
                    super::coinbase::CoinbaseAddressSigner::from_secrets_manager(
                        cb.clone(),
                        address,
                        secret_arn,
                    )
                    .await?
                } else {
                    #[cfg(debug_assertions)]
                    if let (Some(name), Some(secret)) =
                        (&credentials.wallet_secret_name, &credentials.wallet_secret)
                    {
                        // Use inline credentials (debug builds only)
                        let wallet_creds = super::coinbase::WalletCredentials {
                            wallet_secret_name: name.clone(),
                            wallet_secret: secret.clone(),
                        };
                        return Ok(Arc::new(
                            super::coinbase::CoinbaseAddressSigner::with_credentials(
                                cb.clone(),
                                address,
                                wallet_creds,
                            ),
                        ));
                    }
                    return Err(SignerError::Config(
                        "Coinbase credentials require wallet_secret_arn or (wallet_secret_name + wallet_secret)".to_string(),
                    ));
                };

                Ok(Arc::new(signer))
            }

            "secrets_manager" | "secretsmanager" => {
                // For per-request Secrets Manager, we'd need to load from a specific ARN
                // This is less common but supported for completeness
                Err(SignerError::Config(
                    "Per-request Secrets Manager credentials not yet supported".to_string(),
                ))
            }

            #[cfg(feature = "nitro")]
            "nitro" | "nitro_enclave" => {
                // Per-request credentials carry nothing Nitro-specific: the signing
                // service picks the wallet itself, so there is nothing here to override.
                Ok(self.build_nitro_signer(address).await?)
            }

            other => Err(SignerError::Config(format!(
                "Unknown signer backend: {}",
                other
            ))),
        }
    }

    /// Check if we have a signer for the given address
    #[allow(dead_code)]
    pub async fn has_signer(&self, address: Address) -> bool {
        // Check cache
        {
            let cache = self.signers.read().await;
            if cache.contains_key(&address) {
                return true;
            }
        }

        // Check backends
        let backend = self.config.backend_for_address(&address);
        match backend {
            SignerBackend::SecretsManager => self
                .secrets_manager
                .as_ref()
                .map(|sm| sm.has_address(address))
                .unwrap_or(false),
            #[cfg(feature = "coinbase")]
            SignerBackend::Coinbase => {
                if let Some(ref cb) = self.coinbase_signer {
                    cb.has_address(address).await.unwrap_or(false)
                } else {
                    false
                }
            }
            #[cfg(feature = "nitro")]
            SignerBackend::NitroEnclave => self.nitro_config.is_some(),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// List all available addresses
    #[allow(dead_code)]
    pub async fn list_addresses(&self) -> Vec<Address> {
        let mut addresses = Vec::new();

        // From Secrets Manager
        if let Some(ref sm) = self.secrets_manager {
            addresses.extend(sm.addresses());
        }

        // From Coinbase (if configured)
        #[cfg(feature = "coinbase")]
        {
            if let Some(ref cb) = self.coinbase_signer
                && let Ok(cb_addrs) = cb.list_addresses().await
            {
                addresses.extend(cb_addrs);
            }
        }

        addresses.sort();
        addresses.dedup();
        addresses
    }

    /// Get info about all available signers
    #[allow(dead_code)]
    pub async fn list_signers(&self) -> Vec<SignerInfo> {
        let addresses = self.list_addresses().await;
        let mut infos = Vec::new();

        for addr in addresses {
            if let Ok(signer) = self.get_signer(addr).await {
                infos.push(signer.info());
            }
        }

        infos
    }

    /// Perform health check on all backends
    #[allow(dead_code)]
    pub async fn health_check(&self) -> SignerResult<()> {
        // Check Secrets Manager
        if let Some(ref sm) = self.secrets_manager {
            sm.health_check().await?;
        }

        #[cfg(feature = "coinbase")]
        if let Some(ref cb) = self.coinbase_signer {
            cb.health_check().await?;
        }

        Ok(())
    }
}

/// Decide whether an explicit signing-client role is configured for Nitro SigV4 auth.
///
/// Returns the trimmed role ARN when `NITRO_AUTH_ROLE_ARN` is present and non-empty, or
/// `None` to fall back to the execution role's own credentials. Kept as a pure function
/// so the selection boundary is unit-tested without touching AWS or the environment.
#[cfg(feature = "nitro")]
fn configured_nitro_auth_role(raw: Option<String>) -> Option<String> {
    raw.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(all(test, feature = "nitro"))]
mod tests {
    use super::configured_nitro_auth_role;

    #[test]
    fn unset_selects_execution_role() {
        // No env var -> None -> caller keeps default execution-role credentials, which is
        // what keeps the Nitro stack's own invoke Lambda and the tests working.
        assert_eq!(configured_nitro_auth_role(None), None);
    }

    #[test]
    fn empty_or_whitespace_selects_execution_role() {
        // A blank value must not be treated as a role ARN; assuming "" would fail loudly
        // at runtime, so it falls back to the execution role instead.
        assert_eq!(configured_nitro_auth_role(Some(String::new())), None);
        assert_eq!(configured_nitro_auth_role(Some("   ".to_string())), None);
    }

    #[test]
    fn present_value_selects_assumed_role_and_is_trimmed() {
        assert_eq!(
            configured_nitro_auth_role(Some(
                "  arn:aws:iam::123456789012:role/nitro-signing-client  ".to_string()
            )),
            Some("arn:aws:iam::123456789012:role/nitro-signing-client".to_string())
        );
    }
}
