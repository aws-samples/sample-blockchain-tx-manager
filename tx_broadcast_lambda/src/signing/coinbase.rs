//! Coinbase Developer Platform (CDP) signing backend
//!
//! Signs transactions using Coinbase's EVM Account API.
//! Keys are generated and stored in Coinbase's Trusted Execution Environment (TEE).
//!
//! API Reference: https://docs.cdp.coinbase.com/api-reference/v2/rest-api/evm-accounts
//!
//! # Authentication
//!
//! CDP uses two layers of authentication:
//! - CDP Secret API Key: JWT signed with ES256, used for all API requests (shared across tenants)
//! - Wallet Secret: Additional JWT for sensitive operations (per-tenant in multi-tenant mode)
//!
//! # Multi-Tenant Support
//!
//! Two operational modes are supported:
//! - **Environment-based**: Single wallet secret from env vars for all requests
//! - **Per-request credentials**: Wallet secret passed per-request for segregated accounts
//!
//! # Endpoints Used
//!
//! - `GET /v2/evm/accounts` - List accounts
//! - `POST /v2/evm/accounts/{address}/sign` - Sign a hash
//! - `POST /v2/evm/accounts/{address}/sign/transaction` - Sign a transaction

use super::config::CoinbaseConfig;
use super::error::{SignerError, SignerResult};
use super::traits::{SignerInfo, TransactionSigner};
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::signers::Signature as PrimitiveSignature;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info};

const CDP_API_BASE: &str = "https://api.cdp.coinbase.com/platform";

/// Per-request wallet credentials for multi-tenant scenarios
#[derive(Debug, Clone)]
pub struct WalletCredentials {
    /// Wallet secret name (kid in JWT header)
    pub wallet_secret_name: String,
    /// Wallet secret private key (PEM format, ES256)
    pub wallet_secret: String,
}

impl WalletCredentials {
    /// Load wallet credentials from Secrets Manager
    pub async fn from_secrets_manager(secret_arn: &str) -> SignerResult<Self> {
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_secretsmanager::Client::new(&aws_config);

        let secret = client
            .get_secret_value()
            .secret_id(secret_arn)
            .send()
            .await
            .map_err(|e| SignerError::Aws(format!("Failed to get wallet secret: {}", e)))?;

        let secret_string = secret
            .secret_string()
            .ok_or_else(|| SignerError::Aws("Wallet secret has no string value".to_string()))?;

        // Expected format: { "wallet_secret_name": "...", "wallet_secret": "<PEM-ENCODED-EC-PRIVATE-KEY>" }
        #[derive(Deserialize)]
        struct WalletSecretJson {
            wallet_secret_name: String,
            wallet_secret: String,
        }

        let parsed: WalletSecretJson = serde_json::from_str(secret_string)
            .map_err(|e| SignerError::Aws(format!("Failed to parse wallet secret JSON: {}", e)))?;

        Ok(Self {
            wallet_secret_name: parsed.wallet_secret_name,
            wallet_secret: parsed.wallet_secret,
        })
    }
}

/// Coinbase Developer Platform signer
///
/// Uses Coinbase's EVM Account API for signing operations.
/// Keys are managed in Coinbase's TEE and never exposed.
///
/// Supports two modes:
/// - Environment-based: wallet credentials from config
/// - Per-request: wallet credentials passed per-request for segregated accounts
pub struct CoinbaseSigner {
    /// HTTP client for API requests
    client: Client,
    /// API configuration (API key is shared, wallet secret may be per-request)
    config: CoinbaseConfig,
    /// Cached addresses from the account (only populated for environment-based mode)
    addresses: Arc<RwLock<HashSet<Address>>>,
}

/// Response from list accounts endpoint
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListAccountsResponse {
    accounts: Vec<AccountInfo>,
    #[serde(default)]
    next_page_token: Option<String>,
}

/// Account info from CDP
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountInfo {
    address: String,
    #[serde(default)]
    name: Option<String>,
}

/// Request body for sign hash
#[derive(Debug, Serialize)]
struct SignHashRequest {
    hash: String,
}

/// Response from sign hash endpoint
#[derive(Debug, Deserialize)]
struct SignHashResponse {
    signature: String,
}

/// Request body for sign transaction
#[derive(Debug, Serialize)]
struct SignTransactionRequest {
    transaction: String,
}

/// Response from sign transaction endpoint
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignTransactionResponse {
    signed_transaction: String,
}

impl CoinbaseSigner {
    /// Create a new Coinbase signer
    ///
    /// # Arguments
    /// * `config` - CDP API configuration including API key and wallet secret
    pub async fn new(config: CoinbaseConfig) -> SignerResult<Self> {
        info!("Initializing Coinbase CDP signer");

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| SignerError::Config(format!("Failed to create HTTP client: {}", e)))?;

        let signer = Self {
            client,
            config,
            addresses: Arc::new(RwLock::new(HashSet::new())),
        };

        // Load available addresses
        signer.refresh_addresses().await?;

        Ok(signer)
    }

    /// Refresh the list of available addresses from CDP
    pub async fn refresh_addresses(&self) -> SignerResult<()> {
        let mut all_addresses = HashSet::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut url = format!("{}/v2/evm/accounts", CDP_API_BASE);
            if let Some(ref token) = page_token {
                url = format!("{}?pageToken={}", url, token);
            }

            let jwt = self.generate_api_jwt("GET", "/v2/evm/accounts")?;

            let response = self
                .client
                .get(&url)
                .header("Authorization", format!("Bearer {}", jwt))
                .send()
                .await
                .map_err(|e| SignerError::Network(format!("Failed to list accounts: {}", e)))?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(SignerError::ExternalApi(format!(
                    "CDP list accounts failed ({}): {}",
                    status, body
                )));
            }

            let data: ListAccountsResponse = response.json().await.map_err(|e| {
                SignerError::ExternalApi(format!("Failed to parse response: {}", e))
            })?;

            for account in data.accounts {
                if let Ok(addr) = account.address.parse::<Address>() {
                    all_addresses.insert(addr);
                    debug!(address = ?addr, name = ?account.name, "Found CDP account");
                }
            }

            page_token = data.next_page_token;
            if page_token.is_none() {
                break;
            }
        }

        info!(count = all_addresses.len(), "Loaded CDP accounts");

        let mut addresses = self.addresses.write().await;
        *addresses = all_addresses;

        Ok(())
    }

    /// Check if this signer controls the given address
    pub async fn has_address(&self, address: Address) -> SignerResult<bool> {
        let addresses = self.addresses.read().await;
        Ok(addresses.contains(&address))
    }

    /// List all addresses controlled by this signer
    pub async fn list_addresses(&self) -> SignerResult<Vec<Address>> {
        let addresses = self.addresses.read().await;
        Ok(addresses.iter().cloned().collect())
    }

    /// Sign a 32-byte hash using the CDP API
    ///
    /// # Arguments
    /// * `address` - The address to sign with
    /// * `hash` - The 32-byte hash to sign
    /// * `wallet_creds` - Optional per-request wallet credentials (for multi-tenant mode)
    pub async fn sign_hash_for_address(
        &self,
        address: Address,
        hash: B256,
        wallet_creds: Option<&WalletCredentials>,
    ) -> SignerResult<PrimitiveSignature> {
        let path = format!("/v2/evm/accounts/{}/sign", address);
        let url = format!("{}{}", CDP_API_BASE, path);

        let api_jwt = self.generate_api_jwt("POST", &path)?;

        // Use per-request credentials if provided, otherwise fall back to config
        let wallet_jwt = match wallet_creds {
            Some(creds) => self.generate_jwt(
                &creds.wallet_secret_name,
                &creds.wallet_secret,
                "POST",
                &path,
            )?,
            None => self.generate_wallet_jwt("POST", &path)?,
        };

        let request_body = SignHashRequest {
            hash: format!("0x{}", hex::encode(hash.as_slice())),
        };

        debug!(address = ?address, hash = ?hash, "Signing hash via CDP");

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_jwt))
            .header("X-Wallet-Auth", wallet_jwt)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| SignerError::Network(format!("CDP sign request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            if status.as_u16() == 429 {
                return Err(SignerError::RateLimited(body));
            } else if status.as_u16() == 401 || status.as_u16() == 403 {
                return Err(SignerError::Unauthorized(body));
            }

            return Err(SignerError::ExternalApi(format!(
                "CDP sign failed ({}): {}",
                status, body
            )));
        }

        let data: SignHashResponse = response.json().await.map_err(|e| {
            SignerError::ExternalApi(format!("Failed to parse sign response: {}", e))
        })?;

        // Parse the signature (0x-prefixed hex, 65 bytes: r[32] + s[32] + v[1])
        self.parse_signature(&data.signature)
    }

    /// Sign an RLP-encoded transaction using the CDP API
    ///
    /// The transaction must be an EIP-1559 dynamic fee transaction.
    ///
    /// # Arguments
    /// * `address` - The address to sign with
    /// * `rlp_encoded_tx` - The RLP-encoded unsigned transaction
    /// * `wallet_creds` - Optional per-request wallet credentials (for multi-tenant mode)
    #[allow(dead_code)]
    pub async fn sign_transaction(
        &self,
        address: Address,
        rlp_encoded_tx: &[u8],
        wallet_creds: Option<&WalletCredentials>,
    ) -> SignerResult<Bytes> {
        let path = format!("/v2/evm/accounts/{}/sign/transaction", address);
        let url = format!("{}{}", CDP_API_BASE, path);

        let api_jwt = self.generate_api_jwt("POST", &path)?;

        // Use per-request credentials if provided, otherwise fall back to config
        let wallet_jwt = match wallet_creds {
            Some(creds) => self.generate_jwt(
                &creds.wallet_secret_name,
                &creds.wallet_secret,
                "POST",
                &path,
            )?,
            None => self.generate_wallet_jwt("POST", &path)?,
        };

        let request_body = SignTransactionRequest {
            transaction: format!("0x{}", hex::encode(rlp_encoded_tx)),
        };

        debug!(address = ?address, "Signing transaction via CDP");

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_jwt))
            .header("X-Wallet-Auth", wallet_jwt)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| SignerError::Network(format!("CDP sign transaction failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            if status.as_u16() == 429 {
                return Err(SignerError::RateLimited(body));
            } else if status.as_u16() == 401 || status.as_u16() == 403 {
                return Err(SignerError::Unauthorized(body));
            }

            return Err(SignerError::ExternalApi(format!(
                "CDP sign transaction failed ({}): {}",
                status, body
            )));
        }

        let data: SignTransactionResponse = response
            .json()
            .await
            .map_err(|e| SignerError::ExternalApi(format!("Failed to parse response: {}", e)))?;

        // Parse the signed transaction
        let signed_tx = data
            .signed_transaction
            .strip_prefix("0x")
            .unwrap_or(&data.signed_transaction);

        let bytes = hex::decode(signed_tx)
            .map_err(|e| SignerError::Crypto(format!("Invalid signed transaction hex: {}", e)))?;

        Ok(Bytes::from(bytes))
    }

    /// Parse a 65-byte signature from hex string
    fn parse_signature(&self, sig_hex: &str) -> SignerResult<PrimitiveSignature> {
        let sig_hex = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| SignerError::Crypto(format!("Invalid signature hex: {}", e)))?;

        if sig_bytes.len() != 65 {
            return Err(SignerError::Crypto(format!(
                "Invalid signature length: expected 65, got {}",
                sig_bytes.len()
            )));
        }

        // Signature format: r (32 bytes) + s (32 bytes) + v (1 byte)
        let r = U256::from_be_slice(&sig_bytes[0..32]);
        let s = U256::from_be_slice(&sig_bytes[32..64]);
        let v = sig_bytes[64];

        // Normalize v: CDP returns 27/28, we need 0/1 for PrimitiveSignature
        let v_normalized = if v >= 27 { v - 27 } else { v };

        Ok(PrimitiveSignature::new(r, s, v_normalized != 0))
    }

    /// Generate JWT for API authentication (CDP Secret API Key)
    fn generate_api_jwt(&self, method: &str, path: &str) -> SignerResult<String> {
        self.generate_jwt(
            &self.config.api_key_name,
            &self.config.api_key_secret,
            method,
            path,
        )
    }

    /// Generate JWT for wallet authentication (Wallet Secret)
    fn generate_wallet_jwt(&self, method: &str, path: &str) -> SignerResult<String> {
        self.generate_jwt(
            &self.config.wallet_secret_name,
            &self.config.wallet_secret,
            method,
            path,
        )
    }

    /// Generate a JWT token for CDP authentication
    fn generate_jwt(
        &self,
        key_name: &str,
        key_secret: &str,
        method: &str,
        path: &str,
    ) -> SignerResult<String> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SignerError::Config(format!("System time error: {}", e)))?
            .as_secs();

        let uri = format!("{} api.cdp.coinbase.com{}", method, path);

        #[derive(Serialize)]
        struct Claims {
            sub: String,
            iss: String,
            nbf: u64,
            exp: u64,
            uri: String,
            nonce: String,
        }

        // Generate random nonce
        let nonce: String = (0..32)
            .map(|_| format!("{:02x}", rand::random::<u8>()))
            .collect();

        let claims = Claims {
            sub: key_name.to_string(),
            iss: "cdp".to_string(),
            nbf: now,
            exp: now + 120,
            uri,
            nonce,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key_name.to_string());
        header.typ = Some("JWT".to_string());

        let key = EncodingKey::from_ec_pem(key_secret.as_bytes())
            .map_err(|e| SignerError::Config(format!("Invalid EC private key: {}", e)))?;

        encode(&header, &claims, &key)
            .map_err(|e| SignerError::Config(format!("Failed to generate JWT: {}", e)))
    }
}

#[async_trait]
impl TransactionSigner for CoinbaseSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            address: Address::ZERO, // Multi-address signer
            name: Some("CDP".to_string()),
            backend: "coinbase".to_string(),
            supports_batch: false,
        }
    }

    async fn sign_hash(&self, _hash: B256) -> SignerResult<PrimitiveSignature> {
        // This method requires an address - use CoinbaseAddressSigner instead
        Err(SignerError::Config(
            "Use get_signer_for_address() to get an address-specific signer".to_string(),
        ))
    }

    async fn health_check(&self) -> SignerResult<()> {
        // Try to list accounts as a health check
        let url = format!("{}/v2/evm/accounts?pageSize=1", CDP_API_BASE);
        let jwt = self.generate_api_jwt("GET", "/v2/evm/accounts")?;

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", jwt))
            .send()
            .await
            .map_err(|e| SignerError::Network(format!("Health check failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(SignerError::ExternalApi(format!(
                "Health check failed: {}",
                response.status()
            )));
        }

        Ok(())
    }
}

/// Address-specific signer for Coinbase CDP
///
/// Wraps CoinbaseSigner for a specific address.
/// Supports both environment-based credentials and per-request credentials for segregated accounts.
pub struct CoinbaseAddressSigner {
    inner: Arc<CoinbaseSigner>,
    address: Address,
    /// Per-request wallet credentials (for segregated accounts)
    wallet_credentials: Option<WalletCredentials>,
}

impl CoinbaseAddressSigner {
    /// Create a new address-specific signer (environment-based credentials)
    pub fn new(inner: Arc<CoinbaseSigner>, address: Address) -> Self {
        Self {
            inner,
            address,
            wallet_credentials: None,
        }
    }

    /// Create a new address-specific signer with per-request credentials (segregated accounts)
    pub fn with_credentials(
        inner: Arc<CoinbaseSigner>,
        address: Address,
        credentials: WalletCredentials,
    ) -> Self {
        Self {
            inner,
            address,
            wallet_credentials: Some(credentials),
        }
    }

    /// Create from a Secrets Manager ARN containing wallet credentials
    pub async fn from_secrets_manager(
        inner: Arc<CoinbaseSigner>,
        address: Address,
        secret_arn: &str,
    ) -> SignerResult<Self> {
        let credentials = WalletCredentials::from_secrets_manager(secret_arn).await?;
        Ok(Self::with_credentials(inner, address, credentials))
    }
}

#[async_trait]
impl TransactionSigner for CoinbaseAddressSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            address: self.address,
            name: Some(format!("CDP:{}", self.address)),
            backend: "coinbase".to_string(),
            supports_batch: false,
        }
    }

    async fn sign_hash(&self, hash: B256) -> SignerResult<PrimitiveSignature> {
        self.inner
            .sign_hash_for_address(self.address, hash, self.wallet_credentials.as_ref())
            .await
    }

    async fn health_check(&self) -> SignerResult<()> {
        self.inner.health_check().await
    }
}
