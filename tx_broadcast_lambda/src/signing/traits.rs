//! Core signing traits
//!
//! Defines the interface that all signing backends must implement.

use super::error::SignerResult;
use alloy::primitives::{Address, B256};
use alloy::signers::Signature;
use async_trait::async_trait;

/// Information about a signer
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SignerInfo {
    /// The Ethereum address this signer controls
    pub address: Address,
    /// Human-readable name/identifier for this signer
    pub name: Option<String>,
    /// The backend type (e.g., "secrets_manager", "coinbase", "nitro_enclave")
    pub backend: String,
    /// Whether this signer supports batch operations
    pub supports_batch: bool,
}

/// Core trait for transaction signing
///
/// All signing backends must implement this trait. The trait is designed to be
/// async-first since most backends involve network calls (AWS APIs, external services).
///
/// # Implementation Notes
///
/// - `sign_hash` is the primary method - it signs a 32-byte hash (typically a transaction hash)
/// - `sign_message` is for EIP-191 personal message signing
/// - `sign_typed_data` is for EIP-712 typed data signing
/// - Implementations should handle retries internally for transient failures
#[async_trait]
#[allow(dead_code)]
pub trait TransactionSigner: Send + Sync {
    /// Get information about this signer
    fn info(&self) -> SignerInfo;

    /// Get the Ethereum address for this signer
    fn address(&self) -> Address {
        self.info().address
    }

    /// Sign a 32-byte hash (e.g., transaction hash, message hash)
    ///
    /// This is the core signing operation. For transactions, the hash is typically
    /// computed from the RLP-encoded transaction data.
    ///
    /// # Arguments
    /// * `hash` - The 32-byte hash to sign
    ///
    /// # Returns
    /// * `Signature` - The ECDSA signature (r, s, v)
    async fn sign_hash(&self, hash: B256) -> SignerResult<Signature>;

    /// Sign a personal message (EIP-191)
    ///
    /// The message is prefixed with "\x19Ethereum Signed Message:\n" + length
    /// before hashing and signing.
    ///
    /// Default implementation computes the EIP-191 hash and calls `sign_hash`.
    async fn sign_message(&self, message: &[u8]) -> SignerResult<Signature> {
        use alloy::primitives::keccak256;
        // EIP-191: "\x19Ethereum Signed Message:\n" + len + message
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut data = Vec::with_capacity(prefix.len() + message.len());
        data.extend_from_slice(prefix.as_bytes());
        data.extend_from_slice(message);
        let hash = keccak256(&data);
        self.sign_hash(hash).await
    }

    /// Sign typed data (EIP-712)
    ///
    /// # Arguments
    /// * `domain_separator` - The EIP-712 domain separator hash
    /// * `struct_hash` - The hash of the typed struct
    ///
    /// Default implementation computes the EIP-712 hash and calls `sign_hash`.
    async fn sign_typed_data(
        &self,
        domain_separator: B256,
        struct_hash: B256,
    ) -> SignerResult<Signature> {
        // EIP-712: keccak256("\x19\x01" || domainSeparator || structHash)
        use alloy::primitives::keccak256;
        let mut data = Vec::with_capacity(66);
        data.extend_from_slice(&[0x19, 0x01]);
        data.extend_from_slice(domain_separator.as_slice());
        data.extend_from_slice(struct_hash.as_slice());
        let hash = keccak256(&data);
        self.sign_hash(hash).await
    }

    /// Check if this signer is healthy/available
    ///
    /// Implementations should perform a lightweight check to verify the signing
    /// backend is accessible. This is useful for health checks and failover.
    async fn health_check(&self) -> SignerResult<()> {
        // Default: assume healthy
        Ok(())
    }
}

/// Extension trait for signers that support Alloy's wallet interface
///
/// This allows signers to be used directly with Alloy's provider system.
#[async_trait]
#[allow(dead_code)]
pub trait AlloyCompatibleSigner: TransactionSigner {
    /// Convert this signer into an Alloy-compatible wallet
    ///
    /// This creates a wrapper that implements Alloy's signing traits,
    /// allowing the signer to be used with `ProviderBuilder::wallet()`.
    fn into_alloy_wallet(self) -> AlloySignerWrapper<Self>
    where
        Self: Sized,
    {
        AlloySignerWrapper(self)
    }
}

// Blanket implementation - all TransactionSigners are Alloy-compatible
impl<T: TransactionSigner> AlloyCompatibleSigner for T {}

/// Wrapper to make TransactionSigner compatible with Alloy's signing traits
#[allow(dead_code)]
pub struct AlloySignerWrapper<S: TransactionSigner>(pub S);

impl<S: TransactionSigner> AlloySignerWrapper<S> {
    #[allow(dead_code)]
    pub fn inner(&self) -> &S {
        &self.0
    }
}

// Implement Alloy's Signer trait for the wrapper
#[async_trait]
impl<S: TransactionSigner + 'static> alloy::signers::Signer for AlloySignerWrapper<S> {
    async fn sign_hash(&self, hash: &B256) -> Result<Signature, alloy::signers::Error> {
        self.0
            .sign_hash(*hash)
            .await
            .map_err(alloy::signers::Error::other)
    }

    fn address(&self) -> Address {
        self.0.address()
    }

    fn chain_id(&self) -> Option<u64> {
        None // Chain ID is set at transaction level
    }

    fn set_chain_id(&mut self, _chain_id: Option<u64>) {
        // No-op - chain ID is set at transaction level
    }
}
