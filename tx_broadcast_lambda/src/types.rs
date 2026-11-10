//! Request and response types for the Lambda function

use alloy::primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};

/// Per-request replacement preferences. Every optional value is resolved against
/// deployment defaults and bounded by deployment hard maxima before nonce reservation.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacementPolicyRequest {
    pub bump_every_blocks: Option<u64>,
    pub max_bumps: Option<u32>,
    pub on_exhaust: Option<nonce_manager::ExhaustionAction>,
    pub max_fee_per_gas_wei: Option<U256>,
    pub max_total_fee_wei: Option<U256>,
}

/// Transaction request from direct invocation or SQS
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxRequest {
    /// Sender wallet address
    pub from: Address,

    /// Recipient address
    pub to: Address,

    /// Value to send (in wei)
    #[serde(default)]
    pub value: U256,

    /// Transaction data (for contract calls)
    #[serde(default)]
    pub data: Bytes,

    /// Gas limit (optional, will estimate if not provided)
    pub gas_limit: Option<u64>,

    /// Max fee per gas (EIP-1559)
    pub max_fee_per_gas: Option<U256>,

    /// Max priority fee per gas (EIP-1559)
    pub max_priority_fee_per_gas: Option<U256>,

    /// Legacy gas price (if not using EIP-1559)
    #[allow(dead_code)]
    pub gas_price: Option<U256>,

    /// Chain ID (defaults to config)
    pub chain_id: Option<u64>,

    /// Idempotency key (optional, for deduplication)
    pub idempotency_key: Option<String>,

    /// Optional live fee tier. Defaults to `standard` when fees are estimated.
    #[serde(default)]
    pub fee_speed: Option<nonce_manager::FeeSpeed>,

    /// Immutable same-nonce replacement policy. Omitted fields use deployment defaults.
    #[serde(default)]
    pub replacement_policy: Option<ReplacementPolicyRequest>,

    /// Signer credentials for multi-tenant scenarios
    /// When provided, these override environment-based credentials
    #[serde(default)]
    pub signer_credentials: Option<SignerCredentials>,
}

/// Per-request signer credentials for multi-tenant scenarios
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct SignerCredentials {
    /// Signer backend to use (e.g., "coinbase", "nitro")
    pub backend: String,

    /// For Coinbase CDP: wallet secret name (kid in JWT)
    pub wallet_secret_name: Option<String>,

    /// For Coinbase CDP: wallet secret (PEM format)
    /// Only available in debug builds for local development
    #[cfg(debug_assertions)]
    pub wallet_secret: Option<String>,

    /// For Coinbase CDP: Secrets Manager ARN containing wallet secret
    /// Preferred over inline wallet_secret for security
    pub wallet_secret_arn: Option<String>,
    //
    // There is deliberately no per-request Nitro secret id. The Nitro signing service
    // selects the wallet from its own configuration, because the instance role can read
    // every secret in the namespace — a caller-chosen id would let any authorized caller
    // sign with any other wallet.
}

/// Transaction response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxResponse {
    /// Whether the transaction was accepted
    pub success: bool,

    /// Transaction hash (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<B256>,

    /// Nonce used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,

    /// Error message (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Error code for programmatic handling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,

    /// Whether the request can be retried
    #[serde(default)]
    pub retryable: bool,
}

impl TxResponse {
    pub fn success(tx_hash: B256, nonce: u64) -> Self {
        Self {
            success: true,
            tx_hash: Some(tx_hash),
            nonce: Some(nonce),
            error: None,
            error_code: None,
            retryable: false,
        }
    }

    pub fn error_with_code(message: String, code: &str, retryable: bool) -> Self {
        Self {
            success: false,
            tx_hash: None,
            nonce: None,
            error: Some(message),
            error_code: Some(code.to_string()),
            retryable,
        }
    }
}

/// Sign-hash request — signs a raw 32-byte hash or EIP-712 typed data
///
/// Three modes:
/// 1. Raw hash: provide `hash`
/// 2. Pre-computed EIP-712: provide `domainSeparator` + `structHash`
/// 3. Full EIP-712: provide `typedData` (standard EIP-712 object with types/primaryType/domain/message)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignHashRequest {
    /// Signer address (used to resolve the signing backend)
    pub from: Address,

    /// Raw 32-byte hash to sign
    #[serde(default)]
    pub hash: Option<B256>,

    /// EIP-712 domain separator (used with struct_hash)
    #[serde(default)]
    pub domain_separator: Option<B256>,

    /// EIP-712 struct hash (used with domain_separator)
    #[serde(default)]
    pub struct_hash: Option<B256>,

    /// Full EIP-712 typed data (standard format per https://eips.ethereum.org/EIPS/eip-712)
    #[serde(default)]
    pub typed_data: Option<crate::eip712::TypedData>,

    /// Signer credentials override
    #[serde(default)]
    pub signer_credentials: Option<SignerCredentials>,
}

/// Sign-hash response
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SignHashResponse {
    pub success: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub v: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// Error codes for client handling
#[allow(dead_code)]
pub mod error_codes {
    pub const NONCE_EXHAUSTED: &str = "NONCE_EXHAUSTED";
    pub const SIMULATION_FAILED: &str = "SIMULATION_FAILED";
    pub const BROADCAST_FAILED: &str = "BROADCAST_FAILED";
    pub const INSUFFICIENT_FUNDS: &str = "INSUFFICIENT_FUNDS";
    pub const GAS_ESTIMATION_FAILED: &str = "GAS_ESTIMATION_FAILED";
    pub const INVALID_REQUEST: &str = "INVALID_REQUEST";
    pub const SIGNER_ERROR: &str = "SIGNER_ERROR";
    pub const RPC_ERROR: &str = "RPC_ERROR";
}
