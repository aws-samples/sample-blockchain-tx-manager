# Adding New Signer Backends

> [!NOTE]
> This is sample code from a source-only reference architecture, provided as-is under MIT-0 without warranty or support. It is not a production-ready deployment. See [Known Limitations and Customer Responsibilities](known-limitations.md).

This guide explains how to add new signing backends to the modular signer architecture.

## Architecture Overview

```
                         Request arrives
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        SignerProvider                           │
│  (Routes signing requests by address to appropriate backend)    │
└─────────────────────────────────────────────────────────────────┘
                              │
         ┌────────────┬───────┼───────┬───────────────┐
         ▼            ▼       ▼       ▼               ▼
┌──────────────┐ ┌────────┐ ┌────┐ ┌──────────┐ ┌─────────┐
│ NitroEnclave │ │Secrets │ │KMS │ │ Coinbase │ │Your New │
│  (default)   │ │Manager │ │    │ │   CDP    │ │ Backend │
└──────┬───────┘ └───┬────┘ └─┬──┘ └────┬─────┘ └────┬────┘
       │             │        │         │             │
       └─────────────┴────────┴─────────┴─────────────┘
                              │
                    TransactionSigner::sign_hash()
                              │
                              ▼
                   Unified broadcast flow:
                   build_unsigned_tx → sign_hash → encode → send_raw_transaction
```

All signers implement the `TransactionSigner` trait. The handler uses a single code path for all backends: it builds an unsigned EIP-1559 transaction, computes the signing hash, calls `sign_hash()` on whichever backend the `SignerProvider` resolved, encodes the signed transaction, and broadcasts it as a raw transaction.

The trait defines three signing methods:
- `sign_hash(B256)`: raw 32-byte hash signing (the only required method)
- `sign_message(&[u8])`: EIP-191 personal message (default impl delegates to `sign_hash`)
- `sign_typed_data(domain_separator, struct_hash)`: EIP-712 (default impl delegates to `sign_hash`)

Because `sign_message` and `sign_typed_data` have default implementations, **any backend that implements `sign_hash` automatically supports all three signing modes**, including full EIP-712 typed data via the `/sign-hash` API endpoint.

## Step-by-Step Guide

### 1. Add Feature Flag (Optional but Recommended)

In `tx_broadcast_lambda/Cargo.toml`, add a feature flag for your backend:

```toml
[features]
default = ["nitro"]
coinbase = ["dep:reqwest", "dep:jsonwebtoken", "dep:rand"]
nitro = ["dep:reqwest"]
your_backend = ["your-dependency"]  # Add your feature
```

### 2. Create the Backend Module

Create a new file `tx_broadcast_lambda/src/signing/your_backend.rs`:

```rust
//! Your Backend signing implementation

use super::error::{SignerError, SignerResult};
use super::traits::{SignerInfo, TransactionSigner};
use alloy::primitives::{Address, B256};
use alloy::signers::Signature;
use async_trait::async_trait;

pub struct YourBackendSigner {
    address: Address,
    // Add backend-specific fields (API clients, credentials, etc.)
}

impl YourBackendSigner {
    /// Create a new signer instance
    pub async fn new(address: Address, /* config params */) -> SignerResult<Self> {
        // Initialize your backend connection
        Ok(Self { address })
    }
}

#[async_trait]
impl TransactionSigner for YourBackendSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            address: self.address,
            name: Some("YourBackend".to_string()),
            backend: "your_backend".to_string(),
            supports_batch: false, // Set true if your backend supports batch signing
        }
    }

    async fn sign_hash(&self, hash: B256) -> SignerResult<Signature> {
        // Implement the actual signing logic:
        // 1. Call your backend's signing API
        // 2. Convert the response to Signature (r, s, v)
        // 3. Verify the signature (see below)
        // 4. Handle errors appropriately

        let sig = todo!("Call backend and parse signature");

        // IMPORTANT: Always verify the signature before returning.
        // This catches malformed responses, MITM attacks, and backend bugs.
        let recovered = sig.recover_address_from_prehash(&hash)
            .map_err(|e| SignerError::Crypto(format!("Signature recovery failed: {}", e)))?;
        if recovered != self.address {
            return Err(SignerError::Crypto(format!(
                "Signature verification failed: recovered {} but expected {}",
                recovered, self.address
            )));
        }

        Ok(sig)
    }

    async fn health_check(&self) -> SignerResult<()> {
        // Optional: verify backend connectivity
        Ok(())
    }
}
```

### 3. Register in Module

Update `tx_broadcast_lambda/src/signing/mod.rs`:

```rust
// Add conditional compilation
#[cfg(feature = "your_backend")]
mod your_backend;

#[cfg(feature = "your_backend")]
pub use your_backend::YourBackendSigner;
```

### 4. Add Backend Enum Variant

In `tx_broadcast_lambda/src/signing/config.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignerBackend {
    SecretsManager,
    #[cfg(feature = "coinbase")]
    Coinbase,
    #[cfg(feature = "nitro")]
    NitroEnclave,
    #[cfg(feature = "your_backend")]
    YourBackend,  // Add your variant
}
```

### 5. Add Configuration

In `SignerConfig`, add fields for your backend:

```rust
pub struct SignerConfig {
    // ... existing fields ...
    
    #[cfg(feature = "your_backend")]
    pub your_backend_config: Option<YourBackendConfig>,
}

#[cfg(feature = "your_backend")]
pub struct YourBackendConfig {
    pub api_key: String,
    pub endpoint: String,
    // etc.
}
```

Update `SignerConfig::from_env()` to load your config from environment variables.

### 6. Wire Up in Provider

In `tx_broadcast_lambda/src/signing/provider.rs`, add initialization and routing:

```rust
pub struct SignerProvider {
    // ... existing fields ...
    
    #[cfg(feature = "your_backend")]
    your_backend_signer: Option<Arc<YourBackendSigner>>,
}

impl SignerProvider {
    pub async fn new(config: SignerConfig) -> SignerResult<Self> {
        // ... existing initialization ...
        
        #[cfg(feature = "your_backend")]
        let your_backend_signer = if let Some(ref cfg) = config.your_backend_config {
            Some(Arc::new(YourBackendSigner::new(cfg).await?))
        } else {
            None
        };
        
        Ok(Self {
            // ... existing fields ...
            #[cfg(feature = "your_backend")]
            your_backend_signer,
        })
    }
    
    pub async fn get_signer(&self, address: Address) -> SignerResult<Arc<dyn TransactionSigner>> {
        // ... existing code ...
        
        match backend {
            // ... existing matches ...
            
            #[cfg(feature = "your_backend")]
            SignerBackend::YourBackend => {
                let signer = self.your_backend_signer.as_ref()
                    .ok_or_else(|| SignerError::Config("YourBackend not configured".into()))?;
                // Return or create address-specific signer
                signer.clone()
            }
        }
    }
}
```

## Signature Format

The `sign_hash` method must return a `Signature` with:
- `r`: 32-byte scalar
- `s`: 32-byte scalar  
- `v`: Recovery ID (0 or 1, or 27/28 for legacy)

Most external APIs return DER-encoded signatures that need conversion:

```rust
use alloy::signers::Signature;

fn der_to_signature(der: &[u8], recovery_id: u8) -> SignerResult<Signature> {
    // Parse DER format (common for KMS, HSMs)
    // Extract r and s values
    // Create Signature::new(r, s, v)
    todo!()
}
```

## Environment Variables

Document the environment variables your backend needs:

| Variable | Description | Example |
|----------|-------------|---------|
| `YOUR_BACKEND_API_KEY` | API key for authentication | `sk_live_...` |
| `YOUR_BACKEND_ENDPOINT` | API endpoint URL | `https://api.example.com` |

## Testing

1. Unit test your signer in isolation
2. Integration test with the `SignerProvider`
3. Test error handling and retries

```rust
#[tokio::test]
async fn test_your_backend_signing() {
    let signer = YourBackendSigner::new(...).await.unwrap();
    let hash = B256::random();
    let sig = signer.sign_hash(hash).await.unwrap();
    
    // Verify signature recovers to expected address
    let recovered = sig.recover_address_from_prehash(&hash).unwrap();
    assert_eq!(recovered, signer.address());
}
```

## Existing Backends Reference

| Backend | Status | Feature Flag | Description |
|---------|--------|--------------|-------------|
| Nitro Enclave | Complete | `nitro` (default) | AWS Nitro Enclave isolated signing |
| SecretsManager | Complete | (always available) | Private keys in AWS Secrets Manager |
| Coinbase | Complete | `coinbase` | Coinbase Developer Platform EVM Accounts |

### Nitro Enclave Configuration

The Nitro backend delegates signing to an isolated AWS Nitro Enclave via HTTP. Private keys are stored encrypted in Secrets Manager and decrypted inside the enclave using KMS cryptographic attestation.

**Architecture:**
```
Lambda → NLB → EC2 (http_server) → vsock → Enclave (signing_server)
                                              ↓
                                         KMS decrypt (attestation)
                                              ↓
                                         Sign hash
```

**Environment Variables:**

| Variable | Description | Example |
|----------|-------------|---------|
| `NITRO_ENDPOINT` | NLB endpoint for Nitro signing service | `https://nitro-nlb.internal:443` |
| `NITRO_SECRET_ID` | Secret ID the signing service was deployed with. A log/`SignerInfo` label only; see below. | `nitro-wallet/treasury` |
| `NITRO_CA_CERT_PATH` | Path to PEM CA cert for TLS validation | `/etc/pki/tls/certs/nitro-ca.pem` |
| `NITRO_SKIP_TLS_VERIFY` | Skip TLS verification (dev/test only) | `true` |

The client does not choose the wallet. `NITRO_SECRET_ID` is not sent with the request; the
signing service signs with the single wallet named in its own deploy-time configuration. A
caller-supplied id would let any authorized caller sign with any wallet the instance role can
read. Use one deployment per wallet.

**CDK Configuration:**

```typescript
new TxManagerStack(app, 'TxManager', {
  nitroEndpoint: 'https://nitro-nlb.internal:443',
  nitroSecretId: 'nitro-wallet/treasury',  // Label only; must match the service's own config
  nitroSecurityGroupId: 'sg-0abc123',  // Nitro instance SG, allows Lambda→NLB on 443
});
```

**Per-Request Credentials:** none. `signerCredentials` carries no Nitro fields, deliberately;
see the note above. A request can select the `nitro` backend but not a wallet within it.

**Security Notes:**
- Every request to the signing service is authenticated against an IAM allowlist; there is no
  unauthenticated mode. See
  [Authentication](nitro-enclave-deployment.md#authentication).
- Private keys never leave the enclave in plaintext
- KMS key policy restricts decryption to attested enclave code (PCR0 hash)
- Rebuild enclave → new PCR0 → redeploy with `--context pcr0=<new value>` (signing fails
  closed until you do)

**TLS Configuration:**

The NLB performs TCP passthrough; TLS terminates at the EC2 host's Docker container using a self-signed certificate. The Lambda's Rust client (reqwest/rustls) validates this certificate.

There are three TLS modes, from least to most secure:

| Mode | Config | Use Case |
|------|--------|----------|
| **Skip verification** | `NITRO_SKIP_TLS_VERIFY=true` | Dev/test only. Traffic is still encrypted but the cert is not validated. |
| **Self-signed with CA trust** | `NITRO_CA_CERT_PATH=/path/to/cert.pem` | Internal deployments. Generates a proper end-entity cert (not a CA cert) and provides it to the Lambda. |
| **ACM Private CA** | ACM cert on NLB, no env vars needed | Production. NLB terminates TLS with a cert issued by ACM Private CA. Lambda trusts it natively. |

**Self-signed certificate requirements (rustls):**

The Rust TLS library (rustls) is stricter than OpenSSL. Self-signed certificates must:
- Have `basicConstraints=critical,CA:FALSE` (not a CA cert)
- Include `subjectAltName` matching the NLB DNS name
- Use RSA 2048+ or ECDSA P-256/P-384

Example end-entity cert generation for the Nitro EC2 user_data:
```bash
openssl genrsa -out /etc/pki/tls/certs/localhost.key 4096
openssl req -new -x509 -key /etc/pki/tls/certs/localhost.key \
  -out /etc/pki/tls/certs/localhost.crt \
  -days 3650 -subj "/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "subjectAltName=DNS:localhost,DNS:*.elb.us-east-1.amazonaws.com"
cat /etc/pki/tls/certs/localhost.key >> /etc/pki/tls/certs/localhost.crt
```

A cert generated with `openssl req -x509` without `-addext "basicConstraints=critical,CA:FALSE"` will be rejected by rustls with `CaUsedAsEndEntity`.

To use the self-signed cert with the Lambda, bake it into the Docker image or load it from S3/Secrets Manager at startup, then set `NITRO_CA_CERT_PATH`.

**Networking:**

The tx-manager Lambda must be able to reach the Nitro NLB on port 443. When deploying into the same VPC as the Nitro stack, pass `nitroSecurityGroupId` to allow the Lambda's security group as an ingress source on the Nitro security group. Without this, the connection will time out.

**Deploying the Nitro Stack:**

The Nitro Enclave signing infrastructure is in `nitro_enclave_signer/`. Deploy it separately using the CDK in that directory, then provide the NLB endpoint and security group ID to this stack.

### Coinbase CDP Configuration

The Coinbase backend uses the CDP EVM Accounts API and supports two credential modes:

**Environment-Based Credentials** (default): All requests use the same wallet credentials, taken from environment variables when the provider is initialized. In release builds (including the Docker image CDK deploys) the only credential variables read are the `_ARN` pair, which carry Secrets Manager ARNs rather than PEM material, so no private key appears in the Lambda environment. All four variables must be set or the Coinbase backend is not initialized.

| Variable | Description |
|----------|-------------|
| `CDP_API_KEY_NAME` | CDP API key name (kid in JWT header) |
| `CDP_API_KEY_SECRET_ARN` | Secrets Manager ARN of the secret holding the CDP API private key (PEM format, ES256) |
| `CDP_WALLET_SECRET_NAME` | Wallet secret name (kid for wallet JWT) |
| `CDP_WALLET_SECRET_ARN` | Secrets Manager ARN of the secret holding the wallet secret private key (PEM format) |

The raw-PEM variants `CDP_API_KEY_SECRET` and `CDP_WALLET_SECRET` are read only in debug builds (`#[cfg(debug_assertions)]` in `tx_broadcast_lambda/src/signing/config.rs`) as a local-testing convenience. Release builds compile them out, so setting them on a deployed Lambda has no effect.

**Per-Request Credentials**: For segregated accounts, credentials can be passed in each request.

### Option 1: Direct Credentials in Request (Recommended for Segregated Accounts)

For segregated account deployments, credentials are passed directly in the request body:

```json
{
  "from": "0x...",
  "to": "0x...",
  "value": "1000000000000000000",
  "signerCredentials": {
    "backend": "coinbase",
    "walletSecretArn": "arn:aws:secretsmanager:us-east-1:123456789:secret:user-wallet-abc123"
  }
}
```

The `walletSecretArn` should point to a Secrets Manager secret containing:
```json
{
  "wallet_secret_name": "user-wallet-key-name",
  "wallet_secret": "<PEM-ENCODED-EC-PRIVATE-KEY>"
}
```

Alternatively, credentials can be passed inline (not recommended for production):
```json
{
  "signerCredentials": {
    "backend": "coinbase",
    "walletSecretName": "user-wallet-key-name",
    "walletSecret": "<PEM-ENCODED-EC-PRIVATE-KEY>"
  }
}
```

**Benefits of Segregated Accounts**:
- Per-customer key separation - funds are never pooled under one key; whether that satisfies a given regulatory regime is the adopter's determination
- Security isolation - Compromise of one key doesn't affect others
- Audit trail - Per-user transaction history
- Simplified accounting - Direct mapping of addresses to users

### Option 2: Environment-Based Credentials

For internal operations or testing, all requests use shared credentials from environment variables. No `signerCredentials` needed in requests.

**Credential Resolution Priority**:

1. Explicit `signerCredentials` in request body (Option 1)
2. Environment-based credentials (Option 2)

The Coinbase signer:
- Uses the `/v2/evm/accounts/{address}/sign` endpoint for hash signing
- Uses the `/v2/evm/accounts/{address}/sign/transaction` endpoint for transaction signing
- Generates ES256 JWTs for both API and wallet authentication
- Supports per-request wallet credentials for segregated accounts

## Common Patterns

### Caching
If your backend has high latency, consider caching signers:
```rust
signers: RwLock<HashMap<Address, Arc<dyn TransactionSigner>>>
```

### Retry Logic
For transient failures, use the `SignerError::is_retryable()` method:
```rust
if error.is_retryable() {
    // Implement exponential backoff
}
```

### Multi-Address Support
If your backend manages multiple addresses (like a wallet), implement address enumeration:
```rust
pub async fn list_addresses(&self) -> SignerResult<Vec<Address>>
```
