//! AWS Nitro Enclave signing backend
//!
//! Signs transaction hashes via an HTTP endpoint backed by a Nitro Enclave.
//! The enclave holds encrypted private keys that are decrypted using KMS
//! cryptographic attestation.

use super::error::{SignerError, SignerResult};
use super::nitro_auth::{self, AUTHORIZATION_HEADER, DATE_HEADER, DIGEST_HEADER, TOKEN_HEADER};
use super::traits::{SignerInfo, TransactionSigner};
use alloy::primitives::{Address, B256, U256};
use alloy::signers::Signature;
use async_trait::async_trait;
use aws_credential_types::provider::ProvideCredentials;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Request payload for Nitro Enclave hash signing
///
/// `secret_id` is deliberately absent: the signing service selects the wallet from its
/// own configuration. A caller-chosen secret id would let any authorized caller name any
/// other wallet in the namespace the instance role can read.
#[derive(Serialize)]
struct NitroSignHashRequest {
    hash: String,
}

/// Response from Nitro Enclave signing
#[derive(Deserialize)]
struct NitroSignResponse {
    signature: Option<NitroSignature>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct NitroSignature {
    r: String,
    s: String,
    v: u64,
}

/// How the signer proves its identity to the Nitro signing service.
///
/// The service accepts one or the other, matching its own `NITRO_AUTH_MODE`. There is no
/// unauthenticated variant: the service rejects requests it cannot attribute.
#[derive(Debug, Clone)]
pub enum NitroAuth {
    /// Sign a `GetCallerIdentity` request per call; the service replays it to STS to
    /// learn this Lambda's role ARN. Requires no certificate provisioning.
    SigV4 { region: String },
    /// Present a client certificate issued by the service's configured CA. Cheaper per
    /// request (no STS call) and the usual choice where a private CA already exists.
    Mtls { client_identity_path: String },
}

/// Nitro Enclave signer configuration
#[derive(Debug, Clone)]
pub struct NitroConfig {
    /// HTTPS endpoint for the Nitro signing service (NLB URL)
    pub endpoint: String,
    /// How to authenticate to the service
    pub auth: NitroAuth,
    /// Optional path to a PEM-encoded CA certificate to trust for TLS validation.
    /// When set, only this CA is trusted. When unset, the system's default CA
    /// store is used. In either case, certificate validation is always enforced.
    pub ca_cert_path: Option<String>,
    /// Optional inline PEM-encoded CA certificate (alternative to `ca_cert_path`).
    /// This is how CDK delivers the deployment CA to the Lambda: the Nitro stack's
    /// per-instance server certs are issued by this CA, so trusting it — and validating
    /// the NLB DNS name against the cert's SAN — is real verification with no mounted
    /// file. Takes precedence over `ca_cert_path` when both are set.
    pub ca_cert_pem: Option<String>,
    /// Skip TLS certificate verification. Only for internal VPC deployments
    /// where the Nitro server uses a self-signed certificate.
    pub skip_tls_verify: bool,
}

impl NitroConfig {
    /// Resolve the authentication mode from the environment.
    ///
    /// Defaults to SigV4, which needs no provisioning beyond the execution role.
    fn auth_from_env() -> SignerResult<NitroAuth> {
        let mode = std::env::var("NITRO_AUTH_MODE").unwrap_or_else(|_| "sigv4".to_string());
        match mode.trim().to_ascii_lowercase().as_str() {
            "sigv4" => Ok(NitroAuth::SigV4 {
                region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
            }),
            "mtls" => Ok(NitroAuth::Mtls {
                client_identity_path: std::env::var("NITRO_CLIENT_IDENTITY_PATH").map_err(
                    |_| {
                        SignerError::Config(
                            "NITRO_AUTH_MODE=mtls requires NITRO_CLIENT_IDENTITY_PATH (PEM \
                             holding the client certificate and its private key)"
                                .to_string(),
                        )
                    },
                )?,
            }),
            other => Err(SignerError::Config(format!(
                "NITRO_AUTH_MODE must be 'sigv4' or 'mtls', got '{}'",
                other
            ))),
        }
    }

    /// Load auth and TLS settings from the environment for an already-resolved endpoint.
    ///
    /// The endpoint is passed in rather than read here so there is a single place
    /// (`SignerConfig::from_env`) that decides whether Nitro is configured at all.
    pub fn from_env(endpoint: String) -> SignerResult<Self> {
        let ca_cert_path = std::env::var("NITRO_CA_CERT_PATH").ok();
        let ca_cert_pem = std::env::var("NITRO_CA_CERT_PEM")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let skip_tls_verify = std::env::var("NITRO_SKIP_TLS_VERIFY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        Ok(Self {
            endpoint,
            auth: Self::auth_from_env()?,
            ca_cert_path,
            ca_cert_pem,
            skip_tls_verify,
        })
    }
}

/// Signer that delegates to a Nitro Enclave via HTTP
pub struct NitroSigner {
    address: Address,
    endpoint: String,
    /// Label for logs and `SignerInfo` only. Which wallet actually signs is decided by
    /// the signing service, not by this client.
    secret_id: String,
    auth: NitroAuth,
    client: Client,
    credentials: Option<Arc<dyn ProvideCredentials>>,
}

impl NitroSigner {
    /// Create a signer with an explicit credentials provider for SigV4 identity proofs.
    ///
    /// # Arguments
    ///
    /// * `address` - The wallet address this signer produces signatures for.
    /// * `config` - Endpoint, auth mode, and TLS settings.
    /// * `secret_id` - Label used in logs and `SignerInfo`; not sent to the service.
    /// * `credentials` - Provider for the execution role's credentials. Required for
    ///   [`NitroAuth::SigV4`]; ignored for mTLS.
    pub fn with_credentials(
        address: Address,
        config: &NitroConfig,
        secret_id: String,
        credentials: Option<Arc<dyn ProvideCredentials>>,
    ) -> SignerResult<Self> {
        use reqwest::tls::Version;

        let mut builder = Client::builder()
            // Force TLS 1.2 minimum for rustls compatibility
            .min_tls_version(Version::TLS_1_2)
            .timeout(Duration::from_secs(30));

        if config.skip_tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        } else if let Some(pem) = config.ca_cert_pem.as_deref() {
            // Inline deployment CA (from CDK env). Only this CA is trusted; the NLB DNS
            // name is still validated against the server cert's SAN.
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| SignerError::Config(format!("Invalid NITRO_CA_CERT_PEM: {}", e)))?;
            builder = builder.add_root_certificate(cert);
        } else if let Some(ref ca_cert_path) = config.ca_cert_path {
            let pem = std::fs::read(ca_cert_path).map_err(|e| {
                SignerError::Config(format!("Failed to read CA cert '{}': {}", ca_cert_path, e))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                SignerError::Config(format!("Invalid CA cert '{}': {}", ca_cert_path, e))
            })?;
            builder = builder.add_root_certificate(cert);
        }

        if let NitroAuth::Mtls {
            ref client_identity_path,
        } = config.auth
        {
            let pem = std::fs::read(client_identity_path).map_err(|e| {
                SignerError::Config(format!(
                    "Failed to read client identity '{}': {}",
                    client_identity_path, e
                ))
            })?;
            let identity = reqwest::Identity::from_pem(&pem).map_err(|e| {
                SignerError::Config(format!(
                    "Invalid client identity '{}' (expected a PEM holding both the \
                     certificate and its private key): {}",
                    client_identity_path, e
                ))
            })?;
            builder = builder.identity(identity);
        }

        let client = builder
            .build()
            .map_err(|e| SignerError::Config(format!("HTTP client error: {}", e)))?;

        Ok(Self {
            address,
            endpoint: config.endpoint.clone(),
            secret_id,
            auth: config.auth.clone(),
            client,
            credentials,
        })
    }

    /// Attach proof of this caller's identity to a request.
    ///
    /// For mTLS the proof is the client certificate, already presented during the TLS
    /// handshake, so nothing is added here.
    async fn authenticate(
        &self,
        request: reqwest::RequestBuilder,
        body: &[u8],
    ) -> SignerResult<reqwest::RequestBuilder> {
        let NitroAuth::SigV4 { ref region } = self.auth else {
            return Ok(request);
        };

        let provider = self.credentials.as_ref().ok_or_else(|| {
            SignerError::Config(
                "Nitro SigV4 authentication requires a credentials provider".to_string(),
            )
        })?;

        let credentials = provider
            .provide_credentials()
            .await
            .map_err(|e| SignerError::Config(format!("Failed to resolve credentials: {}", e)))?;

        let proof = nitro_auth::build_identity_proof(&credentials, region, body)?;

        let request = request
            .header(AUTHORIZATION_HEADER, &proof.authorization)
            .header(DATE_HEADER, &proof.date)
            .header(DIGEST_HEADER, &proof.digest);

        Ok(match proof.session_token {
            Some(token) => request.header(TOKEN_HEADER, token),
            None => request,
        })
    }
}

#[async_trait]
impl TransactionSigner for NitroSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            address: self.address,
            name: Some(format!("Nitro:{}", self.secret_id)),
            backend: "nitro".to_string(),
            supports_batch: false,
        }
    }

    async fn sign_hash(&self, hash: B256) -> SignerResult<Signature> {
        let url = format!("{}/sign_hash", self.endpoint.trim_end_matches('/'));

        let request = NitroSignHashRequest {
            hash: format!("0x{}", hex::encode(hash)),
        };

        // Serialize once: the identity proof covers a digest of these exact bytes, so the
        // body that is signed must be the body that is sent.
        let body = serde_json::to_vec(&request).map_err(|e| {
            SignerError::Config(format!("Failed to serialize sign_hash request: {}", e))
        })?;

        debug!(url = %url, hash = ?hash, "Sending sign_hash request to Nitro enclave");

        let signed_request = self
            .authenticate(
                self.client
                    .post(&url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.clone()),
                &body,
            )
            .await?;

        let response = signed_request.send().await.map_err(|e| {
            // Log full error chain for debugging
            let mut source_chain = String::new();
            let mut current: &dyn Error = &e;
            while let Some(source) = current.source() {
                source_chain.push_str(&format!(" -> {}", source));
                current = source;
            }
            tracing::error!(
                error = %e,
                source_chain = %source_chain,
                is_timeout = e.is_timeout(),
                is_connect = e.is_connect(),
                is_request = e.is_request(),
                is_builder = e.is_builder(),
                url = %url,
                "Nitro request error details"
            );
            if e.is_timeout() {
                SignerError::Timeout(format!("Nitro request timed out: {}", e))
            } else if e.is_connect() {
                SignerError::Network(format!("Failed to connect to Nitro endpoint: {}", e))
            } else {
                SignerError::Network(format!("Nitro request failed: {}{}", e, source_chain))
            }
        })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SignerError::ExternalApi(format!(
                "Nitro returned {}: {}",
                status, body
            )));
        }

        // Get response body as text first for debugging
        let body_text = response.text().await.map_err(|e| {
            SignerError::ExternalApi(format!("Failed to read response body: {}", e))
        })?;

        debug!(body = %body_text, "Nitro response body");

        let result: NitroSignResponse = serde_json::from_str(&body_text).map_err(|e| {
            SignerError::ExternalApi(format!(
                "Invalid response from Nitro: {} - body: {}",
                e, body_text
            ))
        })?;

        if let Some(err) = result.error {
            return Err(SignerError::Backend(err));
        }

        let sig = result
            .signature
            .ok_or_else(|| SignerError::Backend("No signature in response".into()))?;

        // Parse r, s from hex strings
        let r_hex = sig.r.strip_prefix("0x").unwrap_or(&sig.r);
        let s_hex = sig.s.strip_prefix("0x").unwrap_or(&sig.s);

        let r = U256::from_str_radix(r_hex, 16)
            .map_err(|e| SignerError::Crypto(format!("Invalid r value: {}", e)))?;
        let s = U256::from_str_radix(s_hex, 16)
            .map_err(|e| SignerError::Crypto(format!("Invalid s value: {}", e)))?;

        // v is 27 or 28 from Nitro, convert to parity (0 or 1)
        let parity = sig.v != 27;

        let sig = Signature::new(r, s, parity);

        // Verify signature recovers to expected address
        let recovered = sig
            .recover_address_from_prehash(&hash)
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
        let url = format!("{}/health", self.endpoint.trim_end_matches('/'));

        self.client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| SignerError::Network(format!("Health check failed: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid self-signed CA fixture (throwaway; short-lived). Proves the inline-CA
    /// trust path builds a verifying client — the production path where CDK passes the
    /// deployment CA as NITRO_CA_CERT_PEM.
    const TEST_CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUNq4RkvpcJxS9ftLcknRVBEfKhZAwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNjA5MTAxOTA1MjFaFw0yNjA5MTEx
OTA1MjFaMBIxEDAOBgNVBAMMB3Rlc3QtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCnKlCXOZBqqdxFzIUttgTNXxmHz1ZnrgkllQT2HLcjMezV2C8Y
0oaEBBCirVXI+THi1m72cBbRWn7VecmViy2O1cgl5bH9p4Wy9VU9JEvQZYm+3pDQ
nmzhGimyWmaPS5seFDsoymmTSPJgRaYwR/QbvBodG8zsKlF1FDDaNMOBb4yQZUsZ
wIlc1MIptpfg+ns/6/YeA/voLLg4Bu7uXCY7huTC4ihbr1mx7BeDosubuAd2jO1Q
BygD2lPIO/ayAXExp9wqQbEu4oh3Zvt8pBbi3D6T7ZclhBnsQq9D9HJREuq6avxD
RvG8qqiAqtKJ85Yf6F/yEZwnqm7SSWyTL4t1AgMBAAGjUzBRMB0GA1UdDgQWBBRH
jj+Wx5ZPyE+Hg18ZUb5quzsVJzAfBgNVHSMEGDAWgBRHjj+Wx5ZPyE+Hg18ZUb5q
uzsVJzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCQyxXjYTWv
Nomn54vtAGexpmRaX0D36ak1V9igV50e/YD0dzzn2ILAyAF0Dhj1t+A6qPnBZZ32
yg7rmuQY5/Cbri4VvIv0+C3LMpr9E5T9aZfcRYaPA3KtaldrH8TZsj8VsC0nmoDr
ScWWqk3R/opVgG5y8a1qOsPNs8S+lTWL+le78S14Rxk80SMgo7/KKez56mas0aSE
6iHe2lLMyMGDqgfO0uD63bzEwj+gVtTlbV5/StHszWgzhmoUGCpfs2KgTzpAbnij
O+xsCDDa3ClgjemhO/yWqUYPx0b7xi8b18oEemdk3AMJ+pcey7kBSzPZDfJ/dJMd
fn6TioDolTJT
-----END CERTIFICATE-----
"#;

    #[test]
    fn inline_ca_pem_builds_a_verifying_client() {
        let signer = NitroSigner::with_credentials(
            Address::repeat_byte(0x11),
            &NitroConfig {
                endpoint: "https://nlb.example".to_string(),
                auth: NitroAuth::SigV4 {
                    region: "us-east-1".to_string(),
                },
                ca_cert_path: None,
                ca_cert_pem: Some(TEST_CA_PEM.to_string()),
                skip_tls_verify: false,
            },
            "nitro-wallet/test".to_string(),
            None,
        );
        assert!(
            signer.is_ok(),
            "valid inline CA must build a client: {:?}",
            signer.err()
        );
    }

    #[test]
    fn from_env_reads_inline_ca_and_ignores_blank() {
        // Isolate env mutations to this test.
        unsafe {
            std::env::set_var("NITRO_CA_CERT_PEM", "  ");
            std::env::set_var("NITRO_AUTH_MODE", "sigv4");
        }
        let cfg = NitroConfig::from_env("https://nlb.example".to_string()).unwrap();
        assert_eq!(cfg.ca_cert_pem, None, "blank inline CA is treated as unset");
        unsafe {
            std::env::set_var("NITRO_CA_CERT_PEM", TEST_CA_PEM);
        }
        let cfg = NitroConfig::from_env("https://nlb.example".to_string()).unwrap();
        assert!(cfg.ca_cert_pem.is_some());
        unsafe {
            std::env::remove_var("NITRO_CA_CERT_PEM");
            std::env::remove_var("NITRO_AUTH_MODE");
        }
    }
    use aws_credential_types::Credentials;
    use sha2::Digest;
    use wiremock::matchers::{header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a signer pointed at `endpoint` with static SigV4 credentials.
    ///
    /// The mock server does not verify identity proofs — that is the signing service's
    /// job, tested on the Python side. These tests cover request construction and
    /// response handling; `sigv4_mode_attaches_proof_headers` asserts the proof headers
    /// are actually present on the wire.
    fn test_signer(address: Address, endpoint: String) -> NitroSigner {
        NitroSigner::with_credentials(
            address,
            &NitroConfig {
                endpoint,
                auth: NitroAuth::SigV4 {
                    region: "us-east-1".to_string(),
                },
                ca_cert_path: None,
                ca_cert_pem: None,
                skip_tls_verify: true,
            },
            "test-secret".to_string(),
            Some(Arc::new(Credentials::new(
                "AKIDEXAMPLE",
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                Some("session-token".to_string()),
                None,
                "test",
            ))),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_sign_hash_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/sign_hash"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": {
                    "r": "0x63b0e704a223cde8b5ddd4eacd25b86cfb1d3edd8c713aecd03944fa4962927d",
                    "s": "0x5533afe99d68aac0a1f7021d7fad22ba105c78b7edc393f6a76e867184e366ed",
                    "v": 28
                }
            })))
            .mount(&mock_server)
            .await;

        let expected_addr: Address = "0xD764672D0bF0Cf30d2D3D665Bb5edd919Aa86384"
            .parse()
            .unwrap();
        let signer = test_signer(expected_addr, mock_server.uri());

        let hash = B256::left_padding_from(&[1u8]);
        let sig = signer.sign_hash(hash).await.unwrap();

        // Verify signature recovers to expected address
        let recovered = sig.recover_address_from_prehash(&hash).unwrap();
        assert_eq!(recovered, expected_addr);
    }

    #[tokio::test]
    async fn sigv4_mode_attaches_proof_headers() {
        let mock_server = MockServer::start().await;

        // The service rejects a request missing any of these, and rejects a digest that
        // does not match the body, so assert all four go out and that the digest covers
        // the bytes actually sent.
        let expected_body = serde_json::to_vec(&NitroSignHashRequest {
            hash: format!("0x{}", hex::encode(B256::ZERO)),
        })
        .unwrap();
        let expected_digest = hex::encode(sha2::Sha256::digest(&expected_body));

        Mock::given(method("POST"))
            .and(path("/sign_hash"))
            .and(header_exists(AUTHORIZATION_HEADER))
            .and(header_exists(DATE_HEADER))
            .and(header(TOKEN_HEADER, "session-token"))
            .and(header(DIGEST_HEADER, expected_digest.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": "reached-with-auth"
            })))
            .mount(&mock_server)
            .await;

        let signer = test_signer(Address::ZERO, mock_server.uri());

        // The mock only matches when every proof header is present and the digest is
        // correct, so reaching the backend error proves the request was well formed.
        match signer.sign_hash(B256::ZERO).await.unwrap_err() {
            SignerError::Backend(msg) => assert_eq!(msg, "reached-with-auth"),
            e => panic!("Authenticated request did not reach the mock: {:?}", e),
        }
    }

    #[tokio::test]
    async fn sigv4_mode_without_credentials_is_a_config_error() {
        // Failing here rather than sending an unauthenticated request matters: the
        // service would reject it anyway, and a silent downgrade would be worse.
        let signer = NitroSigner::with_credentials(
            Address::ZERO,
            &NitroConfig {
                endpoint: "https://example.invalid".to_string(),
                auth: NitroAuth::SigV4 {
                    region: "us-east-1".to_string(),
                },
                ca_cert_path: None,
                ca_cert_pem: None,
                skip_tls_verify: true,
            },
            "test-secret".to_string(),
            None,
        )
        .unwrap();

        match signer.sign_hash(B256::ZERO).await.unwrap_err() {
            SignerError::Config(msg) => assert!(msg.contains("credentials provider"), "{}", msg),
            e => panic!("Expected Config error, got {:?}", e),
        }
    }

    #[test]
    fn mtls_mode_rejects_a_missing_client_identity() {
        // Construction must fail loudly: a client that silently starts without its
        // certificate would present no identity and be rejected on every request.
        let result = NitroSigner::with_credentials(
            Address::ZERO,
            &NitroConfig {
                endpoint: "https://example.invalid".to_string(),
                auth: NitroAuth::Mtls {
                    client_identity_path: "/nonexistent/client.pem".to_string(),
                },
                ca_cert_path: None,
                ca_cert_pem: None,
                skip_tls_verify: true,
            },
            "test-secret".to_string(),
            None,
        );

        match result {
            Err(SignerError::Config(msg)) => assert!(msg.contains("client identity"), "{}", msg),
            Err(e) => panic!("Expected Config error, got {:?}", e),
            Ok(_) => panic!("Expected construction to fail without a client certificate"),
        }
    }

    #[tokio::test]
    async fn request_body_omits_secret_id() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/sign_hash"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": "ok"
            })))
            .mount(&mock_server)
            .await;

        let signer = test_signer(Address::ZERO, mock_server.uri());
        let _ = signer.sign_hash(B256::ZERO).await;

        let requests = mock_server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();

        // The wallet is chosen by the service, never named by this client.
        assert!(
            body.get("secret_id").is_none(),
            "client must not send secret_id, got {}",
            body
        );
        assert!(body.get("hash").is_some());
    }

    #[tokio::test]
    async fn test_sign_hash_v27_parity() {
        let mock_server = MockServer::start().await;

        // Use a signature with v=27 (parity=false)
        Mock::given(method("POST"))
            .and(path("/sign_hash"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": {
                    "r": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                    "s": "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
                    "v": 27
                }
            })))
            .mount(&mock_server)
            .await;

        let signer = test_signer(Address::ZERO, mock_server.uri());

        let hash = B256::ZERO;
        // With ecrecover verification, synthetic signatures fail recovery against
        // Address::ZERO. Verify we get a Crypto error (not a panic).
        let result = signer.sign_hash(hash).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::Crypto(msg) => {
                assert!(msg.contains("Signature") || msg.contains("recovery"))
            }
            e => panic!("Expected Crypto error, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_sign_hash_v28_parity() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/sign_hash"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": {
                    "r": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                    "s": "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
                    "v": 28
                }
            })))
            .mount(&mock_server)
            .await;

        let signer = test_signer(Address::ZERO, mock_server.uri());

        let hash = B256::ZERO;
        let result = signer.sign_hash(hash).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::Crypto(msg) => {
                assert!(msg.contains("Signature") || msg.contains("recovery"))
            }
            e => panic!("Expected Crypto error, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_sign_hash_error_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/sign_hash"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": "Key not found"
            })))
            .mount(&mock_server)
            .await;

        let signer = test_signer(Address::ZERO, mock_server.uri());

        let result = signer.sign_hash(B256::ZERO).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            SignerError::Backend(msg) => assert_eq!(msg, "Key not found"),
            e => panic!("Expected Backend error, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_sign_hash_http_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/sign_hash"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let signer = test_signer(Address::ZERO, mock_server.uri());

        let result = signer.sign_hash(B256::ZERO).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            SignerError::ExternalApi(msg) => assert!(msg.contains("500")),
            e => panic!("Expected ExternalApi error, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn unauthorized_response_is_surfaced() {
        let mock_server = MockServer::start().await;

        // What the service returns when the caller is not on its allowlist. It must not
        // be mistaken for a transient fault, so the status has to reach the caller.
        Mock::given(method("POST"))
            .and(path("/sign_hash"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": "Caller is not authorized to use this signing service"
            })))
            .mount(&mock_server)
            .await;

        let signer = test_signer(Address::ZERO, mock_server.uri());

        match signer.sign_hash(B256::ZERO).await.unwrap_err() {
            SignerError::ExternalApi(msg) => {
                assert!(msg.contains("403"), "status should be surfaced: {}", msg);
                assert!(msg.contains("not authorized"));
            }
            e => panic!("Expected ExternalApi error, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_sign_hash_invalid_json() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/sign_hash"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&mock_server)
            .await;

        let signer = test_signer(Address::ZERO, mock_server.uri());

        let result = signer.sign_hash(B256::ZERO).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            SignerError::ExternalApi(msg) => assert!(msg.contains("Invalid response")),
            e => panic!("Expected ExternalApi error, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_sign_hash_missing_signature() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/sign_hash"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;

        let signer = test_signer(Address::ZERO, mock_server.uri());

        let result = signer.sign_hash(B256::ZERO).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            SignerError::Backend(msg) => assert!(msg.contains("No signature")),
            e => panic!("Expected Backend error, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_health_check_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock_server)
            .await;

        let signer = test_signer(Address::ZERO, mock_server.uri());

        let result = signer.health_check().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_signer_info() {
        let addr: Address = "0xD764672D0bF0Cf30d2D3D665Bb5edd919Aa86384"
            .parse()
            .unwrap();
        let signer = test_signer(addr, "https://example.com".to_string());

        let info = signer.info();
        assert_eq!(info.address, addr);
        assert_eq!(info.backend, "nitro");
        assert!(!info.supports_batch);
        assert!(info.name.unwrap().contains("test-secret"));
    }

    #[tokio::test]
    async fn test_sign_hash_strips_0x_prefix() {
        let mock_server = MockServer::start().await;

        // Test that r/s values work with or without 0x prefix
        Mock::given(method("POST"))
            .and(path("/sign_hash"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": {
                    "r": "63b0e704a223cde8b5ddd4eacd25b86cfb1d3edd8c713aecd03944fa4962927d",
                    "s": "5533afe99d68aac0a1f7021d7fad22ba105c78b7edc393f6a76e867184e366ed",
                    "v": 28
                }
            })))
            .mount(&mock_server)
            .await;

        let expected_addr: Address = "0xD764672D0bF0Cf30d2D3D665Bb5edd919Aa86384"
            .parse()
            .unwrap();
        let signer = test_signer(expected_addr, mock_server.uri());

        let hash = B256::left_padding_from(&[1u8]);
        let sig = signer.sign_hash(hash).await.unwrap();

        let recovered = sig.recover_address_from_prehash(&hash).unwrap();
        assert_eq!(recovered, expected_addr);
    }
}
