//! Identity proofs for the Nitro signing service
//!
//! The signing service returns ECDSA signatures over caller-supplied hashes, so
//! reaching it is equivalent to holding the wallet. It therefore refuses any request it
//! cannot attribute to an allowed IAM principal.
//!
//! No AWS API can validate a SigV4 signature on a third party's behalf, so the proof is
//! indirect: this module signs an `sts:GetCallerIdentity` request and sends the
//! resulting SigV4 headers alongside the signing request. The service replays them to
//! STS, which validates the signature and reports this Lambda's role ARN.
//!
//! The proof is bound to one specific request body. A SHA-256 digest of the body is sent
//! as a *signed* header, so a captured proof cannot be replayed against a different
//! payload — the service recomputes the digest and also rejects any proof whose
//! `SignedHeaders` list omits the digest header.

use super::error::{SignerError, SignerResult};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;
use sha2::{Digest, Sha256};
use std::time::SystemTime;

pub const AUTHORIZATION_HEADER: &str = "X-Nitro-Auth-Authorization";
pub const DATE_HEADER: &str = "X-Nitro-Auth-Date";
pub const TOKEN_HEADER: &str = "X-Nitro-Auth-Token";
pub const DIGEST_HEADER: &str = "X-Nitro-Request-Digest";

const STS_BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";
const STS_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// Headers that prove the caller's IAM identity for one specific request body.
#[derive(Debug, Clone)]
pub struct IdentityProof {
    pub authorization: String,
    pub date: String,
    pub digest: String,
    pub session_token: Option<String>,
}

/// Compute the lowercase hex SHA-256 of a request body.
fn body_digest(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// Build an identity proof binding `credentials` to `body`.
///
/// # Arguments
///
/// * `credentials` - Credentials resolved from the Lambda execution role.
/// * `region` - The region whose STS endpoint the signing service will replay to. It must
///   match the service's configured region, or verification fails.
/// * `body` - The exact bytes that will be sent to the signing service.
///
/// # Errors
///
/// Returns [`SignerError::Config`] if the request cannot be signed, which indicates
/// malformed credentials or an unusable region rather than a transient fault.
pub fn build_identity_proof(
    credentials: &Credentials,
    region: &str,
    body: &[u8],
) -> SignerResult<IdentityProof> {
    let digest = body_digest(body);
    let host = format!("sts.{}.amazonaws.com", region);
    let url = format!("https://{}/", host);
    let identity = credentials.clone().into();

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("sts")
        .time(SystemTime::now())
        .settings(SigningSettings::default())
        .build()
        .map_err(|e| SignerError::Config(format!("Failed to build SigV4 params: {}", e)))?;

    // The digest is signed, not merely sent: that is what binds the proof to this body.
    let signable = SignableRequest::new(
        "POST",
        &url,
        [
            ("host", host.as_str()),
            ("content-type", STS_CONTENT_TYPE),
            (DIGEST_HEADER, digest.as_str()),
        ]
        .into_iter(),
        SignableBody::Bytes(STS_BODY.as_bytes()),
    )
    .map_err(|e| SignerError::Config(format!("Failed to build signable request: {}", e)))?;

    let (instructions, _signature) = sign(signable, &signing_params.into())
        .map_err(|e| SignerError::Config(format!("SigV4 signing failed: {}", e)))?
        .into_parts();

    let mut authorization = None;
    let mut date = None;
    for (name, value) in instructions.headers() {
        match name.to_ascii_lowercase().as_str() {
            "authorization" => authorization = Some(value.to_string()),
            "x-amz-date" => date = Some(value.to_string()),
            _ => {}
        }
    }

    Ok(IdentityProof {
        authorization: authorization.ok_or_else(|| {
            SignerError::Config("SigV4 produced no Authorization header".to_string())
        })?,
        date: date.ok_or_else(|| {
            SignerError::Config("SigV4 produced no X-Amz-Date header".to_string())
        })?,
        digest,
        session_token: credentials.session_token().map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_credentials() -> Credentials {
        Credentials::new(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            Some("session-token".to_string()),
            None,
            "test",
        )
    }

    #[test]
    fn digest_matches_known_sha256() {
        // Well-known SHA-256 of the empty string.
        assert_eq!(
            body_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn proof_covers_the_digest_header() {
        let proof = build_identity_proof(&test_credentials(), "us-east-1", b"{\"hash\":\"0x1\"}")
            .expect("signing should succeed");

        // The whole security property depends on the digest being in SignedHeaders; the
        // server rejects proofs where it is absent.
        let signed_headers = proof
            .authorization
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .expect("Authorization must carry SignedHeaders");
        assert!(
            signed_headers.contains(&DIGEST_HEADER.to_ascii_lowercase()),
            "digest header must be signed, got: {}",
            signed_headers
        );
        assert!(signed_headers.contains("host"), "host must be signed");
    }

    #[test]
    fn proof_binds_to_body() {
        let creds = test_credentials();
        let one = build_identity_proof(&creds, "us-east-1", b"body-one").unwrap();
        let two = build_identity_proof(&creds, "us-east-1", b"body-two").unwrap();

        assert_ne!(one.digest, two.digest);
        assert_ne!(
            one.authorization, two.authorization,
            "a different body must produce a different signature"
        );
    }

    #[test]
    fn proof_carries_session_token_and_credential_scope() {
        let proof = build_identity_proof(&test_credentials(), "eu-west-1", b"{}").unwrap();

        assert_eq!(proof.session_token.as_deref(), Some("session-token"));
        assert!(
            proof.authorization.contains("eu-west-1/sts/aws4_request"),
            "credential scope must name the signing region and service: {}",
            proof.authorization
        );
        assert!(proof.date.ends_with('Z'), "date must be ISO8601 basic UTC");
    }

    #[test]
    fn proof_omits_session_token_for_long_term_credentials() {
        let creds = Credentials::new("AKIDEXAMPLE", "secret", None, None, "test");
        let proof = build_identity_proof(&creds, "us-east-1", b"{}").unwrap();
        assert!(proof.session_token.is_none());
    }
}
