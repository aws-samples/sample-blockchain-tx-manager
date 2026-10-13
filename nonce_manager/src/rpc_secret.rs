//! RPC endpoint resolution from Secrets Manager.
//!
//! Provider RPC URLs (`https://<provider>/v2/<API_KEY>`) are credentials. Deploying them
//! as plaintext Lambda/ECS environment variables exposes the key to anyone who can read
//! the function or task-definition configuration, and puts it in every synthesized
//! template. Production deployments therefore pass `RPC_SECRET_ARN` instead; the secret
//! holds a JSON object `{"rpcUrl": "https://...", "wsRpcUrl": "wss://..."}` and each
//! service reads it once at startup.
//!
//! Plaintext `RPC_URL` / `ETH_RPC_URL` / `WS_RPC_URL` / `HTTP_RPC_URL` remain accepted for
//! local development and non-production stacks; the CDK stack refuses them for prod.

use aws_sdk_secretsmanager::Client as SecretsClient;
use serde::Deserialize;

use crate::error::{NonceError, Result};

/// Environment variable naming the Secrets Manager secret with the RPC endpoints.
pub const RPC_SECRET_ARN_ENV: &str = "RPC_SECRET_ARN";

/// Resolved RPC endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcEndpoints {
    /// HTTP(S) JSON-RPC endpoint.
    pub http: String,
    /// WebSocket endpoint (may be absent for services that never subscribe).
    pub ws: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretShape {
    rpc_url: String,
    #[serde(default)]
    ws_rpc_url: Option<String>,
}

/// Parse the secret's JSON body. Pure so the shape contract is testable.
pub fn parse_rpc_secret(json: &str) -> Result<RpcEndpoints> {
    let shape: SecretShape = serde_json::from_str(json).map_err(|e| {
        NonceError::Config(format!("RPC secret is not the expected JSON object: {e}"))
    })?;
    let http = shape.rpc_url.trim().to_string();
    if !(http.starts_with("https://") || http.starts_with("http://")) {
        return Err(NonceError::Config(
            "RPC secret rpcUrl must be an http(s) URL".to_string(),
        ));
    }
    let ws = shape
        .ws_rpc_url
        .map(|w| w.trim().to_string())
        .filter(|w| !w.is_empty());
    if let Some(w) = &ws
        && !(w.starts_with("wss://") || w.starts_with("ws://"))
    {
        return Err(NonceError::Config(
            "RPC secret wsRpcUrl must be a ws(s) URL".to_string(),
        ));
    }
    Ok(RpcEndpoints { http, ws })
}

/// Fetch and parse the RPC endpoints from the secret named by `secret_arn`.
pub async fn load_rpc_endpoints(client: &SecretsClient, secret_arn: &str) -> Result<RpcEndpoints> {
    let out = client
        .get_secret_value()
        .secret_id(secret_arn)
        .send()
        .await
        .map_err(|e| NonceError::Config(format!("failed to read RPC secret: {e}")))?;
    let body = out
        .secret_string()
        .ok_or_else(|| NonceError::Config("RPC secret has no SecretString".to_string()))?;
    parse_rpc_secret(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_urls() {
        let ep =
            parse_rpc_secret(r#"{"rpcUrl":"https://x/v2/K","wsRpcUrl":"wss://x/v2/K"}"#).unwrap();
        assert_eq!(ep.http, "https://x/v2/K");
        assert_eq!(ep.ws.as_deref(), Some("wss://x/v2/K"));
    }

    #[test]
    fn ws_is_optional_and_blank_is_none() {
        let ep = parse_rpc_secret(r#"{"rpcUrl":"https://x"}"#).unwrap();
        assert_eq!(ep.ws, None);
        let ep = parse_rpc_secret(r#"{"rpcUrl":"https://x","wsRpcUrl":"  "}"#).unwrap();
        assert_eq!(ep.ws, None);
    }

    #[test]
    fn rejects_wrong_schemes_and_shape() {
        assert!(parse_rpc_secret(r#"{"rpcUrl":"ftp://x"}"#).is_err());
        assert!(parse_rpc_secret(r#"{"rpcUrl":"https://x","wsRpcUrl":"https://x"}"#).is_err());
        assert!(
            parse_rpc_secret(r#"{"wsRpcUrl":"wss://x"}"#).is_err(),
            "rpcUrl required"
        );
        assert!(parse_rpc_secret("not json").is_err());
        assert!(
            parse_rpc_secret(r#""https://x""#).is_err(),
            "must be an object"
        );
    }
}
