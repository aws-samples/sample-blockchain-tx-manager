//! Configuration for the transaction watcher

use std::env;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct WatcherConfig {
    /// WebSocket RPC URL for block subscriptions
    pub ws_rpc_url: String,

    /// HTTP RPC URL. Used to build the `RootProvider` the DynamoDB nonce manager is
    /// constructed with (chain reconciliation) and for the stale-reservation chain
    /// queries during recovery.
    pub http_rpc_url: String,

    /// DynamoDB table name for transaction tracking
    pub dynamodb_table: String,

    /// Chain ID
    pub chain_id: u64,

    /// Required confirmations for finality
    pub required_confirmations: u64,

    /// How long before a pending TX is considered stuck (seconds)
    pub stuck_threshold_secs: u64,

    /// TTL for DynamoDB records (days)
    pub ttl_days: i64,

    /// Reconnect delay on WebSocket disconnect
    pub reconnect_delay: Duration,

    /// Maximum time to wait for the next block header before treating the WebSocket
    /// subscription as silently stalled and reconnecting. An open connection that stops
    /// delivering headers is otherwise indistinguishable from a quiet chain.
    pub block_stall_timeout: Duration,

    /// Internal queue used only to request policy-authorized same-nonce replacements.
    /// When absent, replacement enqueueing is disabled but receipt tracking continues.
    pub replacement_queue_url: Option<String>,

    /// Path of the liveness heartbeat file. The watcher writes the current epoch second
    /// here after every processed block; the ECS container health check reads it and
    /// fails the task when it goes stale, so a hung-but-running watcher is replaced.
    pub heartbeat_path: String,

    /// Fallback poll interval if WS fails (reserved for future use)
    #[allow(dead_code)]
    pub fallback_poll_interval: Duration,
}

impl WatcherConfig {
    /// Load configuration from the environment.
    ///
    /// DynamoDB is the sole nonce authority; there is no Redis dependency. The nonce
    /// manager is built from the DynamoDB client, the tracker table, and an HTTP
    /// `RootProvider` derived from `HTTP_RPC_URL`.
    /// Load configuration, resolving the RPC endpoints from Secrets Manager when
    /// `RPC_SECRET_ARN` is set (production) and from `WS_RPC_URL`/`HTTP_RPC_URL` otherwise.
    /// The watcher needs both a WebSocket and an HTTP endpoint, so a secret without
    /// `wsRpcUrl` is a configuration error here.
    pub async fn load(aws_config: &aws_config::SdkConfig) -> Result<Self, String> {
        let mut cfg = Self::from_env()?;
        if let Ok(arn) = env::var(nonce_manager::rpc_secret::RPC_SECRET_ARN_ENV)
            && !arn.trim().is_empty()
        {
            let client = aws_sdk_secretsmanager::Client::new(aws_config);
            let endpoints = nonce_manager::load_rpc_endpoints(&client, arn.trim())
                .await
                .map_err(|e| e.to_string())?;
            cfg.http_rpc_url = endpoints.http;
            cfg.ws_rpc_url = endpoints
                .ws
                .ok_or_else(|| "RPC secret must include wsRpcUrl for the watcher".to_string())?;
        }
        Ok(cfg)
    }

    pub fn from_env() -> Result<Self, String> {
        // Fail closed on the two values that select *which* chain and table this watcher
        // finalizes nonces for. A default here would silently watch mainnet or a table
        // named tx_tracker; CDK always sets both.
        let chain_id = env::var("CHAIN_ID")
            .map_err(|_| {
                "CHAIN_ID is required (no default; refusing to assume mainnet)".to_string()
            })?
            .parse::<u64>()
            .map_err(|e| format!("CHAIN_ID must be a positive integer: {e}"))?;
        if chain_id == 0 {
            return Err("CHAIN_ID must be non-zero".to_string());
        }
        let dynamodb_table = env::var("DYNAMODB_TABLE")
            .ok()
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| "DYNAMODB_TABLE is required (no default table)".to_string())?;

        Ok(Self {
            ws_rpc_url: env::var("WS_RPC_URL")
                .unwrap_or_else(|_| "ws://localhost:8546".to_string()),
            http_rpc_url: env::var("HTTP_RPC_URL")
                .unwrap_or_else(|_| "http://localhost:8545".to_string()),
            dynamodb_table,
            chain_id,
            required_confirmations: env::var("REQUIRED_CONFIRMATIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(12),
            stuck_threshold_secs: env::var("STUCK_THRESHOLD_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300), // 5 minutes
            ttl_days: env::var("TTL_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(7),
            reconnect_delay: Duration::from_secs(
                env::var("RECONNECT_DELAY_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(5),
            ),
            block_stall_timeout: Duration::from_secs(
                env::var("BLOCK_STALL_TIMEOUT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(120),
            ),
            replacement_queue_url: env::var("REPLACEMENT_QUEUE_URL")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            heartbeat_path: env::var("HEARTBEAT_PATH")
                .unwrap_or_else(|_| "/tmp/tx_watcher_heartbeat".to_string()),
            fallback_poll_interval: Duration::from_secs(
                env::var("FALLBACK_POLL_INTERVAL_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(12),
            ),
        })
    }
}
