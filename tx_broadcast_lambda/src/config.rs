//! Lambda configuration

use alloy::primitives::U256;
use std::time::Duration;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct LambdaConfig {
    /// Ethereum RPC URL
    pub eth_rpc_url: String,

    /// Chain ID
    pub chain_id: u64,

    /// DynamoDB table name for transaction tracking
    pub dynamodb_table: String,

    /// TTL for DynamoDB records (days)
    pub ttl_days: i64,

    /// Maximum retries for transient failures
    #[allow(dead_code)]
    pub max_retries: u32,

    /// Timeout for RPC calls
    #[allow(dead_code)]
    pub rpc_timeout: Duration,

    /// Default gas limit if estimation fails
    pub default_gas_limit: u64,

    /// Gas limit buffer percentage (add X% to estimated gas)
    pub gas_buffer_percentage: u64,

    pub replacement_enabled: bool,
    /// Whether direct invocations may use the sign-hash path. Sign-hash hands the caller a
    /// signature over any 32-byte digest, including the signing hash of a transaction the
    /// caller built offline, so every principal with `lambda:InvokeFunction` holds full
    /// wallet authority while it is on. Deployments that only broadcast should turn it off.
    pub sign_hash_enabled: bool,
    pub default_max_fee_per_gas_wei: u128,
    pub hard_max_fee_per_gas_wei: u128,
    pub default_max_total_fee_wei: U256,
    pub hard_max_total_fee_wei: U256,
    pub max_replacement_attempts: u32,
    pub fee_tip_floor_wei: u128,
}

impl LambdaConfig {
    /// Load configuration from the environment.
    ///
    /// `CHAIN_ID` and `DYNAMODB_TABLE` are required and fail closed: a missing chain id
    /// must never silently pin the deployment to mainnet, and a missing table name must
    /// never silently point the nonce authority at a default table. CDK always sets both.
    /// Load configuration, resolving the RPC endpoint from Secrets Manager when
    /// `RPC_SECRET_ARN` is set (production) and from `ETH_RPC_URL`/`RPC_URL` otherwise.
    pub async fn load() -> Result<Self, String> {
        let mut cfg = Self::from_env()?;
        if let Ok(arn) = std::env::var(nonce_manager::rpc_secret::RPC_SECRET_ARN_ENV)
            && !arn.trim().is_empty()
        {
            let aws = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let client = aws_sdk_secretsmanager::Client::new(&aws);
            let endpoints = nonce_manager::load_rpc_endpoints(&client, arn.trim())
                .await
                .map_err(|e| e.to_string())?;
            cfg.eth_rpc_url = endpoints.http;
        }
        Ok(cfg)
    }

    pub fn from_env() -> Result<Self, String> {
        let chain_id = std::env::var("CHAIN_ID")
            .map_err(|_| {
                "CHAIN_ID is required (no default; refusing to assume mainnet)".to_string()
            })?
            .parse::<u64>()
            .map_err(|e| format!("CHAIN_ID must be a positive integer: {e}"))?;
        if chain_id == 0 {
            return Err("CHAIN_ID must be non-zero".to_string());
        }
        let dynamodb_table = std::env::var("DYNAMODB_TABLE")
            .ok()
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| "DYNAMODB_TABLE is required (no default table)".to_string())?;
        let parse_u128 = |name: &str, default: u128| -> Result<u128, String> {
            std::env::var(name)
                .ok()
                .map(|v| {
                    v.parse::<u128>()
                        .map_err(|e| format!("{name} must be a positive integer: {e}"))
                })
                .transpose()
                .map(|v| v.unwrap_or(default))
        };
        let parse_u256 = |name: &str, default: &str| -> Result<U256, String> {
            std::env::var(name)
                .unwrap_or_else(|_| default.to_string())
                .parse::<U256>()
                .map_err(|e| format!("{name} must be a positive integer: {e}"))
        };
        let default_max_fee_per_gas_wei =
            parse_u128("DEFAULT_MAX_FEE_PER_GAS_WEI", 150_000_000_000)?;
        let hard_max_fee_per_gas_wei = parse_u128("HARD_MAX_FEE_PER_GAS_WEI", 500_000_000_000)?;
        let default_max_total_fee_wei =
            parse_u256("DEFAULT_MAX_TOTAL_FEE_WEI", "20000000000000000")?;
        let hard_max_total_fee_wei = parse_u256("HARD_MAX_TOTAL_FEE_WEI", "100000000000000000")?;
        if default_max_fee_per_gas_wei > hard_max_fee_per_gas_wei
            || default_max_total_fee_wei > hard_max_total_fee_wei
        {
            return Err("replacement default fee limits must not exceed hard limits".into());
        }

        Ok(Self {
            // Overwritten by `load()` when RPC_SECRET_ARN is set.
            eth_rpc_url: std::env::var("ETH_RPC_URL")
                .or_else(|_| std::env::var("RPC_URL"))
                .unwrap_or_else(|_| {
                    if std::env::var(nonce_manager::rpc_secret::RPC_SECRET_ARN_ENV).is_err() {
                        warn!("ETH_RPC_URL/RPC_URL not set; defaulting to http://localhost:8545");
                    }
                    "http://localhost:8545".to_string()
                }),

            chain_id,

            dynamodb_table,

            ttl_days: std::env::var("TTL_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(7),

            max_retries: std::env::var("MAX_RETRIES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3),

            rpc_timeout: Duration::from_secs(
                std::env::var("RPC_TIMEOUT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(30),
            ),

            default_gas_limit: std::env::var("DEFAULT_GAS_LIMIT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(21000),

            gas_buffer_percentage: std::env::var("GAS_BUFFER_PERCENTAGE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(20),
            replacement_enabled: std::env::var("REPLACEMENT_ENABLED")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            sign_hash_enabled: std::env::var("SIGN_HASH_ENABLED")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            default_max_fee_per_gas_wei,
            hard_max_fee_per_gas_wei,
            default_max_total_fee_wei,
            hard_max_total_fee_wei,
            max_replacement_attempts: std::env::var("MAX_REPLACEMENT_ATTEMPTS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3),
            fee_tip_floor_wei: parse_u128("FEE_TIP_FLOOR_WEI", 100_000_000)?,
        })
    }
}
