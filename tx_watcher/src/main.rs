//! Transaction Watcher Service
//!
//! Subscribes to new blocks and tracks pending transactions to finality.
//! Uses DynamoDB for durable transaction state and WebSocket for real-time block updates.

mod config;
mod error;
mod metrics;
mod reorg;
mod store;
mod watcher;

use config::WatcherConfig;
use store::TxStore;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use watcher::TransactionWatcher;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Load .env if present
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    info!("Transaction Watcher starting...");

    // Initialize AWS SDK
    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let dynamo_client = aws_sdk_dynamodb::Client::new(&aws_config);
    let sqs_client = aws_sdk_sqs::Client::new(&aws_config);

    // Load configuration (RPC endpoints come from Secrets Manager when RPC_SECRET_ARN is set)
    let config = WatcherConfig::load(&aws_config)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    info!(
        chain_id = config.chain_id,
        required_confirmations = config.required_confirmations,
        "Configuration loaded"
    );

    // Create transaction store
    let store = TxStore::new(
        dynamo_client.clone(),
        config.dynamodb_table.clone(),
        config.ttl_days,
    );

    // Create and run watcher. DynamoDB is the sole nonce authority — the watcher builds
    // its DynamoNonceManager from the shared DynamoDB client, the tracker table, and an
    // HTTP RootProvider derived from HTTP_RPC_URL. There is no Redis dependency.
    let watcher = TransactionWatcher::new(config, store, dynamo_client, sqs_client)?;

    // Handle shutdown gracefully. ECS stops tasks with SIGTERM (then SIGKILL after the
    // stop timeout); SIGINT is what a terminal sends. Trap both so a deploy or scale-in
    // exits cleanly between blocks instead of being killed mid-loop.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("failed to install SIGTERM handler: {e}"))?;
    tokio::select! {
        result = watcher.run() => {
            if let Err(e) = result {
                error!(error = %e, "Watcher failed");
                return Err(e.into());
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received; shutting down");
        }
        _ = sigterm.recv() => {
            info!("SIGTERM received; shutting down");
        }
    }

    info!("Transaction Watcher stopped");
    Ok(())
}
