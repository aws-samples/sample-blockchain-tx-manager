//! Example usage of the DynamoDB Nonce Manager
//!
//! Run with: cargo run --bin example --features tracing-subscriber

use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use nonce_manager::{DynamoNonceManager, NonceManagerConfig};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // DynamoDB client from the ambient AWS environment (region/credentials).
    let aws_cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_dynamodb::Client::new(&aws_cfg);
    let table = std::env::var("DYNAMODB_TABLE").unwrap_or_else(|_| "tx_tracker".to_string());

    // Connect to Ethereum RPC
    let rpc_url =
        std::env::var("ETH_RPC_URL").unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());

    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);
    let provider = Arc::new(provider);

    // Configure nonce manager
    let config = NonceManagerConfig {
        max_pending_per_wallet: 50,
        stuck_threshold: Duration::from_secs(180), // 3 minutes
        gas_bump_percentage: 15,
        ..Default::default()
    };

    // Chain ID 1 = Ethereum mainnet
    let chain_id: u64 = std::env::var("CHAIN_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let manager = DynamoNonceManager::new(client, table, provider, chain_id, config);

    // Example wallet address
    let wallet: Address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".parse()?;

    // Initialize wallet (fetches nonce from blockchain)
    let initial_nonce = manager.initialize_wallet(wallet).await?;
    println!("Wallet initialized with nonce: {}", initial_nonce);

    // Reserve a nonce for a new transaction
    let reserved_nonce = manager.reserve_nonce(wallet).await?;
    println!("Reserved nonce: {}", reserved_nonce);

    // Simulate transaction preparation...
    // If simulation fails, release the nonce:
    // manager.release_nonce(wallet, reserved_nonce).await?;

    // After signing, record the signed transaction, then mark broadcast:
    // manager.record_signed(wallet, reserved_nonce, tx_hash, &signed_raw_tx,
    //     Some(gas_price), None, None).await?;
    // manager.mark_broadcast(wallet, reserved_nonce, tx_hash).await?;

    // Check wallet state
    let state = manager.get_wallet_state(wallet).await?;
    println!("Wallet state: {:?}", state);

    // Check for gaps
    let gaps = manager.detect_gaps(wallet).await?;
    if !gaps.is_empty() {
        println!("Warning: nonce gaps detected: {:?}", gaps);
    }

    // Find stuck transactions
    let stuck = manager.find_stuck_transactions(wallet).await?;
    for tx in &stuck {
        println!(
            "Stuck tx: nonce={}, hash={:?}, age={:?}",
            tx.nonce,
            tx.tx_hash,
            chrono::Utc::now().signed_duration_since(tx.timestamp)
        );

        // Calculate replacement gas price
        if let Some(bumped) = tx.bumped_gas_price(15) {
            println!("  Suggested replacement gas price: {}", bumped);
        }
    }

    Ok(())
}
