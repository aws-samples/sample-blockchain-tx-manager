//! Example: Concurrent transaction execution with retry
//!
//! Demonstrates safe concurrent nonce management with automatic
//! retry on failures.
//!
//! Run with:
//! ```
//! DYNAMODB_TABLE=tx_tracker \
//! ETH_RPC_URL=https://eth.llamarpc.com \
//! cargo run --bin concurrent_example --features tracing-subscriber
//! ```

use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use nonce_manager::{
    BatchExecutor, ConcurrentExecutor, DynamoNonceManager, FailureType, NonceManagerConfig,
    RetryConfig,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Classify errors to determine retry strategy
fn classify_error(error: &str) -> FailureType {
    let error_lower = error.to_lowercase();

    // Nonce-related errors - slot occupied/consumed, leave pending
    if error_lower.contains("nonce too low")
        || error_lower.contains("nonce has already been used")
        || error_lower.contains("replacement transaction underpriced")
    {
        return FailureType::NodeRejected;
    }

    // Rejected before mempool admission - nonce unspent, safe to recycle
    if error_lower.contains("execution reverted")
        || error_lower.contains("revert")
        || error_lower.contains("out of gas")
    {
        return FailureType::OnChainRevert;
    }

    // Transient/network errors - can retry with same nonce
    if error_lower.contains("timeout")
        || error_lower.contains("connection")
        || error_lower.contains("rate limit")
        || error_lower.contains("503")
        || error_lower.contains("502")
    {
        return FailureType::Transient;
    }

    // Default to node rejected (leave pending for the watcher)
    FailureType::NodeRejected
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Setup connections
    let aws_cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_dynamodb::Client::new(&aws_cfg);
    let table = std::env::var("DYNAMODB_TABLE").unwrap_or_else(|_| "tx_tracker".to_string());
    let rpc_url = std::env::var("ETH_RPC_URL").unwrap_or("https://eth.llamarpc.com".into());

    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);
    let provider = Arc::new(provider);

    // Chain ID 1 = Ethereum mainnet
    let chain_id: u64 = std::env::var("CHAIN_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let manager = DynamoNonceManager::new(
        client,
        table,
        provider.clone(),
        chain_id,
        NonceManagerConfig::default(),
    );

    let wallet: Address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".parse()?;

    // Initialize wallet (fetches nonce from chain)
    let initial_nonce = manager.initialize_wallet(wallet).await?;
    println!("Wallet initialized at nonce: {}", initial_nonce);

    // Demo 1: Concurrent nonce reservation (atomic, no conflicts)
    println!("\n=== Demo 1: Concurrent Nonce Reservation ===");
    demo_concurrent_reservation(&manager, wallet).await?;

    // Demo 2: Transaction with retry on failure
    println!("\n=== Demo 2: Transaction with Retry ===");
    demo_retry_flow(manager.clone(), wallet).await?;

    // Demo 3: Batch execution
    println!("\n=== Demo 3: Batch Execution ===");
    demo_batch_execution(manager, wallet).await?;

    Ok(())
}

/// Demonstrates that concurrent tasks get unique nonces atomically
async fn demo_concurrent_reservation<P>(
    manager: &DynamoNonceManager<P>,
    wallet: Address,
) -> anyhow::Result<()>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    let manager = manager.clone();
    let mut handles = vec![];

    // Spawn 10 concurrent tasks, each reserving a nonce
    for i in 0..10 {
        let mgr = manager.clone();
        let handle = tokio::spawn(async move {
            let nonce = mgr.reserve_nonce(wallet).await?;
            println!("  Task {} got nonce: {}", i, nonce);
            Ok::<_, nonce_manager::NonceError>(nonce)
        });
        handles.push(handle);
    }

    let mut nonces = vec![];
    for handle in handles {
        let nonce = handle.await??;
        nonces.push(nonce);
    }

    // Verify all nonces are unique
    nonces.sort();
    let unique_count = {
        let mut unique = nonces.clone();
        unique.dedup();
        unique.len()
    };

    println!(
        "\n  Reserved {} nonces, {} unique (should be 10)",
        nonces.len(),
        unique_count
    );
    assert_eq!(unique_count, 10, "All nonces should be unique!");
    println!("  All nonces are unique - concurrent reservation works!");

    Ok(())
}

/// Demonstrates retry flow when transactions fail
async fn demo_retry_flow<P>(manager: DynamoNonceManager<P>, wallet: Address) -> anyhow::Result<()>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    let executor = ConcurrentExecutor::new(
        manager,
        RetryConfig {
            max_transient_retries: 2,
            max_fresh_nonce_retries: 5,
            ..Default::default()
        },
    );

    // Counter to simulate failures
    let attempt = Arc::new(AtomicU32::new(0));
    let attempt_sim = attempt.clone();
    let attempt_bc = attempt.clone();

    println!("  Executing transaction (will fail twice, succeed on third)...\n");

    let result = executor
        .execute_with_retry(
            wallet,
            // Simulate function
            move |nonce| {
                let att = attempt_sim.clone();
                async move {
                    let n = att.load(Ordering::SeqCst);
                    println!("    Simulating nonce {} (attempt {})", nonce, n + 1);
                    Ok::<(), String>(()) // Simulation passes
                }
            },
            // Broadcast function -> (tx_hash, signed_raw_tx, gas_price)
            move |nonce| {
                let att = attempt_bc.clone();
                async move {
                    let n = att.fetch_add(1, Ordering::SeqCst);
                    println!("    Broadcasting nonce {} (attempt {})", nonce, n + 1);

                    if n < 2 {
                        // First two attempts are ambiguous transient failures.
                        println!("    -> FAILED: timeout (simulated)");
                        Err("timeout".to_string())
                    } else {
                        let fake_hash = B256::repeat_byte((nonce % 256) as u8);
                        let signed_raw_tx = vec![0x02u8, (nonce % 256) as u8];
                        let gas_price = U256::from(20_000_000_000u64);
                        println!("    -> SUCCESS!");
                        Ok((fake_hash, signed_raw_tx, gas_price))
                    }
                }
            },
            classify_error,
        )
        .await;

    match result {
        Ok((nonce, hash)) => {
            println!("\n  Transaction succeeded after retries!");
            println!("    Final nonce: {}", nonce);
            println!("    Tx hash: {:?}", hash);
        }
        Err(e) => {
            println!("\n  Transaction failed after all retries: {}", e);
        }
    }

    Ok(())
}

/// Demonstrates batch execution of multiple concurrent transactions
async fn demo_batch_execution<P>(
    manager: DynamoNonceManager<P>,
    wallet: Address,
) -> anyhow::Result<()>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    let batch_executor = BatchExecutor::new(
        manager,
        RetryConfig::default(),
        5, // max 5 concurrent
    );

    println!("  Executing batch of 10 transactions (max 5 concurrent)...\n");

    let results = batch_executor
        .execute_batch(
            wallet,
            10,
            |nonce| async move {
                println!("    [{}] Simulating...", nonce);
                Ok(())
            },
            |nonce| async move {
                println!("    [{}] Broadcasting...", nonce);
                let hash = B256::repeat_byte((nonce % 256) as u8);
                let signed_raw_tx = vec![0x02u8, (nonce % 256) as u8];
                Ok((hash, signed_raw_tx, U256::from(20_000_000_000u64)))
            },
            classify_error,
        )
        .await;

    let succeeded = results.iter().filter(|r| r.result.is_ok()).count();
    let failed = results.iter().filter(|r| r.result.is_err()).count();

    println!("\n  Batch results:");
    println!("    Succeeded: {}", succeeded);
    println!("    Failed: {}", failed);

    for result in &results {
        match &result.result {
            Ok((nonce, _)) => println!("    TX {}: nonce {}", result.index, nonce),
            Err(e) => println!("    TX {}: FAILED - {}", result.index, e),
        }
    }

    Ok(())
}
