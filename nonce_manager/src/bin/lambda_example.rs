//! Example: Lambda + Finalizer Architecture
//!
//! Demonstrates the pattern where:
//! - Lambda functions submit transactions and exit after mempool acceptance
//! - A separate long-running finalizer watches for on-chain confirmation
//!
//! Run with:
//! ```
//! DYNAMODB_TABLE=tx_tracker \
//! ETH_RPC_URL=https://eth.llamarpc.com \
//! cargo run --bin lambda_example --features tracing-subscriber
//! ```

use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use nonce_manager::{
    DynamoNonceManager, FailureType, LambdaExecutor, LambdaSubmitResult, NonceManagerConfig,
};
use std::sync::Arc;
use std::time::Duration;

fn classify_error(error: &str) -> FailureType {
    let e = error.to_lowercase();
    if e.contains("nonce too low") || e.contains("already known") {
        FailureType::NodeRejected
    } else if e.contains("revert") {
        FailureType::OnChainRevert
    } else if e.contains("timeout") || e.contains("connection") {
        FailureType::Transient
    } else {
        FailureType::NodeRejected
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

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
    manager.initialize_wallet(wallet).await?;

    println!("=== Lambda + Finalizer Architecture Demo ===\n");

    // Simulate multiple Lambda invocations
    println!("--- Simulating Lambda Invocations ---\n");
    simulate_lambda_invocations(manager.clone(), wallet).await?;

    // Simulate finalizer processing
    println!("\n--- Simulating Finalizer Process ---\n");
    simulate_finalizer(manager, wallet).await?;

    Ok(())
}

/// Simulates what happens in Lambda functions
async fn simulate_lambda_invocations<P>(
    manager: DynamoNonceManager<P>,
    wallet: Address,
) -> anyhow::Result<()>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    let executor = LambdaExecutor::new(manager);

    // Simulate 3 concurrent Lambda invocations
    let mut handles = vec![];

    for i in 0..3 {
        let exec = LambdaExecutor::new(executor.manager().clone());

        let handle = tokio::spawn(async move {
            println!("  Lambda {} starting...", i);

            let result = exec
                .submit(
                    wallet,
                    |nonce| async move {
                        println!("    Lambda {}: Simulating nonce {}", i, nonce);
                        // Simulate eth_call for revert check
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(())
                    },
                    |nonce| async move {
                        println!("    Lambda {}: Broadcasting nonce {}", i, nonce);
                        // Simulate signing + eth_sendRawTransaction
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        let hash = B256::repeat_byte((nonce % 256) as u8);
                        let signed_raw_tx = vec![0x02u8, (nonce % 256) as u8];
                        Ok((hash, signed_raw_tx, U256::from(20_000_000_000u64)))
                    },
                    classify_error,
                )
                .await;

            match &result {
                LambdaSubmitResult::Accepted { nonce, tx_hash } => {
                    println!(
                        "  Lambda {} DONE: TX accepted, nonce={}, hash={:?}",
                        i, nonce, tx_hash
                    );
                    println!("  Lambda {} can now terminate safely", i);
                }
                LambdaSubmitResult::SimulationFailed { nonce, error, .. } => {
                    println!(
                        "  Lambda {} FAILED: Simulation error at nonce {}: {}",
                        i, nonce, error
                    );
                }
                LambdaSubmitResult::BroadcastFailed { nonce, error, .. } => {
                    println!(
                        "  Lambda {} FAILED: Broadcast error at nonce {}: {}",
                        i, nonce, error
                    );
                }
                LambdaSubmitResult::ReservationFailed { error } => {
                    println!("  Lambda {} FAILED: Could not reserve nonce: {}", i, error);
                }
            }

            result
        });

        handles.push(handle);
    }

    // Wait for all "Lambda invocations" to complete
    for handle in handles {
        let _ = handle.await?;
    }

    Ok(())
}

/// Simulates the long-running finalizer process
async fn simulate_finalizer<P>(
    manager: DynamoNonceManager<P>,
    wallet: Address,
) -> anyhow::Result<()>
where
    P: Provider + Clone,
{
    println!("  Finalizer checking pending transactions...\n");

    // Query pending transactions
    let pending = manager.get_pending_for_finalization(wallet).await?;

    if pending.is_empty() {
        println!("  No pending transactions to finalize");
        return Ok(());
    }

    println!("  Found {} pending transactions:", pending.len());
    for tx in &pending {
        println!(
            "    - nonce={}, hash={:?}, age={}s",
            tx.nonce, tx.tx_hash, tx.age_seconds
        );
    }

    // Simulate checking on-chain status for each
    println!("\n  Checking on-chain status...");

    let mut confirmed = vec![];
    let mut failed = vec![];

    for tx in &pending {
        // In real code: call eth_getTransactionReceipt
        // Simulate: first 2 confirmed, last one reverted
        if tx.nonce % 3 != 2 {
            println!("    nonce {}: CONFIRMED on-chain", tx.nonce);
            confirmed.push(tx.nonce);
        } else {
            println!("    nonce {}: REVERTED on-chain", tx.nonce);
            failed.push(tx.nonce);
        }
    }

    // Update DynamoDB state
    if !confirmed.is_empty() {
        println!(
            "\n  Marking {} transactions as confirmed...",
            confirmed.len()
        );
        manager.batch_confirm(wallet, &confirmed).await?;
    }

    if !failed.is_empty() {
        println!("  Marking {} transactions as failed...", failed.len());
        manager.batch_mark_failed(wallet, &failed).await?;
    }

    // Check final state
    let state = manager.get_wallet_state(wallet).await?;
    println!("\n  Final wallet state:");
    println!("    Next nonce: {}", state.next_nonce);
    println!("    Confirmed nonce: {}", state.confirmed_nonce);
    println!("    Pending count: {}", state.pending_count);
    if !state.gaps.is_empty() {
        println!("    Gaps: {:?}", state.gaps);
    }

    Ok(())
}
