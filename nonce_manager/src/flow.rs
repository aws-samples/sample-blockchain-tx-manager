//! Transaction flow helpers for common patterns
//!
//! Provides high-level abstractions for transaction lifecycle management

use crate::error::Result;
use crate::manager::DynamoNonceManager;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use std::future::Future;
use tracing::{debug, error, info, warn};

/// Result of a transaction submission attempt
#[derive(Debug)]
pub enum SubmitResult {
    /// Transaction submitted successfully
    Success { nonce: u64, tx_hash: B256 },
    /// Simulation failed, nonce was released
    SimulationFailed { nonce: u64, error: String },
    /// Broadcast failed, nonce is now a gap
    BroadcastFailed { nonce: u64, error: String },
    /// Could not reserve nonce
    ReservationFailed { error: String },
}

/// Helper for executing transactions with proper nonce management
pub struct TransactionFlow<'a, P>
where
    P: Provider + Clone,
{
    manager: &'a DynamoNonceManager<P>,
}

impl<'a, P> TransactionFlow<'a, P>
where
    P: Provider + Clone,
{
    pub fn new(manager: &'a DynamoNonceManager<P>) -> Self {
        Self { manager }
    }

    /// Execute a transaction with full nonce lifecycle management
    ///
    /// 1. Reserves nonce
    /// 2. Calls simulate_fn - if fails, releases nonce
    /// 3. Calls broadcast_fn - records pending tx
    /// 4. Returns result
    pub async fn execute<S, B, SF, BF>(
        &self,
        address: Address,
        simulate_fn: S,
        broadcast_fn: B,
    ) -> SubmitResult
    where
        S: FnOnce(u64) -> SF,
        SF: Future<Output = std::result::Result<(), String>>,
        B: FnOnce(u64) -> BF,
        BF: Future<Output = std::result::Result<(B256, Vec<u8>, U256), String>>, // (tx_hash, signed_raw_tx, gas_price)
    {
        // Step 1: Reserve nonce
        let nonce = match self.manager.reserve_nonce(address).await {
            Ok(n) => n,
            Err(e) => {
                return SubmitResult::ReservationFailed {
                    error: e.to_string(),
                };
            }
        };

        debug!(wallet = ?address, nonce, "Nonce reserved, simulating...");

        // Step 2: Simulate
        if let Err(sim_error) = simulate_fn(nonce).await {
            warn!(wallet = ?address, nonce, error = %sim_error, "Simulation failed");

            // Try to release the nonce
            if let Err(e) = self.manager.release_nonce(address, nonce).await {
                error!(wallet = ?address, nonce, error = %e, "Failed to release nonce after simulation failure");
            }

            return SubmitResult::SimulationFailed {
                nonce,
                error: sim_error,
            };
        }

        debug!(wallet = ?address, nonce, "Simulation passed, broadcasting...");

        // Step 3: Broadcast
        match broadcast_fn(nonce).await {
            Ok((tx_hash, signed_raw_tx, gas_price)) => {
                // Persist the signed bytes (durable tracker row) then mark broadcast.
                if let Err(e) = self
                    .manager
                    .record_signed(
                        address,
                        nonce,
                        tx_hash,
                        &signed_raw_tx,
                        Some(gas_price),
                        None,
                        None,
                    )
                    .await
                {
                    error!(
                        wallet = ?address,
                        nonce,
                        tx_hash = ?tx_hash,
                        error = %e,
                        "Failed to record signed tx (tx was broadcast!)"
                    );
                } else if let Err(e) = self.manager.mark_broadcast(address, nonce, tx_hash).await {
                    error!(
                        wallet = ?address,
                        nonce,
                        tx_hash = ?tx_hash,
                        error = %e,
                        "Failed to mark broadcast (tx was broadcast!)"
                    );
                }

                info!(wallet = ?address, nonce, tx_hash = ?tx_hash, "Transaction submitted");
                SubmitResult::Success { nonce, tx_hash }
            }
            Err(broadcast_error) => {
                error!(
                    wallet = ?address,
                    nonce,
                    error = %broadcast_error,
                    "Broadcast failed - nonce gap created!"
                );

                SubmitResult::BroadcastFailed {
                    nonce,
                    error: broadcast_error,
                }
            }
        }
    }

    /// Register detected gaps for reuse (call when tx_watcher finds failed transactions)
    /// This is typically not needed since mark_failed already registers gaps,
    /// but useful for reconciliation with blockchain state
    pub async fn register_gaps_for_reuse(&self, address: Address) -> Result<Vec<u64>> {
        let gaps = self.manager.detect_gaps(address).await?;

        if gaps.is_empty() {
            return Ok(vec![]);
        }

        info!(wallet = ?address, gaps = ?gaps, "Registering gaps for reuse");

        // Gaps detected by detect_gaps are not yet in the reuse pool
        // We need to add them (this happens when we detect gaps from blockchain state)
        for &gap_nonce in &gaps {
            // Use release_nonce which will add to gaps set
            let _ = self.manager.release_nonce(address, gap_nonce).await;
        }

        Ok(gaps)
    }
}
