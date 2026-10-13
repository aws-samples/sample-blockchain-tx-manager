//! Retry mechanism for failed transactions
//!
//! Handles concurrent transaction submission with proper nonce management
//! when transactions fail at various stages.

use crate::error::{NonceError, Result};
use crate::manager::DynamoNonceManager;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Failure classification for retry decisions
#[derive(Debug, Clone, PartialEq)]
pub enum FailureType {
    /// Transaction was never broadcast - nonce can be released/reused
    PreBroadcast,
    /// Transaction was broadcast but rejected by node (bad nonce, insufficient funds, etc.)
    /// Nonce is burned - need fresh nonce
    NodeRejected,
    /// Transaction was rejected synchronously before mempool admission (for example,
    /// insufficient funds, an execution rejection, or an unsupported transaction type).
    /// The nonce is unspent and may be returned to the gap pool. Despite the historical
    /// variant name, a transaction observed mined-and-reverted on-chain is consumed and
    /// must be finalized by the watcher, never classified into this variant.
    OnChainRevert,
    /// Transaction stuck in mempool - can replace with same nonce + higher gas
    Stuck,
    /// Temporary failure (network, RPC) - can retry with same nonce
    Transient,
}

/// Result of a transaction attempt
#[derive(Debug)]
pub enum TxAttemptResult {
    Success {
        nonce: u64,
        tx_hash: B256,
    },
    Failed {
        nonce: u64,
        failure_type: FailureType,
        error: String,
        /// Whether the nonce was successfully released (only for PreBroadcast)
        nonce_released: bool,
    },
}

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum retry attempts for transient failures
    pub max_transient_retries: u32,
    /// Maximum fresh nonce retries (for burned nonces)
    pub max_fresh_nonce_retries: u32,
    /// Base delay between retries (exponential backoff)
    pub base_retry_delay: Duration,
    /// Maximum delay between retries
    pub max_retry_delay: Duration,
    /// Gas price bump percentage for stuck transactions
    pub gas_bump_percentage: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_transient_retries: 3,
            max_fresh_nonce_retries: 5,
            base_retry_delay: Duration::from_millis(100),
            max_retry_delay: Duration::from_secs(5),
            gas_bump_percentage: 15,
        }
    }
}

/// Concurrent transaction executor with retry support
pub struct ConcurrentExecutor<P>
where
    P: Provider + Clone,
{
    manager: DynamoNonceManager<P>,
    retry_config: RetryConfig,
}

impl<P> ConcurrentExecutor<P>
where
    P: Provider + Clone,
{
    pub fn new(manager: DynamoNonceManager<P>, retry_config: RetryConfig) -> Self {
        Self {
            manager,
            retry_config,
        }
    }

    /// Execute a transaction with full retry handling
    ///
    /// This is safe to call concurrently from multiple tasks/threads.
    /// Each call gets its own nonce atomically.
    pub async fn execute_with_retry<S, B, C, SF, BF>(
        &self,
        address: Address,
        simulate: S,
        broadcast: B,
        classify_error: C,
    ) -> Result<(u64, B256)>
    where
        S: Fn(u64) -> SF + Clone,
        SF: Future<Output = std::result::Result<(), String>>,
        B: Fn(u64) -> BF + Clone,
        BF: Future<Output = std::result::Result<(B256, Vec<u8>, U256), String>>,
        C: Fn(&str) -> FailureType + Clone,
    {
        let mut fresh_nonce_attempts = 0;

        loop {
            // Reserve a fresh nonce
            let nonce = self.manager.reserve_nonce(address).await?;

            debug!(
                wallet = ?address,
                nonce,
                attempt = fresh_nonce_attempts + 1,
                "Starting transaction attempt"
            );

            // Try to execute with this nonce (handles transient retries internally)
            let result = self
                .try_execute_with_nonce::<S, B, C, SF, BF>(
                    address,
                    nonce,
                    simulate.clone(),
                    broadcast.clone(),
                    classify_error.clone(),
                )
                .await;

            match result {
                Ok((n, hash)) => return Ok((n, hash)),

                Err(TxAttemptResult::Failed {
                    nonce: failed_nonce,
                    failure_type,
                    error,
                    nonce_released,
                }) => {
                    match failure_type {
                        FailureType::PreBroadcast => {
                            // Nonce should have been released, can retry immediately
                            if nonce_released {
                                debug!(
                                    wallet = ?address,
                                    nonce = failed_nonce,
                                    "Pre-broadcast failure, nonce released, retrying"
                                );
                                // Don't increment fresh_nonce_attempts - we released the nonce
                                continue;
                            }
                            // Nonce wasn't released (wasn't the last one), need fresh nonce
                        }

                        FailureType::Transient | FailureType::NodeRejected | FailureType::Stuck => {
                            // A send may have reached the mempool, or another transaction
                            // may already occupy this nonce. Do not recycle the slot and do
                            // not reserve a fresh nonce for the same intent: either action
                            // can double-broadcast. `try_execute_with_nonce` has already
                            // exhausted bounded same-nonce retries for Transient.
                            warn!(
                                wallet = ?address,
                                nonce = failed_nonce,
                                failure_type = ?failure_type,
                                error = %error,
                                "Broadcast outcome ambiguous; leaving nonce pending"
                            );
                            return Err(NonceError::AmbiguousBroadcast {
                                nonce: failed_nonce,
                                message: error,
                            });
                        }

                        FailureType::OnChainRevert => {
                            // The node rejected the transaction before mempool admission,
                            // so the nonce is unspent and may be returned to the gap pool
                            // before retrying.
                            warn!(
                                wallet = ?address,
                                nonce = failed_nonce,
                                error = %error,
                                "Transaction rejected before admission; recycling nonce"
                            );
                            self.manager.mark_failed(address, failed_nonce).await?;
                        }
                    }

                    fresh_nonce_attempts += 1;

                    if fresh_nonce_attempts >= self.retry_config.max_fresh_nonce_retries {
                        error!(
                            wallet = ?address,
                            attempts = fresh_nonce_attempts,
                            last_error = %error,
                            "Max fresh nonce retries exceeded"
                        );
                        return Err(NonceError::MaxPendingExceeded {
                            wallet: format!("{:?}", address),
                            count: fresh_nonce_attempts as u64,
                            max: self.retry_config.max_fresh_nonce_retries as u64,
                        });
                    }

                    // Backoff before next attempt
                    let delay = self.calculate_backoff(fresh_nonce_attempts);
                    sleep(delay).await;
                }

                Err(_) => unreachable!(),
            }
        }
    }

    /// Try to execute a transaction with a specific nonce
    /// Handles transient retries internally
    async fn try_execute_with_nonce<S, B, C, SF, BF>(
        &self,
        address: Address,
        nonce: u64,
        simulate: S,
        broadcast: B,
        classify_error: C,
    ) -> std::result::Result<(u64, B256), TxAttemptResult>
    where
        S: Fn(u64) -> SF,
        SF: Future<Output = std::result::Result<(), String>>,
        B: Fn(u64) -> BF,
        BF: Future<Output = std::result::Result<(B256, Vec<u8>, U256), String>>,
        C: Fn(&str) -> FailureType,
    {
        let mut transient_attempts = 0;

        loop {
            // Step 1: Simulate
            if let Err(sim_error) = simulate(nonce).await {
                let failure_type = classify_error(&sim_error);

                if failure_type == FailureType::Transient {
                    transient_attempts += 1;
                    if transient_attempts < self.retry_config.max_transient_retries {
                        let delay = self.calculate_backoff(transient_attempts);
                        debug!(
                            nonce,
                            attempt = transient_attempts,
                            delay_ms = delay.as_millis(),
                            "Transient simulation failure, retrying"
                        );
                        sleep(delay).await;
                        continue;
                    }
                }

                // Try to release the nonce
                let nonce_released = self
                    .manager
                    .release_nonce(address, nonce)
                    .await
                    .unwrap_or(false);

                return Err(TxAttemptResult::Failed {
                    nonce,
                    failure_type: FailureType::PreBroadcast,
                    error: sim_error,
                    nonce_released,
                });
            }

            // Step 2: Broadcast
            match broadcast(nonce).await {
                Ok((tx_hash, signed_raw_tx, gas_price)) => {
                    // Persist signed bytes (durable tracker row) then mark broadcast.
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
                            nonce,
                            tx_hash = ?tx_hash,
                            error = %e,
                            "Failed to record signed tx (tx was broadcast!)"
                        );
                    } else if let Err(e) =
                        self.manager.mark_broadcast(address, nonce, tx_hash).await
                    {
                        error!(
                            nonce,
                            tx_hash = ?tx_hash,
                            error = %e,
                            "Failed to mark broadcast (tx was broadcast!)"
                        );
                    }

                    info!(wallet = ?address, nonce, tx_hash = ?tx_hash, "Transaction broadcast successfully");
                    return Ok((nonce, tx_hash));
                }

                Err(broadcast_error) => {
                    let failure_type = classify_error(&broadcast_error);

                    if failure_type == FailureType::Transient {
                        transient_attempts += 1;
                        if transient_attempts < self.retry_config.max_transient_retries {
                            let delay = self.calculate_backoff(transient_attempts);
                            debug!(
                                nonce,
                                attempt = transient_attempts,
                                "Transient broadcast failure, retrying"
                            );
                            sleep(delay).await;
                            continue;
                        }
                    }

                    return Err(TxAttemptResult::Failed {
                        nonce,
                        failure_type,
                        error: broadcast_error,
                        nonce_released: false, // Can't release after broadcast attempt
                    });
                }
            }
        }
    }

    fn calculate_backoff(&self, attempt: u32) -> Duration {
        let delay = self.retry_config.base_retry_delay * 2u32.pow(attempt.saturating_sub(1));
        std::cmp::min(delay, self.retry_config.max_retry_delay)
    }
}
