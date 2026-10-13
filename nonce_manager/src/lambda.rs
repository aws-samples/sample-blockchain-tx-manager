//! Lambda-optimized transaction submission
//!
//! Designed for the pattern where:
//! - Lambda reserves nonce, simulates, broadcasts, records pending, then exits
//! - Separate long-running process watches for finalization and updates state
//!
//! Lambda terminates after mempool acceptance — does NOT wait for on-chain confirmation.

use crate::error::Result;
use crate::manager::DynamoNonceManager;
use crate::retry::FailureType;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use std::future::Future;
use tracing::{debug, error, info, warn};

/// Result of Lambda transaction submission
#[derive(Debug)]
pub enum LambdaSubmitResult {
    /// Transaction accepted into mempool - Lambda can exit
    /// The finalizer process will handle confirmation tracking
    Accepted { nonce: u64, tx_hash: B256 },
    /// Simulation failed - nonce was released, can retry
    SimulationFailed {
        nonce: u64,
        error: String,
        nonce_released: bool,
    },
    /// Broadcast failed - nonce may be burned depending on error
    BroadcastFailed {
        nonce: u64,
        error: String,
        failure_type: FailureType,
    },
    /// Could not reserve nonce (max pending exceeded, etc.)
    ReservationFailed { error: String },
}

impl LambdaSubmitResult {
    pub fn is_accepted(&self) -> bool {
        matches!(self, LambdaSubmitResult::Accepted { .. })
    }

    pub fn should_retry_with_fresh_nonce(&self) -> bool {
        match self {
            // Simulation failure releases the nonce when possible. Either way, the retry
            // must go through reserve_nonce again: when release succeeded the nonce is in
            // the shared gap pool and another invocation may claim it, so reusing it
            // directly would race that caller. Reservation atomically reclaims the gap.
            LambdaSubmitResult::SimulationFailed { .. } => true,
            LambdaSubmitResult::BroadcastFailed { failure_type, .. } => {
                // Only a provably-unspent rejection (rejected before mempool admission)
                // is safe to retry under a fresh nonce. NodeRejected is deliberately
                // excluded: `already known` / `replacement transaction underpriced` mean
                // a transaction already occupies the slot, so broadcasting again under a
                // new nonce would double-submit the intent (M2). Those are left pending
                // for the watcher to reconcile.
                matches!(failure_type, FailureType::OnChainRevert)
            }
            _ => false,
        }
    }

    pub fn can_retry_same_nonce(&self) -> bool {
        match self {
            LambdaSubmitResult::BroadcastFailed { failure_type, .. } => {
                // An ambiguous (Transient) broadcast may already be in the mempool. The
                // reserved nonce is still pending, so the retry MUST reuse it — a repeated
                // raw send at the same nonce is a replacement, never a second transaction.
                matches!(failure_type, FailureType::Transient)
            }
            _ => false,
        }
    }
}

/// Lambda-optimized executor
///
/// Single-shot execution: reserve → simulate → broadcast → record → exit
/// No waiting for on-chain confirmation.
pub struct LambdaExecutor<P>
where
    P: Provider + Clone,
{
    manager: DynamoNonceManager<P>,
}

impl<P> LambdaExecutor<P>
where
    P: Provider + Clone,
{
    pub fn new(manager: DynamoNonceManager<P>) -> Self {
        Self { manager }
    }

    /// Submit a transaction - returns after mempool acceptance
    ///
    /// Flow:
    /// 1. Reserve nonce atomically
    /// 2. Call simulate_fn - if fails, release nonce
    /// 3. Call broadcast_fn - if succeeds, record as pending
    /// 4. Return immediately - Lambda can exit
    ///
    /// The separate finalizer process will:
    /// - Watch for on-chain confirmation
    /// - Call manager.confirm_transaction() on success, and also on a mined revert or a
    ///   dropped transaction: in all three cases the chain has spent the nonce, so the
    ///   slot is retired rather than returned to the gap pool
    /// - Call manager.mark_failed() only when the nonce was never spent on-chain
    pub async fn submit<S, B, C, SF, BF>(
        &self,
        address: Address,
        simulate: S,
        broadcast: B,
        classify_error: C,
    ) -> LambdaSubmitResult
    where
        S: FnOnce(u64) -> SF,
        SF: Future<Output = std::result::Result<(), String>>,
        B: FnOnce(u64) -> BF,
        BF: Future<Output = std::result::Result<(B256, Vec<u8>, U256), String>>,
        C: Fn(&str) -> FailureType,
    {
        // Step 1: Reserve nonce
        let nonce = match self.manager.reserve_nonce(address).await {
            Ok(n) => n,
            Err(e) => {
                return LambdaSubmitResult::ReservationFailed {
                    error: e.to_string(),
                };
            }
        };

        debug!(wallet = ?address, nonce, "Nonce reserved");

        self.submit_with_nonce(address, nonce, simulate, broadcast, classify_error)
            .await
    }

    /// Run simulate -> broadcast -> record for an **already reserved** nonce.
    ///
    /// Split out from `submit` so that `submit_with_retry` can re-drive an ambiguous
    /// broadcast against the *same* reserved nonce instead of reserving a fresh one
    /// (M2). Never reserves a nonce itself.
    async fn submit_with_nonce<S, B, C, SF, BF>(
        &self,
        address: Address,
        nonce: u64,
        simulate: S,
        broadcast: B,
        classify_error: C,
    ) -> LambdaSubmitResult
    where
        S: FnOnce(u64) -> SF,
        SF: Future<Output = std::result::Result<(), String>>,
        B: FnOnce(u64) -> BF,
        BF: Future<Output = std::result::Result<(B256, Vec<u8>, U256), String>>,
        C: Fn(&str) -> FailureType,
    {
        // Step 2: Simulate
        if let Err(sim_error) = simulate(nonce).await {
            warn!(wallet = ?address, nonce, error = %sim_error, "Simulation failed");

            let nonce_released = self
                .manager
                .release_nonce(address, nonce)
                .await
                .unwrap_or(false);

            return LambdaSubmitResult::SimulationFailed {
                nonce,
                error: sim_error,
                nonce_released,
            };
        }

        debug!(wallet = ?address, nonce, "Simulation passed");

        // Step 3: Broadcast
        let (tx_hash, signed_raw_tx, gas_price) = match broadcast(nonce).await {
            Ok(result) => result,
            Err(broadcast_error) => {
                let failure_type = classify_error(&broadcast_error);

                error!(
                    wallet = ?address,
                    nonce,
                    error = %broadcast_error,
                    failure_type = ?failure_type,
                    "Broadcast failed"
                );

                // Nonce disposition depends on whether the slot survived the broadcast.
                // A broadcast error is NEVER treated as confirmation: none of these arms
                // call `confirm_transaction`, so a broadcast failure can never advance the
                // confirmed watermark. Only the watcher, observing the chain, may confirm.
                match failure_type {
                    // The node already holds, or has moved past, a transaction in this
                    // nonce slot: `nonce too low` (chain-consumed) or `already known` /
                    // `replacement transaction underpriced` (mempool-occupied). The slot
                    // is not ours to reuse, so it must NOT be recycled into the gap pool
                    // (that would re-serve a rejected nonce and livelock the wallet), and
                    // it must NOT be confirmed (we have not observed it mine). Leave it
                    // pending; the watcher reconciles it — a real mine confirms it, and
                    // dropped-tx detection retires a chain-passed nonce as consumed.
                    FailureType::NodeRejected => {}
                    // The node rejected the transaction before mempool admission
                    // (insufficient funds, revert, block gas limit, unsupported type), so
                    // this nonce was never spent on-chain and is safe to reuse. The C3
                    // guard in REGISTER_GAP still refuses it if it is below confirmed.
                    FailureType::OnChainRevert => {
                        if let Err(e) = self.manager.mark_failed(address, nonce).await {
                            error!(
                                wallet = ?address,
                                nonce,
                                error = %e,
                                "Failed to return unspent nonce to the gap pool"
                            );
                        }
                    }
                    // Transient/Stuck/PreBroadcast: we cannot tell whether the
                    // transaction reached the mempool, so the nonce stays pending and
                    // `submit_with_retry` re-sends under the SAME nonce. Releasing or
                    // reserving anew here would risk a double-broadcast.
                    FailureType::PreBroadcast | FailureType::Stuck | FailureType::Transient => {}
                }

                return LambdaSubmitResult::BroadcastFailed {
                    nonce,
                    error: broadcast_error,
                    failure_type,
                };
            }
        };

        // Step 4: Record the signed bytes durably, then mark broadcast (for finalizer).
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
            // TX was broadcast but we failed to record it.
            // Log error but still return success - TX is in mempool.
            error!(
                wallet = ?address,
                nonce,
                tx_hash = ?tx_hash,
                error = %e,
                "Failed to record signed TX (TX was broadcast!)"
            );
        } else if let Err(e) = self.manager.mark_broadcast(address, nonce, tx_hash).await {
            error!(
                wallet = ?address,
                nonce,
                tx_hash = ?tx_hash,
                error = %e,
                "Failed to mark broadcast (TX was broadcast!)"
            );
        }

        info!(
            wallet = ?address,
            nonce,
            tx_hash = ?tx_hash,
            "Transaction accepted into mempool"
        );

        // Lambda can exit now - finalizer will handle confirmation
        LambdaSubmitResult::Accepted { nonce, tx_hash }
    }

    /// Submit with automatic retry on transient failures
    ///
    /// A nonce is reserved **once**. On an ambiguous (Transient) broadcast failure the
    /// retry re-drives simulate + broadcast against that SAME nonce — never reserving
    /// N+1 — because the first send may already be in the mempool; a repeated raw send at
    /// the same nonce is a replacement, not a second transaction (M2). A fresh nonce is
    /// reserved only for failures that provably did not consume the current one
    /// (pre-broadcast simulation failure without release, or an unspent node rejection).
    pub async fn submit_with_retry<S, B, C, SF, BF>(
        &self,
        address: Address,
        max_retries: u32,
        simulate: S,
        broadcast: B,
        classify_error: C,
    ) -> LambdaSubmitResult
    where
        S: Fn(u64) -> SF + Clone,
        SF: Future<Output = std::result::Result<(), String>>,
        B: Fn(u64) -> BF + Clone,
        BF: Future<Output = std::result::Result<(B256, Vec<u8>, U256), String>>,
        C: Fn(&str) -> FailureType + Clone,
    {
        let mut attempts = 0;

        // Reserve the nonce a single time up front. Retries reuse or re-reserve it
        // explicitly below; the retry loop must never implicitly reserve N+1.
        let mut nonce = match self.manager.reserve_nonce(address).await {
            Ok(n) => n,
            Err(e) => {
                return LambdaSubmitResult::ReservationFailed {
                    error: e.to_string(),
                };
            }
        };

        loop {
            let result = self
                .submit_with_nonce(
                    address,
                    nonce,
                    simulate.clone(),
                    broadcast.clone(),
                    classify_error.clone(),
                )
                .await;

            match &result {
                LambdaSubmitResult::Accepted { .. } => return result,

                LambdaSubmitResult::SimulationFailed { .. }
                | LambdaSubmitResult::BroadcastFailed { .. } => {
                    attempts += 1;

                    if attempts >= max_retries {
                        warn!(attempts, "Max retries exceeded");
                        return result;
                    }

                    if result.can_retry_same_nonce() {
                        // Ambiguous broadcast: the reserved nonce is still pending. Reuse
                        // it verbatim — a re-send at the same nonce cannot double-submit.
                        debug!(nonce, attempts, "Retrying transaction on the same nonce");
                        continue;
                    }

                    if result.should_retry_with_fresh_nonce() {
                        // Provably did not consume the nonce (pre-broadcast failure).
                        // Reserve a fresh one; a released simulation nonce is picked back
                        // up from the gap pool by this reservation.
                        match self.manager.reserve_nonce(address).await {
                            Ok(n) => {
                                nonce = n;
                                debug!(nonce, attempts, "Retrying transaction with a fresh nonce");
                                continue;
                            }
                            Err(e) => {
                                return LambdaSubmitResult::ReservationFailed {
                                    error: e.to_string(),
                                };
                            }
                        }
                    }

                    return result;
                }

                LambdaSubmitResult::ReservationFailed { .. } => return result,
            }
        }
    }

    /// Get reference to underlying manager
    pub fn manager(&self) -> &DynamoNonceManager<P> {
        &self.manager
    }
}

/// Data structure for finalizer to query pending transactions
#[derive(Debug)]
pub struct PendingTxQuery {
    pub address: Address,
    pub nonce: u64,
    pub tx_hash: B256,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub age_seconds: u64,
}

impl<P> DynamoNonceManager<P>
where
    P: Provider + Clone,
{
    /// Get all pending transactions for finalizer processing
    ///
    /// Returns transactions ordered by nonce (oldest first)
    pub async fn get_pending_for_finalization(
        &self,
        address: Address,
    ) -> Result<Vec<PendingTxQuery>> {
        let pending = self.get_all_pending(address).await?;

        let now = chrono::Utc::now();
        let mut queries: Vec<PendingTxQuery> = pending
            .into_iter()
            .map(|tx| {
                let age = now.signed_duration_since(tx.timestamp);
                PendingTxQuery {
                    address,
                    nonce: tx.nonce,
                    tx_hash: tx.tx_hash,
                    timestamp: tx.timestamp,
                    age_seconds: age.num_seconds().max(0) as u64,
                }
            })
            .collect();

        queries.sort_by_key(|q| q.nonce);
        Ok(queries)
    }

    /// Batch confirm multiple transactions (for finalizer efficiency)
    ///
    /// Processes all nonces even if some fail. Returns the first error
    /// encountered (if any) after attempting all nonces, so that a DynamoDB
    /// error on nonce 3 doesn't leave nonces 4-6 unconfirmed.
    ///
    /// Nonces are sorted ascending first. The watermark drain in `CONFIRM_TX` (H4) makes
    /// confirmation order-independent for correctness, but confirming in ascending order
    /// lets the watermark advance directly instead of parking every entry in the
    /// out-of-order set and draining afterwards — a cheaper path and a secondary
    /// mitigation for callers that pass an unordered set (e.g. HashMap iteration).
    pub async fn batch_confirm(&self, address: Address, nonces: &[u64]) -> Result<()> {
        let mut sorted = nonces.to_vec();
        sorted.sort_unstable();
        let mut first_error: Option<crate::error::NonceError> = None;
        for nonce in sorted {
            if let Err(e) = self.confirm_transaction(address, nonce).await {
                warn!(wallet = ?address, nonce, error = %e, "Failed to confirm nonce in batch");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Batch mark failed (for finalizer efficiency)
    ///
    /// Processes all nonces even if some fail. Returns the first error
    /// encountered (if any) after attempting all nonces.
    pub async fn batch_mark_failed(&self, address: Address, nonces: &[u64]) -> Result<()> {
        let mut first_error: Option<crate::error::NonceError> = None;
        for &nonce in nonces {
            if let Err(e) = self.mark_failed(address, nonce).await {
                warn!(wallet = ?address, nonce, error = %e, "Failed to mark nonce failed in batch");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Pure decision-logic tests for `LambdaSubmitResult` — no DynamoDB endpoint, no
    //! AWS calls, never skipped. These pin the nonce-disposition contract (M2): an
    //! ambiguous broadcast retries the SAME nonce, only a provably-unspent rejection
    //! reserves a fresh one, and confirmation is never inferred from a broadcast error.

    use super::*;
    use alloy::primitives::B256;

    fn broadcast_failed(ft: FailureType) -> LambdaSubmitResult {
        LambdaSubmitResult::BroadcastFailed {
            nonce: 7,
            error: "x".to_string(),
            failure_type: ft,
        }
    }

    #[test]
    fn accepted_is_terminal_and_not_retryable() {
        let r = LambdaSubmitResult::Accepted {
            nonce: 1,
            tx_hash: B256::ZERO,
        };
        assert!(r.is_accepted());
        assert!(!r.can_retry_same_nonce());
        assert!(!r.should_retry_with_fresh_nonce());
    }

    #[test]
    fn transient_broadcast_retries_same_nonce_never_fresh() {
        let r = broadcast_failed(FailureType::Transient);
        assert!(
            r.can_retry_same_nonce(),
            "ambiguous send must reuse the nonce"
        );
        assert!(
            !r.should_retry_with_fresh_nonce(),
            "a fresh nonce here would double-submit the intent"
        );
    }

    #[test]
    fn node_rejected_is_left_pending_neither_retry_path() {
        // `already known` / `replacement underpriced`: the slot is occupied/consumed —
        // never reuse the nonce and never reserve a new one; leave it for the watcher.
        let r = broadcast_failed(FailureType::NodeRejected);
        assert!(!r.can_retry_same_nonce());
        assert!(!r.should_retry_with_fresh_nonce());
    }

    #[test]
    fn on_chain_revert_is_unspent_and_takes_a_fresh_nonce() {
        // Rejected before mempool admission (insufficient funds, revert): nonce unspent,
        // safe to reserve a fresh one.
        let r = broadcast_failed(FailureType::OnChainRevert);
        assert!(r.should_retry_with_fresh_nonce());
        assert!(!r.can_retry_same_nonce());
    }

    #[test]
    fn simulation_failure_retries_with_fresh_nonce() {
        let r = LambdaSubmitResult::SimulationFailed {
            nonce: 3,
            error: "revert".to_string(),
            nonce_released: true,
        };
        assert!(
            r.should_retry_with_fresh_nonce(),
            "released simulation nonce is reclaimed via a fresh reserve"
        );
        assert!(!r.can_retry_same_nonce());
        assert!(!r.is_accepted());
    }

    #[test]
    fn reservation_failure_is_terminal() {
        let r = LambdaSubmitResult::ReservationFailed {
            error: "max pending".to_string(),
        };
        assert!(!r.is_accepted());
        assert!(!r.can_retry_same_nonce());
        assert!(!r.should_retry_with_fresh_nonce());
    }
}
