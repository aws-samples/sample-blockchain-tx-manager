//! Idempotency-key deduplication to prevent double-broadcast.
//!
//! SQS delivers at-least-once, so the same transaction request can arrive more
//! than once. Without dedup, each delivery reserves a fresh nonce and broadcasts
//! a *separate* transaction — a double-spend. This module implements claim-first
//! deduplication backed by DynamoDB conditional writes.
//!
//! A transaction only enters the mempool on an `Accepted` submit result; every
//! other outcome broadcasts nothing. So the only state a duplicate must never
//! re-run is a completed (accepted) one. The lifecycle is therefore:
//!
//! 1. [`IdempotencyClaim::claim`] writes an `IN_PROGRESS` record keyed on the
//!    idempotency key, conditional on the key not already existing. The record also
//!    carries a deterministic **request digest** so a later duplicate can be checked
//!    for equivalence. Winning the claim is the precondition for broadcasting.
//! 2. On acceptance the caller invokes [`IdempotencyClaim::complete`], storing the
//!    tx hash and nonce so later duplicates return that result verbatim.
//! 3. On any non-accepted outcome *that precedes the durable signed handoff* the
//!    caller invokes [`IdempotencyClaim::release`] to delete the claim, allowing a
//!    clean retry on redelivery. Once a transaction is durably signed the claim is
//!    never released — the SIGNED tracker row is the recovery handoff.
//!
//! A duplicate carrying the *same* idempotency key but a *different* request digest is
//! a client bug (key reuse across distinct transactions). It is rejected with a
//! non-retryable [`IDEMPOTENCY_CONFLICT`] rather than silently returning the first
//! transaction's result — the two requests are not the same operation.
//!
//! The dedup record reuses the transaction table with a sort key namespaced by
//! [`SK_PREFIX`], and deliberately omits the `status`/`chain_id` attributes so it
//! stays out of the watcher's sparse `status-chain-index` GSI.
//!
//! Lifecycle: `IN_PROGRESS` (claimed) → `HANDED_OFF` (exact signed bytes durable; result
//! hash/nonce fixed) → `COMPLETED` (handler returned). A duplicate that finds `HANDED_OFF`
//! gets the same accepted response as `COMPLETED`, so a Lambda that dies between the
//! durable handoff and `complete` does not redrive an already-successful transaction to
//! the dead-letter queue. Pre-broadcast failures delete the claim.

use crate::error::{LambdaError, Result};
use crate::types::TxResponse;
use alloy::primitives::B256;
use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::Utc;
use std::collections::HashMap;

const SECONDS_PER_DAY: i64 = 86_400;

/// Sort-key prefix that namespaces dedup records away from real transaction
/// records (whose sort key is a `0x…` transaction hash).
const SK_PREFIX: &str = "idem#";

const STATUS_IN_PROGRESS: &str = "IN_PROGRESS";
/// The exact signed bytes are durable (`record_signed` succeeded) and the result hash and
/// nonce are known. From here the outcome for the caller is fixed regardless of whether
/// this invocation lives long enough to reach `complete`: the watcher owns delivery.
const STATUS_HANDED_OFF: &str = "HANDED_OFF";
const STATUS_COMPLETED: &str = "COMPLETED";
/// Tracker status written by `reject_signed`; a handed-off claim pointing at such a row is
/// stale (the retire succeeded but the release did not) and must not masquerade as success.
const TRACKER_STATUS_REJECTED: &str = "REJECTED";

/// Error code returned when an idempotency key is reused for a different request.
pub const IDEMPOTENCY_CONFLICT: &str = "IDEMPOTENCY_CONFLICT";

/// Outcome of attempting to claim an idempotency key.
pub enum ClaimOutcome {
    /// This invocation owns the claim and must proceed to broadcast.
    Claimed,
    /// A duplicate request: return this response instead of broadcasting again.
    Duplicate(TxResponse),
}

/// A single wallet+key idempotency claim against the transaction table.
pub struct IdempotencyClaim<'a> {
    client: &'a DynamoClient,
    table: &'a str,
    wallet: String,
    sort_key: String,
    request_digest: String,
}

impl<'a> IdempotencyClaim<'a> {
    /// Build a claim handle for `wallet` (any case) and idempotency `key`, bound to a
    /// deterministic `request_digest` of the transaction it represents.
    pub fn new(
        client: &'a DynamoClient,
        table: &'a str,
        wallet: &str,
        key: &str,
        request_digest: String,
    ) -> Self {
        Self {
            client,
            table,
            wallet: wallet.to_lowercase(),
            sort_key: format!("{SK_PREFIX}{key}"),
            request_digest,
        }
    }

    /// Attempt to claim the key. Returns [`ClaimOutcome::Claimed`] if this is the
    /// first time the key is seen, or [`ClaimOutcome::Duplicate`] (carrying the
    /// response to return) if another invocation already claimed it.
    pub async fn claim(&self, ttl_days: i64) -> Result<ClaimOutcome> {
        let now = Utc::now();
        let ttl = now.timestamp() + ttl_days * SECONDS_PER_DAY;

        let put = self
            .client
            .put_item()
            .table_name(self.table)
            .item("wallet", AttributeValue::S(self.wallet.clone()))
            .item("tx_hash", AttributeValue::S(self.sort_key.clone()))
            .item(
                "idem_status",
                AttributeValue::S(STATUS_IN_PROGRESS.to_string()),
            )
            .item(
                "request_digest",
                AttributeValue::S(self.request_digest.clone()),
            )
            .item("created_at", AttributeValue::S(now.to_rfc3339()))
            .item("ttl", AttributeValue::N(ttl.to_string()))
            .condition_expression("attribute_not_exists(tx_hash)")
            .send()
            .await;

        match put {
            Ok(_) => Ok(ClaimOutcome::Claimed),
            Err(e) if is_conditional_check_failure(&e) => self.lookup_existing().await,
            Err(e) => Err(LambdaError::Aws(format!("idempotency claim failed: {e}"))),
        }
    }

    /// Record the durable signed handoff: the result hash and nonce are now fixed even if
    /// this invocation dies before `complete`. Call immediately after `record_signed`.
    /// Best effort — a failure here only degrades to the pre-handoff behaviour (a
    /// duplicate sees `IN_PROGRESS` and is retried).
    pub async fn record_handoff(&self, tx_hash: B256, nonce: u64) -> Result<()> {
        self.set_result(STATUS_HANDED_OFF, tx_hash, nonce).await
    }

    /// Persist the accepted result so duplicates return it without re-broadcasting.
    pub async fn complete(&self, tx_hash: B256, nonce: u64) -> Result<()> {
        self.set_result(STATUS_COMPLETED, tx_hash, nonce).await
    }

    async fn set_result(&self, status: &str, tx_hash: B256, nonce: u64) -> Result<()> {
        self.client
            .update_item()
            .table_name(self.table)
            .key("wallet", AttributeValue::S(self.wallet.clone()))
            .key("tx_hash", AttributeValue::S(self.sort_key.clone()))
            .update_expression(
                "SET idem_status = :st, result_tx_hash = :hash, result_nonce = :nonce",
            )
            .expression_attribute_values(":st", AttributeValue::S(status.to_string()))
            .expression_attribute_values(":hash", AttributeValue::S(tx_hash.to_string()))
            .expression_attribute_values(":nonce", AttributeValue::N(nonce.to_string()))
            .send()
            .await
            .map_err(|e| LambdaError::Aws(format!("idempotency {status} failed: {e}")))?;
        Ok(())
    }

    /// Delete the claim after a non-accepted outcome so a redelivery can retry.
    ///
    /// Winning the claim means this invocation created a fresh `IN_PROGRESS`
    /// record, so an unconditional delete only ever removes our own claim.
    pub async fn release(&self) -> Result<()> {
        self.client
            .delete_item()
            .table_name(self.table)
            .key("wallet", AttributeValue::S(self.wallet.clone()))
            .key("tx_hash", AttributeValue::S(self.sort_key.clone()))
            .send()
            .await
            .map_err(|e| LambdaError::Aws(format!("idempotency release failed: {e}")))?;
        Ok(())
    }

    /// Read the existing record after a lost claim and map it to a response.
    async fn lookup_existing(&self) -> Result<ClaimOutcome> {
        let resp = self
            .client
            .get_item()
            .table_name(self.table)
            .key("wallet", AttributeValue::S(self.wallet.clone()))
            .key("tx_hash", AttributeValue::S(self.sort_key.clone()))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| LambdaError::Aws(format!("idempotency lookup failed: {e}")))?;

        // The claim may have been deleted (TTL or a concurrent release) between the
        // failed put and this read; treat that as in-progress so SQS redelivers.
        let Some(item) = resp.item else {
            return Ok(ClaimOutcome::Duplicate(in_progress_response()));
        };

        // A key reused for a *different* request is a client bug, not a legitimate
        // retry. Reject it rather than returning the first transaction's result.
        let stored_digest = item.get("request_digest").and_then(|v| v.as_s().ok());
        if digest_conflicts(stored_digest.map(String::as_str), &self.request_digest) {
            return Ok(ClaimOutcome::Duplicate(conflict_response()));
        }

        match item
            .get("idem_status")
            .and_then(|v| v.as_s().ok())
            .map(String::as_str)
        {
            Some(STATUS_COMPLETED) => Ok(ClaimOutcome::Duplicate(completed_response(&item))),
            Some(STATUS_HANDED_OFF) => {
                // The signed bytes are durable and the watcher owns delivery, so the
                // caller's outcome is the same as the original accepted response — unless
                // the node definitively rejected the first send and the invocation died
                // after retiring the row but before releasing this claim. Check the
                // tracker row; a REJECTED row means this claim is stale: drop it so the
                // redelivery claims afresh instead of reporting a dead hash as success.
                if self.handoff_was_rejected(&item).await? {
                    self.release().await?;
                    return Ok(ClaimOutcome::Duplicate(in_progress_response()));
                }
                Ok(ClaimOutcome::Duplicate(completed_response(&item)))
            }
            _ => Ok(ClaimOutcome::Duplicate(in_progress_response())),
        }
    }

    /// Whether the tracker row a handed-off claim points at has been marked REJECTED.
    async fn handoff_was_rejected(&self, item: &HashMap<String, AttributeValue>) -> Result<bool> {
        let Some(hash) = item.get("result_tx_hash").and_then(|v| v.as_s().ok()) else {
            return Ok(false);
        };
        let resp = self
            .client
            .get_item()
            .table_name(self.table)
            .key("wallet", AttributeValue::S(self.wallet.clone()))
            .key("tx_hash", AttributeValue::S(hash.to_lowercase()))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| LambdaError::Aws(format!("handoff tracker lookup failed: {e}")))?;
        Ok(resp
            .item
            .and_then(|i| i.get("status").and_then(|v| v.as_s().ok()).cloned())
            .is_some_and(|st| st == TRACKER_STATUS_REJECTED))
    }
}

/// Whether a stored digest conflicts with the current request's digest.
///
/// A conflict requires a *present* stored digest that differs. A missing stored digest
/// (legacy record written before digests were tracked, or a mid-write race) is treated
/// as non-conflicting so recovery/idempotency proceed rather than hard-failing.
pub fn digest_conflicts(stored: Option<&str>, current: &str) -> bool {
    matches!(stored, Some(s) if s != current)
}

/// Whether a `PutItem` error is a `ConditionalCheckFailedException` (key exists).
fn is_conditional_check_failure<R>(err: &SdkError<PutItemError, R>) -> bool {
    err.as_service_error()
        .is_some_and(|e| e.is_conditional_check_failed_exception())
}

/// Retryable response telling SQS to redeliver while the original is in flight.
fn in_progress_response() -> TxResponse {
    TxResponse::error_with_code(
        "Duplicate request already in progress; retry later".to_string(),
        "DUPLICATE_IN_PROGRESS",
        true,
    )
}

/// Non-retryable response for an idempotency key reused with a different request body.
fn conflict_response() -> TxResponse {
    TxResponse::error_with_code(
        "Idempotency key was already used for a different request".to_string(),
        IDEMPOTENCY_CONFLICT,
        false,
    )
}

/// Reconstruct the original success response from a completed dedup record.
fn completed_response(item: &HashMap<String, AttributeValue>) -> TxResponse {
    let tx_hash = item
        .get("result_tx_hash")
        .and_then(|v| v.as_s().ok())
        .and_then(|s| s.parse::<B256>().ok());
    let nonce = item
        .get("result_nonce")
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse::<u64>().ok());

    match (tx_hash, nonce) {
        (Some(hash), Some(nonce)) => TxResponse::success(hash, nonce),
        _ => TxResponse::error_with_code(
            "Duplicate completed but stored result is unreadable".to_string(),
            "DUPLICATE_COMPLETED",
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(pairs: &[(&str, AttributeValue)]) -> HashMap<String, AttributeValue> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn completed_response_reconstructs_original_success() {
        let hash = B256::repeat_byte(0xab);
        let resp = completed_response(&item(&[
            ("result_tx_hash", AttributeValue::S(hash.to_string())),
            ("result_nonce", AttributeValue::N("42".to_string())),
        ]));

        assert!(resp.success);
        assert_eq!(resp.tx_hash, Some(hash));
        assert_eq!(resp.nonce, Some(42));
        assert!(!resp.retryable);
    }

    #[test]
    fn completed_response_never_fabricates_success_from_partial_record() {
        // A record missing the nonce must not yield a fake success — it would
        // tell the caller a transaction landed when we cannot prove which one.
        let resp = completed_response(&item(&[(
            "result_tx_hash",
            AttributeValue::S(B256::repeat_byte(1).to_string()),
        )]));

        assert!(!resp.success);
        assert_eq!(resp.error_code.as_deref(), Some("DUPLICATE_COMPLETED"));
        assert!(!resp.retryable);
    }

    #[test]
    fn in_progress_response_is_retryable() {
        // An in-flight duplicate must be retryable so SQS redelivers it after
        // the original invocation finishes (and records the result).
        let resp = in_progress_response();
        assert!(!resp.success);
        assert!(resp.retryable);
        assert_eq!(resp.error_code.as_deref(), Some("DUPLICATE_IN_PROGRESS"));
    }

    #[test]
    fn digest_conflict_only_when_present_and_different() {
        // Same digest → legitimate retry, no conflict.
        assert!(!digest_conflicts(Some("abc"), "abc"));
        // Different digest → key reused for a different request → conflict.
        assert!(digest_conflicts(Some("abc"), "def"));
        // Missing stored digest (legacy/mid-write) → do not hard-fail.
        assert!(!digest_conflicts(None, "abc"));
    }

    #[test]
    fn conflict_response_is_non_retryable_with_conflict_code() {
        // A reused key on a different request is a client bug: never retryable, and
        // never surfaced as the first transaction's success.
        let resp = conflict_response();
        assert!(!resp.success);
        assert!(!resp.retryable);
        assert_eq!(resp.error_code.as_deref(), Some(IDEMPOTENCY_CONFLICT));
        assert!(resp.tx_hash.is_none());
    }
}
