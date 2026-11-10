//! DynamoDB transaction store for tracking pending transactions

use crate::error::{Result, WatcherError};
use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Transaction status in the store
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TxStatus {
    /// Raw transaction signed and durably recorded, but broadcast is not yet confirmed.
    /// The exact signed bytes are stored so the watcher can rebroadcast them verbatim.
    Signed,
    Pending,
    Mined,
    Confirmed,
    Failed,
    Dropped,
    Replaced,
    /// Transaction was confirmed but reverted due to chain reorganization
    Reorged,
    /// The node definitively refused the first broadcast (funds/fees/gas/encoding); the
    /// bytes never entered a mempool and the nonce was recycled. Terminal.
    Rejected,
}

impl TxStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TxStatus::Signed => "SIGNED",
            TxStatus::Pending => "PENDING",
            TxStatus::Mined => "MINED",
            TxStatus::Confirmed => "CONFIRMED",
            TxStatus::Failed => "FAILED",
            TxStatus::Dropped => "DROPPED",
            TxStatus::Replaced => "REPLACED",
            TxStatus::Reorged => "REORGED",
            TxStatus::Rejected => "REJECTED",
        }
    }

    /// Parse a status from its canonical uppercase wire form.
    ///
    /// Returns `None` for an unknown or missing status. The watcher must never silently
    /// treat an unrecognized status as `PENDING`: doing so could resurrect a terminal
    /// transaction or act on a row it does not understand. Callers drop rows that fail
    /// to parse (see [`TxStore::item_to_record`]).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "SIGNED" => Some(TxStatus::Signed),
            "PENDING" => Some(TxStatus::Pending),
            "MINED" => Some(TxStatus::Mined),
            "CONFIRMED" => Some(TxStatus::Confirmed),
            "FAILED" => Some(TxStatus::Failed),
            "DROPPED" => Some(TxStatus::Dropped),
            "REPLACED" => Some(TxStatus::Replaced),
            "REORGED" => Some(TxStatus::Reorged),
            "REJECTED" => Some(TxStatus::Rejected),
            _ => None,
        }
    }
}

/// Parse the `signed_raw_tx` attribute strictly from a `0x`-prefixed hex string.
///
/// Returns `None` unless the value has a `0x` prefix, a non-empty even-length hex body,
/// and decodes cleanly. Strictness matters: the bytes are rebroadcast verbatim and their
/// keccak hash is compared against the stored tx hash, so a malformed value must be
/// rejected rather than coerced.
pub fn parse_signed_raw_tx(s: &str) -> Option<Vec<u8>> {
    let body = s.strip_prefix("0x")?;
    if body.is_empty() {
        return None;
    }
    alloy::hex::decode(body).ok()
}

/// Transaction record stored in DynamoDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    pub wallet: String,
    pub tx_hash: String,
    pub nonce: u64,
    pub status: TxStatus,
    pub chain_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// Block hash where transaction was mined (for reorg detection)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    #[serde(default)]
    pub confirmations: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<String>,

    /// Same-nonce replacement metadata. Legacy rows have no family_nonce and are treated
    /// as active; inactive siblings remain receipt-tracked but are never re-injected.
    #[serde(default)]
    pub family_nonce: Option<u64>,
    #[serde(default)]
    pub replacement_generation: Option<u32>,
    #[serde(default)]
    pub replacement_active: Option<bool>,
    #[serde(default)]
    pub next_eligible_replacement_block: Option<u64>,
    #[serde(default)]
    pub replacement_max_bumps: Option<u32>,
    #[serde(default)]
    pub replacement_on_exhaust: Option<String>,
    #[serde(default)]
    pub replacement_action: Option<String>,
    #[serde(default)]
    pub replacement_exhausted: Option<bool>,
    /// Exact signed raw transaction bytes (present on SIGNED rows), decoded from the
    /// stored `0x` hex. Required for verbatim rebroadcast of a SIGNED transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_raw_tx: Option<Vec<u8>>,
    pub submitted_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ttl: i64,
}

/// DynamoDB-backed transaction store
#[derive(Clone)]
pub struct TxStore {
    client: DynamoClient,
    table_name: String,
    index_name: String,
    ttl_days: i64,
}

impl TxStore {
    pub fn new(client: DynamoClient, table_name: String, ttl_days: i64) -> Self {
        Self {
            client,
            table_name,
            index_name: "status-chain-index".to_string(),
            ttl_days,
        }
    }

    /// Terminal-record TTL: `now + ttl_days`, in epoch seconds. Only terminal rows
    /// (CONFIRMED / FAILED / DROPPED / REPLACED) may carry a TTL; active rows
    /// (SIGNED / PENDING / MINED) and reservation rows must never expire.
    fn terminal_ttl(&self) -> i64 {
        Utc::now().timestamp() + self.ttl_days * 86_400
    }

    /// Query transactions by status using GSI (efficient)
    async fn query_by_status(&self, status: TxStatus, chain_id: u64) -> Result<Vec<TxRecord>> {
        let mut records = Vec::new();
        let mut last_key = None;

        loop {
            let mut query = self
                .client
                .query()
                .table_name(&self.table_name)
                .index_name(&self.index_name)
                .key_condition_expression("#status = :status AND chain_id = :chain")
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(
                    ":status",
                    AttributeValue::S(status.as_str().to_string()),
                )
                .expression_attribute_values(":chain", AttributeValue::N(chain_id.to_string()));

            if let Some(key) = last_key {
                query = query.set_exclusive_start_key(Some(key));
            }

            let result = query
                .send()
                .await
                .map_err(|e| WatcherError::Store(format!("GSI query failed: {}", e)))?;

            if let Some(items) = result.items {
                for item in items {
                    if let Some(record) = self.item_to_record(&item) {
                        records.push(record);
                    }
                }
            }

            last_key = result.last_evaluated_key;
            if last_key.is_none() {
                break;
            }
        }

        Ok(records)
    }

    /// Get all pending transactions (PENDING status) - uses GSI query
    #[allow(dead_code)]
    pub async fn get_pending_transactions(&self, chain_id: u64) -> Result<Vec<TxRecord>> {
        self.query_by_status(TxStatus::Pending, chain_id).await
    }

    /// Get all mined transactions awaiting confirmations - uses GSI query
    #[allow(dead_code)]
    pub async fn get_mined_transactions(&self, chain_id: u64) -> Result<Vec<TxRecord>> {
        self.query_by_status(TxStatus::Mined, chain_id).await
    }

    /// Get all active transactions: SIGNED (awaiting/retrying broadcast), PENDING
    /// (awaiting inclusion), and MINED (awaiting confirmations). Three GSI queries in
    /// parallel, all still efficient (sparse GSI, keyed by status).
    pub async fn get_active_transactions(&self, chain_id: u64) -> Result<Vec<TxRecord>> {
        let (signed, pending, mined) = tokio::join!(
            self.query_by_status(TxStatus::Signed, chain_id),
            self.query_by_status(TxStatus::Pending, chain_id),
            self.query_by_status(TxStatus::Mined, chain_id)
        );

        let mut records = signed?;
        records.extend(pending?);
        records.extend(mined?);
        Ok(records)
    }

    /// Update transaction status when mined.
    ///
    /// MINED is active, so no TTL is written. PENDING rows and inactive SIGNED
    /// replacement siblings are receipt-checked: an ambiguous earlier send may still win.
    pub async fn update_mined(
        &self,
        wallet: &str,
        tx_hash: &str,
        block_number: u64,
        block_hash: &str,
        success: bool,
        confirmations: u64,
    ) -> Result<()> {
        let now = Utc::now();

        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("wallet", AttributeValue::S(wallet.to_lowercase()))
            .key("tx_hash", AttributeValue::S(tx_hash.to_lowercase()))
            .update_expression("SET #status = :status, block_number = :block, block_hash = :bhash, success = :success, confirmations = :conf, updated_at = :updated")
            .condition_expression("#status = :pending OR #status = :signed")
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":status", AttributeValue::S(TxStatus::Mined.as_str().to_string()))
            .expression_attribute_values(":pending", AttributeValue::S(TxStatus::Pending.as_str().to_string()))
            .expression_attribute_values(":signed", AttributeValue::S(TxStatus::Signed.as_str().to_string()))
            .expression_attribute_values(":block", AttributeValue::N(block_number.to_string()))
            .expression_attribute_values(":bhash", AttributeValue::S(block_hash.to_lowercase()))
            .expression_attribute_values(":success", AttributeValue::Bool(success))
            .expression_attribute_values(":conf", AttributeValue::N(confirmations.to_string()))
            .expression_attribute_values(":updated", AttributeValue::S(now.to_rfc3339()))
            .send()
            .await
            .map_err(|e| WatcherError::Store(format!("Failed to update mined: {}", e)))?;

        Ok(())
    }

    /// Update confirmation count for mined transaction
    #[allow(dead_code)]
    pub async fn update_confirmations(
        &self,
        wallet: &str,
        tx_hash: &str,
        confirmations: u64,
    ) -> Result<()> {
        let now = Utc::now();

        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("wallet", AttributeValue::S(wallet.to_lowercase()))
            .key("tx_hash", AttributeValue::S(tx_hash.to_lowercase()))
            .update_expression("SET confirmations = :conf, updated_at = :updated")
            .expression_attribute_values(":conf", AttributeValue::N(confirmations.to_string()))
            .expression_attribute_values(":updated", AttributeValue::S(now.to_rfc3339()))
            .send()
            .await
            .map_err(|e| WatcherError::Store(format!("Failed to update confirmations: {}", e)))?;

        Ok(())
    }

    /// Mark transaction as confirmed (reached required confirmations). Terminal: sets TTL.
    pub async fn mark_confirmed(
        &self,
        wallet: &str,
        tx_hash: &str,
        confirmations: u64,
    ) -> Result<()> {
        let now = Utc::now();

        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("wallet", AttributeValue::S(wallet.to_lowercase()))
            .key("tx_hash", AttributeValue::S(tx_hash.to_lowercase()))
            .update_expression(
                "SET #status = :status, confirmations = :conf, updated_at = :updated, #ttl = :ttl",
            )
            .condition_expression("#status = :expected_status")
            .expression_attribute_names("#status", "status")
            .expression_attribute_names("#ttl", "ttl")
            .expression_attribute_values(
                ":status",
                AttributeValue::S(TxStatus::Confirmed.as_str().to_string()),
            )
            .expression_attribute_values(
                ":expected_status",
                AttributeValue::S(TxStatus::Mined.as_str().to_string()),
            )
            .expression_attribute_values(":conf", AttributeValue::N(confirmations.to_string()))
            .expression_attribute_values(":updated", AttributeValue::S(now.to_rfc3339()))
            .expression_attribute_values(":ttl", AttributeValue::N(self.terminal_ttl().to_string()))
            .send()
            .await
            .map_err(|e| WatcherError::Store(format!("Failed to mark confirmed: {}", e)))?;

        Ok(())
    }

    /// Mark transaction as failed (reverted on-chain). Terminal: sets TTL.
    pub async fn mark_failed(&self, wallet: &str, tx_hash: &str) -> Result<()> {
        let now = Utc::now();

        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("wallet", AttributeValue::S(wallet.to_lowercase()))
            .key("tx_hash", AttributeValue::S(tx_hash.to_lowercase()))
            .update_expression("SET #status = :status, updated_at = :updated, #ttl = :ttl")
            .condition_expression("#status IN (:pending, :mined)")
            .expression_attribute_names("#status", "status")
            .expression_attribute_names("#ttl", "ttl")
            .expression_attribute_values(
                ":status",
                AttributeValue::S(TxStatus::Failed.as_str().to_string()),
            )
            .expression_attribute_values(
                ":pending",
                AttributeValue::S(TxStatus::Pending.as_str().to_string()),
            )
            .expression_attribute_values(
                ":mined",
                AttributeValue::S(TxStatus::Mined.as_str().to_string()),
            )
            .expression_attribute_values(":updated", AttributeValue::S(now.to_rfc3339()))
            .expression_attribute_values(":ttl", AttributeValue::N(self.terminal_ttl().to_string()))
            .send()
            .await
            .map_err(|e| WatcherError::Store(format!("Failed to mark failed: {}", e)))?;

        Ok(())
    }

    /// Persist the last fully processed block for this chain so a restarted watcher can
    /// backfill reorg tracking instead of starting blind. Stored as a single row keyed
    /// `watcher#<chain_id>` / `cursor` with no `status`/`chain_id` attributes, so it is
    /// invisible to the `status-chain-index` GSI and to every transaction query.
    pub async fn save_cursor(&self, chain_id: u64, block_number: u64) -> Result<()> {
        self.client
            .put_item()
            .table_name(&self.table_name)
            .item("wallet", AttributeValue::S(format!("watcher#{chain_id}")))
            .item("tx_hash", AttributeValue::S("cursor".to_string()))
            .item("last_block", AttributeValue::N(block_number.to_string()))
            .item("updated_at", AttributeValue::S(Utc::now().to_rfc3339()))
            .send()
            .await
            .map_err(|e| WatcherError::Store(format!("Failed to save watcher cursor: {}", e)))?;
        Ok(())
    }

    /// Load the persisted cursor, if any.
    pub async fn load_cursor(&self, chain_id: u64) -> Result<Option<u64>> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("wallet", AttributeValue::S(format!("watcher#{chain_id}")))
            .key("tx_hash", AttributeValue::S("cursor".to_string()))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| WatcherError::Store(format!("Failed to load watcher cursor: {}", e)))?;
        Ok(out
            .item
            .and_then(|i| i.get("last_block").and_then(|v| v.as_n().ok().cloned()))
            .and_then(|n| n.parse::<u64>().ok()))
    }

    /// At reorg finality, mark any still-active losing same-nonce candidates REPLACED.
    /// Until this point they deliberately stay receipt-tracked because an earlier hash
    /// may still win after a later replacement was broadcast.
    pub async fn mark_family_siblings_replaced(
        &self,
        wallet: &str,
        family_nonce: u64,
        winner_hash: &str,
    ) -> Result<()> {
        let wallet = wallet.to_lowercase();
        let winner_hash = winner_hash.to_lowercase();
        let mut last_key = None;
        let mut siblings = Vec::new();
        loop {
            let mut query = self
                .client
                .query()
                .table_name(&self.table_name)
                .key_condition_expression("wallet = :wallet")
                .filter_expression("family_nonce = :nonce")
                .expression_attribute_values(":wallet", AttributeValue::S(wallet.clone()))
                .expression_attribute_values(":nonce", AttributeValue::N(family_nonce.to_string()));
            if let Some(key) = last_key {
                query = query.set_exclusive_start_key(Some(key));
            }
            let result = query
                .send()
                .await
                .map_err(|e| WatcherError::Store(format!("family sibling query failed: {e}")))?;
            for item in result.items.unwrap_or_default() {
                let Some(hash) = item
                    .get("tx_hash")
                    .and_then(|v| v.as_s().ok())
                    .filter(|h| h.to_lowercase() != winner_hash)
                else {
                    continue;
                };
                let active = item
                    .get("status")
                    .and_then(|v| v.as_s().ok())
                    .is_some_and(|s| s == "SIGNED" || s == "PENDING");
                if active {
                    siblings.push(hash.clone());
                }
            }
            last_key = result.last_evaluated_key;
            if last_key.is_none() {
                break;
            }
        }
        for hash in siblings {
            let now = Utc::now();
            let result = self
                .client
                .update_item()
                .table_name(&self.table_name)
                .key("wallet", AttributeValue::S(wallet.clone()))
                .key("tx_hash", AttributeValue::S(hash))
                .update_expression("SET #status = :replaced, updated_at = :updated, #ttl = :ttl")
                .condition_expression("#status = :signed OR #status = :pending")
                .expression_attribute_names("#status", "status")
                .expression_attribute_names("#ttl", "ttl")
                .expression_attribute_values(
                    ":replaced",
                    AttributeValue::S(TxStatus::Replaced.as_str().into()),
                )
                .expression_attribute_values(
                    ":signed",
                    AttributeValue::S(TxStatus::Signed.as_str().into()),
                )
                .expression_attribute_values(
                    ":pending",
                    AttributeValue::S(TxStatus::Pending.as_str().into()),
                )
                .expression_attribute_values(":updated", AttributeValue::S(now.to_rfc3339()))
                .expression_attribute_values(
                    ":ttl",
                    AttributeValue::N(self.terminal_ttl().to_string()),
                )
                .send()
                .await;
            if let Err(e) = result
                && !e
                    .as_service_error()
                    .is_some_and(|svc| svc.is_conditional_check_failed_exception())
            {
                return Err(WatcherError::Store(format!(
                    "failed to mark family sibling replaced: {e}"
                )));
            }
        }
        Ok(())
    }

    /// Mark transaction as dropped from mempool. Terminal: sets TTL.
    pub async fn mark_dropped(&self, wallet: &str, tx_hash: &str) -> Result<()> {
        let now = Utc::now();

        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("wallet", AttributeValue::S(wallet.to_lowercase()))
            .key("tx_hash", AttributeValue::S(tx_hash.to_lowercase()))
            .update_expression("SET #status = :status, updated_at = :updated, #ttl = :ttl")
            // A drop may be observed from either pre-mined active state: PENDING (broadcast
            // acked) or SIGNED (nonce consumed by a foreign hash before any ack). Never
            // from MINED/CONFIRMED — those go through the reorg path.
            .condition_expression("#status = :pending OR #status = :signed")
            .expression_attribute_names("#status", "status")
            .expression_attribute_names("#ttl", "ttl")
            .expression_attribute_values(
                ":status",
                AttributeValue::S(TxStatus::Dropped.as_str().to_string()),
            )
            .expression_attribute_values(
                ":pending",
                AttributeValue::S(TxStatus::Pending.as_str().to_string()),
            )
            .expression_attribute_values(
                ":signed",
                AttributeValue::S(TxStatus::Signed.as_str().to_string()),
            )
            .expression_attribute_values(":updated", AttributeValue::S(now.to_rfc3339()))
            .expression_attribute_values(":ttl", AttributeValue::N(self.terminal_ttl().to_string()))
            .send()
            .await
            .map_err(|e| WatcherError::Store(format!("Failed to mark dropped: {}", e)))?;

        Ok(())
    }

    /// Atomically reset a MINED or CONFIRMED transaction back to an active state after a
    /// reorg, in a single UpdateItem with a ConditionExpression.
    ///
    /// The reset target depends on whether the row carries the exact signed bytes:
    ///
    /// * `to_signed = true` (signed bytes present) → **SIGNED**, so the watcher
    ///   rebroadcasts the identical bytes rather than assuming the transaction is still
    ///   in a mempool.
    /// * `to_signed = false` → **PENDING** (legacy rows with no stored bytes).
    ///
    /// Block fields and confirmations are cleared. Any TTL written while the row was
    /// terminal — a CONFIRMED row that then reorged — is removed, because active states
    /// must never expire (requirement: only terminal rows carry a TTL).
    ///
    /// The ConditionExpression guards against reverting a state that is not eligible:
    /// only MINED or CONFIRMED transactions are reset. PENDING, SIGNED, FAILED, DROPPED,
    /// and REPLACED are left untouched; the caller treats a ConditionalCheckFailed as
    /// non-fatal.
    pub async fn reorg_reset(&self, wallet: &str, tx_hash: &str, to_signed: bool) -> Result<()> {
        let now = Utc::now();
        let target = if to_signed {
            TxStatus::Signed
        } else {
            TxStatus::Pending
        };

        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("wallet", AttributeValue::S(wallet.to_lowercase()))
            .key("tx_hash", AttributeValue::S(tx_hash.to_lowercase()))
            // Single write: set the active status, zero confirmations, and remove the
            // stale block fields and any terminal TTL atomically.
            .update_expression("SET #status = :target, confirmations = :zero, updated_at = :updated REMOVE block_number, block_hash, #ttl")
            .condition_expression("attribute_exists(wallet) AND #status IN (:mined, :confirmed)")
            .expression_attribute_names("#status", "status")
            .expression_attribute_names("#ttl", "ttl")
            .expression_attribute_values(":target", AttributeValue::S(target.as_str().to_string()))
            .expression_attribute_values(":mined", AttributeValue::S(TxStatus::Mined.as_str().to_string()))
            .expression_attribute_values(":confirmed", AttributeValue::S(TxStatus::Confirmed.as_str().to_string()))
            .expression_attribute_values(":zero", AttributeValue::N("0".to_string()))
            .expression_attribute_values(":updated", AttributeValue::S(now.to_rfc3339()))
            .send()
            .await
            .map_err(|e| {
                // Surface the raw SDK error; callers can inspect it to distinguish a
                // ConditionalCheckFailedException (benign) from a genuine I/O error.
                WatcherError::Store(format!("Failed to atomically reorg-reset: {}", e))
            })?;

        Ok(())
    }

    /// Convert DynamoDB item to TxRecord.
    ///
    /// Returns `None` when a required attribute is missing or the `status` is
    /// unrecognized — an unknown status is never coerced to a default (requirement:
    /// unknown status must yield no record, never `PENDING`).
    fn item_to_record(&self, item: &HashMap<String, AttributeValue>) -> Option<TxRecord> {
        Some(TxRecord {
            wallet: item.get("wallet")?.as_s().ok()?.clone(),
            tx_hash: item.get("tx_hash")?.as_s().ok()?.clone(),
            nonce: item.get("nonce")?.as_n().ok()?.parse().ok()?,
            status: TxStatus::from_str(item.get("status")?.as_s().ok()?)?,
            chain_id: item.get("chain_id")?.as_n().ok()?.parse().ok()?,
            block_number: item
                .get("block_number")
                .and_then(|v| v.as_n().ok()?.parse().ok()),
            block_hash: item.get("block_hash").and_then(|v| v.as_s().ok().cloned()),
            confirmations: item
                .get("confirmations")
                .and_then(|v| v.as_n().ok()?.parse().ok())
                .unwrap_or(0),
            success: item.get("success").and_then(|v| v.as_bool().ok().copied()),
            gas_price: item.get("gas_price").and_then(|v| {
                // Written as a Number by nonce_manager; older rows may carry a String.
                v.as_n().ok().cloned().or_else(|| v.as_s().ok().cloned())
            }),
            family_nonce: item
                .get("family_nonce")
                .and_then(|v| v.as_n().ok()?.parse().ok()),
            replacement_generation: item
                .get("replacement_generation")
                .and_then(|v| v.as_n().ok()?.parse().ok()),
            replacement_active: item
                .get("replacement_active")
                .and_then(|v| v.as_bool().ok().copied()),
            next_eligible_replacement_block: item
                .get("next_eligible_replacement_block")
                .and_then(|v| v.as_n().ok()?.parse().ok()),
            replacement_max_bumps: item
                .get("replacement_max_bumps")
                .and_then(|v| v.as_n().ok()?.parse().ok()),
            replacement_on_exhaust: item
                .get("replacement_on_exhaust")
                .and_then(|v| v.as_s().ok().cloned()),
            replacement_action: item
                .get("replacement_action")
                .and_then(|v| v.as_s().ok().cloned()),
            replacement_exhausted: item
                .get("replacement_exhausted")
                .and_then(|v| v.as_bool().ok().copied()),
            signed_raw_tx: item
                .get("signed_raw_tx")
                .and_then(|v| v.as_s().ok())
                .and_then(|s| parse_signed_raw_tx(s)),
            submitted_at: item
                .get("submitted_at")
                .and_then(|v| v.as_s().ok())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            updated_at: item
                .get("updated_at")
                .and_then(|v| v.as_s().ok())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            ttl: item
                .get("ttl")
                .and_then(|v| v.as_n().ok()?.parse().ok())
                .unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    //! Pure parsing tests — no DynamoDB endpoint, no AWS calls.
    use super::*;

    #[test]
    fn status_parses_all_known_variants_round_trip() {
        for st in [
            TxStatus::Signed,
            TxStatus::Pending,
            TxStatus::Mined,
            TxStatus::Confirmed,
            TxStatus::Failed,
            TxStatus::Dropped,
            TxStatus::Replaced,
            TxStatus::Reorged,
            TxStatus::Rejected,
        ] {
            assert_eq!(TxStatus::from_str(st.as_str()), Some(st));
        }
    }

    #[test]
    fn unknown_status_is_none_never_pending() {
        // The critical invariant: an unrecognized status must NOT default to PENDING.
        assert_eq!(TxStatus::from_str("WAT"), None);
        assert_eq!(TxStatus::from_str(""), None);
        assert_eq!(TxStatus::from_str("pending"), None); // case-sensitive wire form
        assert_eq!(TxStatus::from_str("signed"), None);
    }

    #[test]
    fn signed_raw_tx_parses_strict_0x_hex() {
        assert_eq!(
            parse_signed_raw_tx("0x02f800ff"),
            Some(vec![0x02, 0xf8, 0x00, 0xff])
        );
        assert_eq!(parse_signed_raw_tx("0x00"), Some(vec![0x00]));
    }

    #[test]
    fn signed_raw_tx_rejects_malformed() {
        // Missing 0x prefix.
        assert_eq!(parse_signed_raw_tx("02f800ff"), None);
        // Empty body.
        assert_eq!(parse_signed_raw_tx("0x"), None);
        // Odd-length nibbles.
        assert_eq!(parse_signed_raw_tx("0xabc"), None);
        // Non-hex characters.
        assert_eq!(parse_signed_raw_tx("0xzz"), None);
        // Empty string.
        assert_eq!(parse_signed_raw_tx(""), None);
    }
}
