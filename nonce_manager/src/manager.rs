//! Core nonce manager implementation — DynamoDB reservation authority.
//!
//! DynamoDB is the sole nonce authority. All per-wallet nonce state and the durable
//! tracker rows the watcher reads live in **one** per-chain table, so every multi-key
//! state change is a single `TransactWriteItems` (ACID). This replaces the previous
//! Redis/Lua storage layer whose state machine spanned two stores with no transaction
//! between them.
//!
//! # Row layout (single per-chain tracker table, PK `wallet`, SK `tx_hash`)
//!
//! All rows share the wallet partition. Sort keys are namespaced; internal rows omit
//! `status`/`chain_id` so they stay out of the `status-chain-index` GSI the watcher
//! queries — with one deliberate exception (a `RESERVED` reservation, see below).
//!
//! | Logical state          | SK                              | In GSI? |
//! |------------------------|---------------------------------|---------|
//! | Wallet nonce state     | `nonce-state`                   | no      |
//! | Per-nonce reservation  | `reservation#<20-digit nonce>`  | only while `RESERVED` |
//! | Gap pool entry         | `gap#<20-digit nonce>`          | no      |
//! | Out-of-order confirmed | `confirmed#<20-digit nonce>`    | no      |
//! | Durable tracker row    | `<0x tx hash>`                  | yes     |
//!
//! A `RESERVED` reservation carries `status=RESERVED` + `chain_id` **on purpose** so a
//! crash between reserve and sign is globally discoverable via the GSI
//! (`find_stale_reservations`). `record_signed` removes that recovery marker as it
//! creates the durable tracker row, so the reservation leaves the GSI the instant the
//! signed bytes exist.

use crate::error::{NonceError, Result};
use crate::types::{
    ExhaustionAction, FeeSpeed, NonceManagerConfig, PendingTransaction, ReplacementFamily,
    ReplacementFamilyInit, ReservationState, ResolvedReplacementPolicy, StaleReservation, TxStatus,
    WalletState,
};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put, TransactWriteItem, Update};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// GSI the watcher uses to discover work by status (`status` PK, `chain_id` SK).
const STATUS_CHAIN_INDEX: &str = "status-chain-index";
/// Bounded optimistic-concurrency retries for the reserve transaction.
const RESERVE_MAX_RETRIES: u32 = 8;
/// Bounded retries for the confirm watermark transaction under contention.
const CONFIRM_MAX_RETRIES: u32 = 8;

/// Maximum out-of-order `confirmed#` markers drained in a single confirm transaction.
/// DynamoDB caps `TransactWriteItems` at 100 items; an in-order confirm already spends
/// 3 fixed items (nonce-state update, reservation delete, gap delete), so we drain at
/// most 96 markers, keeping the transaction at 99 items (a one-item safety margin). A
/// contiguous run longer than the cap is drained across subsequent idempotent
/// transactions (see `drain_residual_markers`) without ever losing a marker: the
/// watermark only advances over markers deleted in the same transaction.
const MAX_DRAIN_MARKERS: usize = 96;

/// Maximum size, in bytes, of a signed raw transaction accepted by `record_signed`.
/// The bytes are stored in DynamoDB as a lowercase hex string (`record_signed` writes
/// `format!("0x{}", hex_encode(..))`), so each raw byte costs 2 characters plus the 2
/// leading `0x` characters, and the tracker item carries additional attributes (keys,
/// hashes, fees, timestamps, status) alongside it. The real per-item ceiling is
/// DynamoDB's 400 KiB limit, so the raw-byte bound must leave room for the ~2x hex
/// expansion, the `0x` prefix, and those other attributes. 128 KiB gives `128*1024`
/// raw bytes -> `256*1024 + 2` hex characters, still comfortably under 400 KiB with
/// headroom for the rest of the item. Real EVM transactions are only a few KB, so this
/// rejects empty or absurdly large / corrupt inputs before any DynamoDB work without
/// ever constraining a legitimate transaction.
const MAX_SIGNED_TX_BYTES: usize = 128 * 1024;

// Compile-time guarantee that the hex-encoded form (2 chars/byte + the `0x` prefix)
// stays clear of DynamoDB's 400 KiB per-item limit, leaving headroom for the item's
// other attributes.
const _: () = assert!(MAX_SIGNED_TX_BYTES * 2 + 2 < 400 * 1024);

/// Pure key/model helpers. Kept as free functions so they are unit-testable without a
/// DynamoDB endpoint (see the tests module).
mod model {
    pub const NONCE_STATE_SK: &str = "nonce-state";
    pub const RESERVATION_PREFIX: &str = "reservation#";
    pub const GAP_PREFIX: &str = "gap#";
    pub const CONFIRMED_PREFIX: &str = "confirmed#";
    pub const FAMILY_PREFIX: &str = "family#";

    /// Zero-padded to 20 digits so lexical sort-key ordering equals numeric nonce
    /// ordering (u64::MAX is 20 digits), making "lowest gap" a `Query` with `Limit=1`.
    pub fn pad(nonce: u64) -> String {
        format!("{nonce:020}")
    }

    pub fn reservation_sk(nonce: u64) -> String {
        format!("{RESERVATION_PREFIX}{}", pad(nonce))
    }

    pub fn gap_sk(nonce: u64) -> String {
        format!("{GAP_PREFIX}{}", pad(nonce))
    }

    pub fn confirmed_sk(nonce: u64) -> String {
        format!("{CONFIRMED_PREFIX}{}", pad(nonce))
    }

    pub fn family_sk(nonce: u64) -> String {
        format!("{FAMILY_PREFIX}{}", pad(nonce))
    }

    /// The wallet partition key: the lowercased `0x`+40-hex address. Derived identically
    /// to the tracker and idempotency rows (`format!("{:?}", addr).to_lowercase()`), so
    /// the nonce-state row shares the partition that already holds a wallet's tx and
    /// idempotency rows. **No `chain_id` prefix** — chain isolation comes from the
    /// per-chain table.
    pub fn wallet_pk(addr: &alloy::primitives::Address) -> String {
        format!("{addr:?}").to_lowercase()
    }

    /// Parse the trailing nonce out of a namespaced sort key (`gap#…`, `reservation#…`,
    /// `confirmed#…`). Returns `None` for the `nonce-state` row or a real `0x…` hash.
    pub fn nonce_from_sk(sk: &str) -> Option<u64> {
        let suffix = sk
            .strip_prefix(RESERVATION_PREFIX)
            .or_else(|| sk.strip_prefix(GAP_PREFIX))
            .or_else(|| sk.strip_prefix(CONFIRMED_PREFIX))
            .or_else(|| sk.strip_prefix(FAMILY_PREFIX))?;
        suffix.parse::<u64>().ok()
    }

    /// Compute the new confirmed watermark when `confirmed_nonce` is being confirmed,
    /// draining any contiguous run of already-present out-of-order `confirmed#` markers
    /// above it. `marker_present(w)` reports whether `confirmed#<w>` exists.
    ///
    /// Returns `(new_watermark, drained)` where `drained` are the marker nonces consumed
    /// (to be deleted). The drain is capped at [`super::MAX_DRAIN_MARKERS`] so the
    /// enclosing `TransactWriteItems` stays within DynamoDB's 100-item limit; a longer
    /// run is finished by subsequent idempotent calls. Pure, total, and overflow-safe:
    /// the watermark saturates at `u64::MAX` and never wraps. The caller supplies the
    /// existence oracle.
    pub fn drain_watermark(
        confirmed_nonce: u64,
        marker_present: impl Fn(u64) -> bool,
    ) -> (u64, Vec<u64>) {
        // The watermark always advances at least past the in-order nonce being
        // confirmed. Nothing exists above u64::MAX, so confirming it is a fixed point.
        let Some(start) = confirmed_nonce.checked_add(1) else {
            return (confirmed_nonce, Vec::new());
        };
        let drained = contiguous_markers(start, super::MAX_DRAIN_MARKERS, marker_present);
        // New watermark is one past the last drained marker (== `start` when the in-order
        // nonce has no markers above it). Saturate at the top of the range.
        let new_watermark = drained.last().map(|w| w.saturating_add(1)).unwrap_or(start);
        (new_watermark, drained)
    }

    /// The contiguous run of present markers starting at `start`, capped at `cap`
    /// entries. Pure, total, and overflow-safe: the probe stops at `u64::MAX` rather
    /// than wrapping.
    pub fn contiguous_markers(
        start: u64,
        cap: usize,
        marker_present: impl Fn(u64) -> bool,
    ) -> Vec<u64> {
        let mut out = Vec::new();
        let mut w = start;
        while out.len() < cap && marker_present(w) {
            out.push(w);
            match w.checked_add(1) {
                Some(next) => w = next,
                None => break, // reached u64::MAX; cannot probe higher
            }
        }
        out
    }
}

/// DynamoDB-backed nonce authority for a single chain.
///
/// Each instance is bound to a specific `chain_id`; chain isolation comes from the
/// per-chain table plus the `chain_id` attribute written onto GSI-visible rows.
#[derive(Clone)]
pub struct DynamoNonceManager<P>
where
    P: Provider + Clone,
{
    client: Client,
    table: String,
    provider: Arc<P>,
    pub config: NonceManagerConfig,
    chain_id: u64,
}

// ---- small AttributeValue helpers ----

fn s(v: impl Into<String>) -> AttributeValue {
    AttributeValue::S(v.into())
}

fn n(v: impl ToString) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

fn b(v: bool) -> AttributeValue {
    AttributeValue::Bool(v)
}

fn get_u128(item: &HashMap<String, AttributeValue>, key: &str) -> Option<u128> {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse::<u128>().ok())
}

fn get_n(item: &HashMap<String, AttributeValue>, key: &str) -> Option<u64> {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

fn get_s<'a>(item: &'a HashMap<String, AttributeValue>, key: &str) -> Option<&'a str> {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .map(|s| s.as_str())
}

fn u256_attr(v: Option<U256>) -> Option<AttributeValue> {
    v.map(|x| AttributeValue::N(x.to_string()))
}

fn parse_u256(item: &HashMap<String, AttributeValue>, key: &str) -> Option<U256> {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse::<U256>().ok())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Brief randomized backoff between optimistic `reserve_nonce` retries. Exponential up
/// to ~8 ms with a small jitter so concurrent reservers desynchronize and stop
/// colliding on the same `next_nonce` value, cutting wasted round trips under high
/// fan-out. Kept tiny: reservation is on the latency-critical broadcast path.
async fn reserve_backoff(attempt: u64) {
    let base_ms = 1u64 << attempt.min(3); // 1, 2, 4, 8 ms
    let jitter_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() % 4) as u64)
        .unwrap_or(0);
    tokio::time::sleep(Duration::from_millis(base_ms + jitter_ms)).await;
}

/// Whether the cancellation reason at `idx` (item order) is a failed condition check.
fn cond_failed(codes: &[Option<String>], idx: usize) -> bool {
    codes
        .get(idx)
        .and_then(|c| c.as_deref())
        .map(|c| c == "ConditionalCheckFailed")
        .unwrap_or(false)
}

fn map_build<T, E: std::fmt::Display>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| NonceError::Dynamo(format!("request build error: {e}")))
}

impl<P> DynamoNonceManager<P>
where
    P: Provider + Clone,
{
    /// Create a new nonce manager for a specific chain.
    ///
    /// * `client` — DynamoDB client (the caller owns credential/region config)
    /// * `table` — per-chain tracker table name
    /// * `provider` — alloy provider for chain reconciliation
    /// * `chain_id` — EVM chain ID (1 = Ethereum, 137 = Polygon, …)
    /// * `config` — nonce manager configuration
    pub fn new(
        client: Client,
        table: impl Into<String>,
        provider: Arc<P>,
        chain_id: u64,
        config: NonceManagerConfig,
    ) -> Self {
        Self {
            client,
            table: table.into(),
            provider,
            config,
            chain_id,
        }
    }

    /// Create with default configuration for a specific chain.
    pub fn with_defaults(
        client: Client,
        table: impl Into<String>,
        provider: Arc<P>,
        chain_id: u64,
    ) -> Self {
        Self::new(
            client,
            table,
            provider,
            chain_id,
            NonceManagerConfig::default(),
        )
    }

    /// Get the chain ID this manager is configured for.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn pk(&self, addr: &Address) -> String {
        model::wallet_pk(addr)
    }

    // ---- transaction helper ----

    /// Run a `TransactWriteItems`. Returns `Ok(None)` on success, `Ok(Some(codes))` when
    /// the transaction was cancelled (per-item reason codes in item order, e.g.
    /// `Some("ConditionalCheckFailed")`), and `Err` on any other failure.
    async fn transact(&self, items: Vec<TransactWriteItem>) -> Result<Option<Vec<Option<String>>>> {
        match self
            .client
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await
        {
            Ok(_) => Ok(None),
            Err(e) => {
                if let Some(svc) = e.as_service_error()
                    && let aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError::TransactionCanceledException(tce) = svc
                {
                    let codes = tce
                        .cancellation_reasons()
                        .iter()
                        .map(|r| r.code().map(|c| c.to_string()))
                        .collect();
                    return Ok(Some(codes));
                }
                Err(NonceError::Dynamo(e.to_string()))
            }
        }
    }

    // ---- read helpers ----

    async fn get_nonce_state(
        &self,
        addr: &Address,
        consistent: bool,
    ) -> Result<Option<HashMap<String, AttributeValue>>> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("wallet", s(self.pk(addr)))
            .key("tx_hash", s(model::NONCE_STATE_SK))
            .consistent_read(consistent)
            .send()
            .await
            .map_err(|e| NonceError::Dynamo(e.to_string()))?;
        Ok(out.item)
    }

    async fn marker_exists(&self, addr: &Address, nonce: u64) -> Result<bool> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("wallet", s(self.pk(addr)))
            .key("tx_hash", s(model::confirmed_sk(nonce)))
            .consistent_read(true)
            .projection_expression("nonce")
            .send()
            .await
            .map_err(|e| NonceError::Dynamo(e.to_string()))?;
        Ok(out.item.is_some())
    }

    /// Query all sort keys under the wallet partition with a given prefix.
    async fn query_prefix(
        &self,
        addr: &Address,
        prefix: &str,
        consistent: bool,
    ) -> Result<Vec<HashMap<String, AttributeValue>>> {
        let mut items = Vec::new();
        let mut last: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let mut req = self
                .client
                .query()
                .table_name(&self.table)
                .key_condition_expression("wallet = :w AND begins_with(tx_hash, :p)")
                .expression_attribute_values(":w", s(self.pk(addr)))
                .expression_attribute_values(":p", s(prefix))
                .consistent_read(consistent);
            if let Some(start) = last.take() {
                req = req.set_exclusive_start_key(Some(start));
            }
            let out = req
                .send()
                .await
                .map_err(|e| NonceError::Dynamo(e.to_string()))?;
            if let Some(mut page) = out.items {
                items.append(&mut page);
            }
            match out.last_evaluated_key {
                Some(k) => last = Some(k),
                None => break,
            }
        }
        Ok(items)
    }

    // ---- initialization / reconciliation ----

    /// Initialize nonce tracking for a wallet, reconciling with chain state.
    ///
    /// Reconciliation is monotonic and non-destructive: `next_nonce`/`confirmed_nonce`
    /// only ever move **upward** toward the chain. Behind-chain drift is raised up so an
    /// already-consumed nonce is never re-issued; ahead-of-chain in-flight state is left
    /// untouched. Returns the effective `next_nonce`.
    pub async fn initialize_wallet(&self, address: Address) -> Result<u64> {
        let chain_pending = self
            .provider
            .get_transaction_count(address)
            .block_id(BlockNumberOrTag::Pending.into())
            .await?;
        let chain_confirmed = self
            .provider
            .get_transaction_count(address)
            .block_id(BlockNumberOrTag::Latest.into())
            .await?;

        // Try to seed a fresh row; conditional on it not already existing.
        let seed = self
            .client
            .put_item()
            .table_name(&self.table)
            .item("wallet", s(self.pk(&address)))
            .item("tx_hash", s(model::NONCE_STATE_SK))
            .item("next_nonce", n(chain_pending))
            .item("confirmed_nonce", n(chain_confirmed))
            .item("pending_count", n(0))
            .item("updated_at", s(now_rfc3339()))
            .condition_expression("attribute_not_exists(tx_hash)")
            .send()
            .await;

        match seed {
            Ok(_) => {
                info!(wallet = ?address, nonce = chain_pending, chain_confirmed, "Wallet initialized");
                Ok(chain_pending)
            }
            Err(e) => {
                let is_conditional = e
                    .as_service_error()
                    .map(|svc| svc.is_conditional_check_failed_exception())
                    .unwrap_or(false);
                if !is_conditional {
                    return Err(NonceError::Dynamo(e.to_string()));
                }
                // Row exists — reconcile upward only.
                self.reconcile_upward(address, chain_pending, chain_confirmed)
                    .await
            }
        }
    }

    async fn reconcile_upward(
        &self,
        address: Address,
        chain_pending: u64,
        chain_confirmed: u64,
    ) -> Result<u64> {
        // Raise each counter toward the chain only when strictly behind. There is no
        // unconditional no-op "safety net" write: a `ConditionalCheckFailed` already
        // means the counter is at or above the chain (benign, since reconciliation is
        // monotonic), while any other DynamoDB error propagates.
        self.raise_counter_if_behind(&address, "next_nonce", chain_pending)
            .await?;
        self.raise_counter_if_behind(&address, "confirmed_nonce", chain_confirmed)
            .await?;

        let state = self.get_nonce_state(&address, true).await?;
        let next = state
            .as_ref()
            .and_then(|i| get_n(i, "next_nonce"))
            .unwrap_or(chain_pending);
        debug!(wallet = ?address, next_nonce = next, chain_pending, "Wallet reconciled upward");
        Ok(next)
    }

    /// Raise a monotonic counter (`next_nonce` / `confirmed_nonce`) on the nonce-state
    /// row up to `target`, but only when it is strictly behind. The guarded update never
    /// writes when the counter is already at or above `target` (the condition fails
    /// before any write), so no unnecessary no-op write is issued. Returns `Ok(())` both
    /// when the raise is applied and when the guard fails as `ConditionalCheckFailed`
    /// (already at/above target — benign); any other DynamoDB error propagates.
    ///
    /// `attr` is an internal, fixed attribute name (never caller input), so interpolating
    /// it into the expressions is safe.
    async fn raise_counter_if_behind(
        &self,
        address: &Address,
        attr: &str,
        target: u64,
    ) -> Result<()> {
        let res = self
            .client
            .update_item()
            .table_name(&self.table)
            .key("wallet", s(self.pk(address)))
            .key("tx_hash", s(model::NONCE_STATE_SK))
            .update_expression(format!("SET {attr} = :t, updated_at = :now"))
            .condition_expression(format!("{attr} < :t"))
            .expression_attribute_values(":t", n(target))
            .expression_attribute_values(":now", s(now_rfc3339()))
            .send()
            .await;
        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                let is_conditional = e
                    .as_service_error()
                    .map(|svc| svc.is_conditional_check_failed_exception())
                    .unwrap_or(false);
                if is_conditional {
                    Ok(())
                } else {
                    Err(NonceError::Dynamo(e.to_string()))
                }
            }
        }
    }

    // ---- reservation ----

    /// Reserve the next nonce for a wallet (atomic). Reuses the lowest gap first, else
    /// allocates sequentially. Two concurrent reservations never return the same nonce.
    pub async fn reserve_nonce(&self, address: Address) -> Result<u64> {
        // Gap reuse path (bounded): claim the lowest gap and turn it into a RESERVED row.
        for _ in 0..2 {
            match self.try_reserve_gap(address).await? {
                GapOutcome::Reserved(nonce) => return Ok(nonce),
                GapOutcome::MaxPending { count } => {
                    return Err(NonceError::MaxPendingExceeded {
                        wallet: format!("{address:?}"),
                        count,
                        max: self.config.max_pending_per_wallet,
                    });
                }
                GapOutcome::NoGap => break,
                // Lost the claim race — fall through to retry gap once, then sequential.
                GapOutcome::Contended => continue,
            }
        }
        self.reserve_sequential(address).await
    }

    async fn try_reserve_gap(&self, address: Address) -> Result<GapOutcome> {
        let out = self
            .client
            .query()
            .table_name(&self.table)
            .key_condition_expression("wallet = :w AND begins_with(tx_hash, :p)")
            .expression_attribute_values(":w", s(self.pk(&address)))
            .expression_attribute_values(":p", s(model::GAP_PREFIX))
            .scan_index_forward(true)
            .limit(1)
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| NonceError::Dynamo(e.to_string()))?;

        let Some(gap_item) = out.items.and_then(|mut v| v.pop()) else {
            return Ok(GapOutcome::NoGap);
        };
        let Some(nonce) = get_n(&gap_item, "nonce") else {
            return Ok(GapOutcome::NoGap);
        };

        let delete_gap = TransactWriteItem::builder()
            .delete(map_build(
                Delete::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&address)))
                    .key("tx_hash", s(model::gap_sk(nonce)))
                    .condition_expression("attribute_exists(tx_hash)")
                    .build(),
            )?)
            .build();
        let bump_pending = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&address)))
                    .key("tx_hash", s(model::NONCE_STATE_SK))
                    .update_expression("ADD pending_count :one SET updated_at = :now")
                    .condition_expression(
                        "attribute_exists(next_nonce) AND pending_count < :max \
                         AND confirmed_nonce <= :gap",
                    )
                    .expression_attribute_values(":one", n(1))
                    .expression_attribute_values(":max", n(self.config.max_pending_per_wallet))
                    .expression_attribute_values(":gap", n(nonce))
                    .expression_attribute_values(":now", s(now_rfc3339()))
                    .build(),
            )?)
            .build();
        let put_reservation = TransactWriteItem::builder()
            .put(self.reservation_put(&address, nonce)?)
            .build();

        match self
            .transact(vec![delete_gap, bump_pending, put_reservation])
            .await?
        {
            None => {
                debug!(wallet = ?address, nonce, from_gap = true, "Nonce reserved from gap pool");
                Ok(GapOutcome::Reserved(nonce))
            }
            Some(codes) => {
                if cond_failed(&codes, 0) {
                    // Gap claimed by another worker between our read and transact.
                    Ok(GapOutcome::Contended)
                } else if cond_failed(&codes, 1) {
                    let state = self.get_nonce_state(&address, true).await?;
                    let Some(state) = state else {
                        // A gap without nonce-state is inconsistent, but sequential
                        // allocation can initialize the wallet safely. Leave the gap for
                        // the next guarded attempt rather than guessing.
                        return Ok(GapOutcome::NoGap);
                    };
                    let count = get_n(&state, "pending_count").unwrap_or(0);
                    if count >= self.config.max_pending_per_wallet {
                        return Ok(GapOutcome::MaxPending { count });
                    }

                    let confirmed = get_n(&state, "confirmed_nonce").unwrap_or(0);
                    if nonce < confirmed {
                        // The watermark is monotonic, so this gap is provably consumed
                        // and can never become reusable again. Remove it conditionally;
                        // if another worker changed it first, the delete simply loses the
                        // race and the next reservation re-reads the gap pool.
                        let delete = self
                            .client
                            .delete_item()
                            .table_name(&self.table)
                            .key("wallet", s(self.pk(&address)))
                            .key("tx_hash", s(model::gap_sk(nonce)))
                            .condition_expression("attribute_exists(tx_hash)")
                            .send()
                            .await;
                        match delete {
                            Ok(_) => warn!(
                                wallet = ?address,
                                nonce,
                                confirmed,
                                "Discarded stale gap below confirmed watermark"
                            ),
                            Err(e)
                                if e.as_service_error()
                                    .map(|svc| svc.is_conditional_check_failed_exception())
                                    .unwrap_or(false) => {}
                            Err(e) => return Err(NonceError::Dynamo(e.to_string())),
                        }
                    }
                    Ok(GapOutcome::Contended)
                } else {
                    // Reservation SK already existed, or other transient — treat as contention.
                    Ok(GapOutcome::Contended)
                }
            }
        }
    }

    async fn reserve_sequential(&self, address: Address) -> Result<u64> {
        // A conditional `next_nonce` advance is optimistic concurrency: under concurrent
        // reservers only one wins each value and the losers must re-read and retry. A
        // loss because another reserver advanced `next_nonce` is *forward progress*, not a
        // wasted spin, and under high fan-out a single caller can lose many such races in
        // a row. Bounding the loop by a small constant therefore turns ordinary
        // concurrency into a spurious `exhausted` error (observed with ~50 concurrent
        // reservers). The budget instead accounts for the maximum number of times other
        // reservers can force us to retry before we either win or `pending_count` trips
        // max-pending: at most `max_pending` progress advances (each permanently
        // increments the capped `pending_count`) plus a small constant slack for the rare
        // reservation-SK collision. This is finite and terminating: every retry-inducing
        // commit by a peer advances a monotonic, capped counter.
        let max_attempts = self
            .config
            .max_pending_per_wallet
            .saturating_add(RESERVE_MAX_RETRIES as u64);
        for attempt in 0..max_attempts {
            let Some(state) = self.get_nonce_state(&address, true).await? else {
                // Not initialized: seed from chain and retry.
                self.initialize_wallet(address).await?;
                continue;
            };
            let expected = get_n(&state, "next_nonce").ok_or_else(|| {
                NonceError::Dynamo("nonce-state row missing next_nonce".to_string())
            })?;
            let pending = get_n(&state, "pending_count").unwrap_or(0);
            if pending >= self.config.max_pending_per_wallet {
                return Err(NonceError::MaxPendingExceeded {
                    wallet: format!("{address:?}"),
                    count: pending,
                    max: self.config.max_pending_per_wallet,
                });
            }

            // The nonce space is u64; advancing past u64::MAX would wrap. Fail closed
            // with a clear error rather than silently reissuing nonce 0.
            let next_nonce = expected.checked_add(1).ok_or_else(|| {
                NonceError::Dynamo(format!(
                    "next_nonce overflow: nonce space exhausted at u64::MAX for wallet {address:?}"
                ))
            })?;

            let advance = TransactWriteItem::builder()
                .update(map_build(
                    Update::builder()
                        .table_name(&self.table)
                        .key("wallet", s(self.pk(&address)))
                        .key("tx_hash", s(model::NONCE_STATE_SK))
                        .update_expression(
                            "SET next_nonce = :next, updated_at = :now ADD pending_count :one",
                        )
                        .condition_expression(
                            "attribute_exists(next_nonce) AND next_nonce = :expected \
                             AND pending_count < :max",
                        )
                        .expression_attribute_values(":next", n(next_nonce))
                        .expression_attribute_values(":expected", n(expected))
                        .expression_attribute_values(":one", n(1))
                        .expression_attribute_values(":max", n(self.config.max_pending_per_wallet))
                        .expression_attribute_values(":now", s(now_rfc3339()))
                        .build(),
                )?)
                .build();
            let put_reservation = TransactWriteItem::builder()
                .put(self.reservation_put(&address, expected)?)
                .build();

            match self.transact(vec![advance, put_reservation]).await? {
                None => {
                    debug!(wallet = ?address, nonce = expected, from_gap = false, "Nonce reserved");
                    return Ok(expected);
                }
                Some(codes) => {
                    if cond_failed(&codes, 0) {
                        // Re-read to distinguish max-pending from a concurrent advance.
                        let latest = self.get_nonce_state(&address, true).await?;
                        let count = latest
                            .as_ref()
                            .and_then(|i| get_n(i, "pending_count"))
                            .unwrap_or(0);
                        if count >= self.config.max_pending_per_wallet {
                            return Err(NonceError::MaxPendingExceeded {
                                wallet: format!("{address:?}"),
                                count,
                                max: self.config.max_pending_per_wallet,
                            });
                        }
                        // next_nonce moved under us — back off briefly to spread
                        // contention, then retry with a fresh read.
                        reserve_backoff(attempt).await;
                        continue;
                    }
                    // Reservation SK collision (should be rare) — back off and retry.
                    reserve_backoff(attempt).await;
                    continue;
                }
            }
        }
        Err(NonceError::Dynamo(
            "reserve_nonce exhausted optimistic-concurrency retries".to_string(),
        ))
    }

    /// Build the `Put` for a fresh `RESERVED` reservation row. Carries `status` +
    /// `chain_id` so a crash before signing is discoverable via the GSI.
    fn reservation_put(&self, address: &Address, nonce: u64) -> Result<Put> {
        map_build(
            Put::builder()
                .table_name(&self.table)
                .item("wallet", s(self.pk(address)))
                .item("tx_hash", s(model::reservation_sk(nonce)))
                .item("nonce", n(nonce))
                .item("state", s(ReservationState::Reserved.as_str()))
                .item("reserved_at", s(now_rfc3339()))
                .item("status", s(ReservationState::Reserved.as_str()))
                .item("chain_id", n(self.chain_id))
                .condition_expression("attribute_not_exists(tx_hash)")
                .build(),
        )
    }

    // ---- release / mark_failed (pre-signed only) ----

    /// Release a reserved nonce (use when simulation fails BEFORE signing). The nonce is
    /// recycled into the gap pool and pending is decremented. Only a `RESERVED`
    /// reservation may be released; a `SIGNED`/`BROADCAST` reservation has a durable
    /// tracker row and cannot be released (returns `Ok(false)`).
    pub async fn release_nonce(&self, address: Address, nonce: u64) -> Result<bool> {
        self.recycle_reserved(address, nonce, "release").await
    }

    /// Mark a pre-signed transaction as failed and return its nonce to the gap pool.
    /// Same guarantees as [`release_nonce`]: only a `RESERVED` reservation is recycled.
    pub async fn mark_failed(&self, address: Address, nonce: u64) -> Result<()> {
        let _ = self.recycle_reserved(address, nonce, "mark_failed").await?;
        Ok(())
    }

    async fn recycle_reserved(&self, address: Address, nonce: u64, op: &str) -> Result<bool> {
        let delete_reservation = TransactWriteItem::builder()
            .delete(map_build(
                Delete::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&address)))
                    .key("tx_hash", s(model::reservation_sk(nonce)))
                    .condition_expression("attribute_exists(tx_hash) AND #st = :reserved")
                    .expression_attribute_names("#st", "state")
                    .expression_attribute_values(
                        ":reserved",
                        s(ReservationState::Reserved.as_str()),
                    )
                    .build(),
            )?)
            .build();
        let dec_pending = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&address)))
                    .key("tx_hash", s(model::NONCE_STATE_SK))
                    .update_expression("ADD pending_count :neg SET updated_at = :now")
                    .condition_expression("attribute_exists(next_nonce)")
                    .expression_attribute_values(":neg", n(-1))
                    .expression_attribute_values(":now", s(now_rfc3339()))
                    .build(),
            )?)
            .build();
        let put_gap = TransactWriteItem::builder()
            .put(map_build(
                Put::builder()
                    .table_name(&self.table)
                    .key_gap(&self.pk(&address), nonce)
                    .build(),
            )?)
            .build();

        match self
            .transact(vec![delete_reservation, dec_pending, put_gap])
            .await?
        {
            None => {
                debug!(wallet = ?address, nonce, op, "Reserved nonce recycled to gap pool");
                Ok(true)
            }
            Some(codes) => {
                if cond_failed(&codes, 0) {
                    // Reservation absent or no longer RESERVED (signed/broadcast) — cannot recycle.
                    warn!(
                        wallet = ?address,
                        nonce,
                        op,
                        "Cannot recycle nonce: reservation is not RESERVED (signed/broadcast) or absent"
                    );
                    Ok(false)
                } else {
                    Err(NonceError::Dynamo(format!(
                        "{op} transaction cancelled: {codes:?}"
                    )))
                }
            }
        }
    }

    // ---- record_signed / mark_broadcast ----

    /// Record that a raw transaction has been signed for a reserved nonce.
    ///
    /// One `TransactWriteItems`:
    /// 1. Advance the reservation `RESERVED -> SIGNED`, store the real tx hash + fees,
    ///    and **remove** the `status`/`chain_id` recovery marker (leaves the GSI).
    /// 2. Put the durable tracker row keyed by the real `0x` tx hash with
    ///    `status=SIGNED`, `chain_id`, `nonce`, the exact signed raw tx bytes, and a
    ///    submitted timestamp — **no TTL**.
    ///
    /// After this returns, the watcher can globally query `status=SIGNED` and the exact
    /// bytes are durable before any send.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_signed(
        &self,
        address: Address,
        nonce: u64,
        tx_hash: B256,
        signed_raw_tx: &[u8],
        gas_price: Option<U256>,
        max_fee_per_gas: Option<U256>,
        max_priority_fee_per_gas: Option<U256>,
    ) -> Result<()> {
        self.record_signed_inner(
            address,
            nonce,
            tx_hash,
            signed_raw_tx,
            gas_price,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            None,
        )
        .await
    }

    /// Durable signed handoff plus an immutable same-nonce replacement family. The
    /// reservation update, tracker row, and family control row are one ACID transaction:
    /// a crash can never leave replacement metadata detached from signed bytes.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_signed_with_family(
        &self,
        address: Address,
        nonce: u64,
        tx_hash: B256,
        signed_raw_tx: &[u8],
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
        family: &ReplacementFamilyInit,
    ) -> Result<()> {
        self.record_signed_inner(
            address,
            nonce,
            tx_hash,
            signed_raw_tx,
            None,
            Some(max_fee_per_gas),
            Some(max_priority_fee_per_gas),
            Some(family),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_signed_inner(
        &self,
        address: Address,
        nonce: u64,
        tx_hash: B256,
        signed_raw_tx: &[u8],
        gas_price: Option<U256>,
        max_fee_per_gas: Option<U256>,
        max_priority_fee_per_gas: Option<U256>,
        family: Option<&ReplacementFamilyInit>,
    ) -> Result<()> {
        validate_signed_raw_tx(signed_raw_tx)?;
        let hash_hex = format!("{tx_hash:?}").to_lowercase();
        let raw_hex = format!("0x{}", hex_encode(signed_raw_tx));
        let now = now_rfc3339();

        let mut set = String::from(
            "SET #st = :signed, real_tx_hash = :hash, signed_at = :now, retry_count = :zero",
        );
        let mut update = Update::builder()
            .table_name(&self.table)
            .key("wallet", s(self.pk(&address)))
            .key("tx_hash", s(model::reservation_sk(nonce)))
            .condition_expression("#st = :reserved")
            .expression_attribute_names("#st", "state")
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":signed", s(ReservationState::Signed.as_str()))
            .expression_attribute_values(":reserved", s(ReservationState::Reserved.as_str()))
            .expression_attribute_values(":hash", s(hash_hex.clone()))
            .expression_attribute_values(":now", s(now.clone()))
            .expression_attribute_values(":zero", n(0));
        if let Some(v) = u256_attr(gas_price) {
            set.push_str(", gas_price = :gp");
            update = update.expression_attribute_values(":gp", v);
        }
        if let Some(v) = u256_attr(max_fee_per_gas) {
            set.push_str(", max_fee_per_gas = :mf");
            update = update.expression_attribute_values(":mf", v);
        }
        if let Some(v) = u256_attr(max_priority_fee_per_gas) {
            set.push_str(", max_priority_fee_per_gas = :pf");
            update = update.expression_attribute_values(":pf", v);
        }
        let update = update.update_expression(format!("{set} REMOVE #status, chain_id"));
        let update_reservation = TransactWriteItem::builder()
            .update(map_build(update.build())?)
            .build();

        let mut tracker = Put::builder()
            .table_name(&self.table)
            .item("wallet", s(self.pk(&address)))
            .item("tx_hash", s(hash_hex.clone()))
            .item("status", s("SIGNED"))
            .item("chain_id", n(self.chain_id))
            .item("nonce", n(nonce))
            .item("signed_raw_tx", s(raw_hex))
            .item("submitted_at", s(now.clone()))
            .condition_expression("attribute_not_exists(tx_hash)");
        if let Some(v) = u256_attr(gas_price) {
            tracker = tracker.item("gas_price", v);
        }
        if let Some(v) = u256_attr(max_fee_per_gas) {
            tracker = tracker.item("max_fee_per_gas", v);
        }
        if let Some(v) = u256_attr(max_priority_fee_per_gas) {
            tracker = tracker.item("max_priority_fee_per_gas", v);
        }
        if let Some(family) = family {
            tracker = tracker
                .item("family_nonce", n(nonce))
                .item("replacement_generation", n(0))
                .item("replacement_active", b(true))
                .item(
                    "next_eligible_replacement_block",
                    n(family
                        .current_block
                        .saturating_add(family.policy.bump_every_blocks)),
                )
                .item("replacement_max_bumps", n(family.policy.max_bumps))
                .item(
                    "replacement_on_exhaust",
                    s(family.policy.on_exhaust.as_str()),
                )
                .item("replacement_action", s("original"));
        }
        let put_tracker = TransactWriteItem::builder()
            .put(map_build(tracker.build())?)
            .build();

        let mut items = vec![update_reservation, put_tracker];
        if let Some(family) = family {
            let put_family = Put::builder()
                .table_name(&self.table)
                .item("wallet", s(self.pk(&address)))
                .item("tx_hash", s(model::family_sk(nonce)))
                .item("row_type", s("REPLACEMENT_FAMILY"))
                .item("nonce", n(nonce))
                .item("chain_id", n(self.chain_id))
                .item("to", s(format!("{:?}", family.to).to_lowercase()))
                .item("value", n(family.value))
                .item("data", s(format!("0x{}", hex_encode(&family.data))))
                .item("gas_limit", n(family.gas_limit))
                .item("fee_speed", s(family.policy.fee_speed.as_str()))
                .item("bump_every_blocks", n(family.policy.bump_every_blocks))
                .item("max_bumps", n(family.policy.max_bumps))
                .item("on_exhaust", s(family.policy.on_exhaust.as_str()))
                .item(
                    "max_fee_per_gas_ceiling",
                    n(family.policy.max_fee_per_gas_wei),
                )
                .item("max_total_fee_ceiling", n(family.policy.max_total_fee_wei))
                .item("active_generation", n(0))
                .item("active_hash", s(hash_hex.clone()))
                .item("active_max_fee_per_gas", n(family.max_fee_per_gas))
                .item(
                    "active_max_priority_fee_per_gas",
                    n(family.max_priority_fee_per_gas),
                )
                .item(
                    "next_eligible_block",
                    n(family
                        .current_block
                        .saturating_add(family.policy.bump_every_blocks)),
                )
                .item("family_state", s("ACTIVE"))
                .item("created_at", s(now.clone()))
                .item("updated_at", s(now))
                .condition_expression("attribute_not_exists(tx_hash)");
            items.push(
                TransactWriteItem::builder()
                    .put(map_build(put_family.build())?)
                    .build(),
            );
        }

        match self.transact(items).await? {
            None => {
                info!(wallet = ?address, nonce, tx_hash = %hash_hex, has_family = family.is_some(), "Transaction signed and recorded");
                Ok(())
            }
            Some(codes) => Err(NonceError::Dynamo(format!(
                "record_signed transaction cancelled (reservation/tracker/family conflict): {codes:?}"
            ))),
        }
    }

    /// Mark that the signed transaction has been handed to the mempool.
    ///
    /// One `TransactWriteItems`: the durable tracker row moves to `PENDING` and the
    /// reservation to `BROADCAST`. This is **idempotent for recovery replay**: the
    /// tracker guard accepts `SIGNED` *or* `PENDING` and the reservation guard accepts
    /// `SIGNED` *or* `BROADCAST`, and both updates set their target state. A first call
    /// advances `SIGNED -> PENDING`/`BROADCAST`; a replay finds the rows already at the
    /// target and re-sets them to the same value (a no-op — no counters are touched, so
    /// there are no double effects) and still succeeds. `record_signed` remains
    /// `RESERVED`-only because the durable tracker row's existence is the recovery
    /// handoff; only after it exists can this method be replayed safely.
    ///
    /// No TTL is written; the terminal watcher applies TTL once the transaction resolves.
    pub async fn mark_broadcast(&self, address: Address, nonce: u64, tx_hash: B256) -> Result<()> {
        let hash_hex = format!("{tx_hash:?}").to_lowercase();
        let now = now_rfc3339();

        let update_tracker = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&address)))
                    .key("tx_hash", s(hash_hex.clone()))
                    .update_expression("SET #st = :pending, updated_at = :now")
                    .condition_expression("#st = :signed OR #st = :pending")
                    .expression_attribute_names("#st", "status")
                    .expression_attribute_values(":pending", s("PENDING"))
                    .expression_attribute_values(":signed", s("SIGNED"))
                    .expression_attribute_values(":now", s(now.clone()))
                    .build(),
            )?)
            .build();
        let update_reservation = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&address)))
                    .key("tx_hash", s(model::reservation_sk(nonce)))
                    .update_expression("SET #st = :broadcast, updated_at = :now")
                    .condition_expression("#st = :signed OR #st = :broadcast")
                    .expression_attribute_names("#st", "state")
                    .expression_attribute_values(
                        ":broadcast",
                        s(ReservationState::Broadcast.as_str()),
                    )
                    .expression_attribute_values(":signed", s(ReservationState::Signed.as_str()))
                    .expression_attribute_values(":now", s(now))
                    .build(),
            )?)
            .build();

        match self
            .transact(vec![update_tracker, update_reservation])
            .await?
        {
            None => {
                info!(wallet = ?address, nonce, tx_hash = %hash_hex, "Transaction broadcast");
                Ok(())
            }
            Some(codes) => Err(NonceError::Dynamo(format!(
                "mark_broadcast transaction cancelled (tracker not SIGNED/PENDING or reservation not SIGNED/BROADCAST): {codes:?}"
            ))),
        }
    }

    /// Load an immutable replacement family with a strongly consistent read.
    pub async fn get_replacement_family(
        &self,
        address: Address,
        nonce: u64,
    ) -> Result<Option<ReplacementFamily>> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("wallet", s(self.pk(&address)))
            .key("tx_hash", s(model::family_sk(nonce)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| NonceError::Dynamo(e.to_string()))?;
        let Some(item) = out.item else {
            return Ok(None);
        };
        let required_s = |key: &str| {
            get_s(&item, key)
                .map(str::to_owned)
                .ok_or_else(|| NonceError::Dynamo(format!("family row missing {key}")))
        };
        let required_n = |key: &str| {
            get_n(&item, key)
                .ok_or_else(|| NonceError::Dynamo(format!("family row missing/invalid {key}")))
        };
        let to = required_s("to")?
            .parse::<Address>()
            .map_err(|e| NonceError::Dynamo(format!("family row invalid to: {e}")))?;
        let value = parse_u256(&item, "value")
            .ok_or_else(|| NonceError::Dynamo("family row missing/invalid value".into()))?;
        let data_hex = required_s("data")?;
        let data = alloy::hex::decode(data_hex.strip_prefix("0x").unwrap_or(&data_hex))
            .map_err(|e| NonceError::Dynamo(format!("family row invalid data: {e}")))?;
        let fee_speed = FeeSpeed::from_str(&required_s("fee_speed")?)
            .ok_or_else(|| NonceError::Dynamo("family row invalid fee_speed".into()))?;
        let on_exhaust = ExhaustionAction::from_str(&required_s("on_exhaust")?)
            .ok_or_else(|| NonceError::Dynamo("family row invalid on_exhaust".into()))?;
        let active_hash = required_s("active_hash")?
            .parse::<B256>()
            .map_err(|e| NonceError::Dynamo(format!("family row invalid active_hash: {e}")))?;
        let max_total_fee_wei = parse_u256(&item, "max_total_fee_ceiling")
            .ok_or_else(|| NonceError::Dynamo("family row invalid max_total_fee_ceiling".into()))?;
        Ok(Some(ReplacementFamily {
            wallet: address,
            nonce,
            chain_id: required_n("chain_id")?,
            to,
            value,
            data: data.into(),
            gas_limit: required_n("gas_limit")?,
            policy: ResolvedReplacementPolicy {
                fee_speed,
                bump_every_blocks: required_n("bump_every_blocks")?,
                max_bumps: required_n("max_bumps")? as u32,
                on_exhaust,
                max_fee_per_gas_wei: get_u128(&item, "max_fee_per_gas_ceiling").ok_or_else(
                    || NonceError::Dynamo("family row invalid max_fee_per_gas_ceiling".into()),
                )?,
                max_total_fee_wei,
            },
            active_generation: required_n("active_generation")? as u32,
            active_hash,
            active_max_fee_per_gas: get_u128(&item, "active_max_fee_per_gas").ok_or_else(|| {
                NonceError::Dynamo("family row invalid active_max_fee_per_gas".into())
            })?,
            active_max_priority_fee_per_gas: get_u128(&item, "active_max_priority_fee_per_gas")
                .ok_or_else(|| {
                    NonceError::Dynamo("family row invalid active_max_priority_fee_per_gas".into())
                })?,
            next_eligible_block: required_n("next_eligible_block")?,
            state: required_s("family_state")?,
        }))
    }

    /// Acquire a short block-denominated enqueue lease. A crash after this conditional
    /// update but before SQS send self-heals when `claim_until_block` expires; duplicate
    /// messages remain harmless because activation is generation-conditional.
    pub async fn claim_replacement(
        &self,
        address: Address,
        nonce: u64,
        expected_generation: u32,
        current_block: u64,
        lease_blocks: u64,
    ) -> Result<bool> {
        let next_generation = expected_generation.saturating_add(1);
        let out = self
            .client
            .update_item()
            .table_name(&self.table)
            .key("wallet", s(self.pk(&address)))
            .key("tx_hash", s(model::family_sk(nonce)))
            .update_expression(
                "SET claim_generation = :next, claim_until_block = :until, updated_at = :now",
            )
            .condition_expression(
                "family_state = :active AND active_generation = :expected AND next_eligible_block <= :current AND (attribute_not_exists(claim_until_block) OR claim_until_block < :current)",
            )
            .expression_attribute_values(":next", n(next_generation))
            .expression_attribute_values(":until", n(current_block.saturating_add(lease_blocks)))
            .expression_attribute_values(":now", s(now_rfc3339()))
            .expression_attribute_values(":active", s("ACTIVE"))
            .expression_attribute_values(":expected", n(expected_generation))
            .expression_attribute_values(":current", n(current_block))
            .send()
            .await;
        match out {
            Ok(_) => Ok(true),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|svc| svc.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(e) => Err(NonceError::Dynamo(e.to_string())),
        }
    }

    /// Release a lease after an SQS send failure. Conditional ownership prevents a late
    /// failure from clearing a newer generation's lease.
    pub async fn release_replacement_claim(
        &self,
        address: Address,
        nonce: u64,
        generation: u32,
    ) -> Result<()> {
        let out = self
            .client
            .update_item()
            .table_name(&self.table)
            .key("wallet", s(self.pk(&address)))
            .key("tx_hash", s(model::family_sk(nonce)))
            .update_expression("REMOVE claim_generation, claim_until_block")
            .condition_expression("claim_generation = :generation")
            .expression_attribute_values(":generation", n(generation))
            .send()
            .await;
        match out {
            Ok(_) => Ok(()),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|svc| svc.is_conditional_check_failed_exception()) =>
            {
                Ok(())
            }
            Err(e) => Err(NonceError::Dynamo(e.to_string())),
        }
    }

    /// Mark a family exhausted without changing its active signed candidate.
    pub async fn mark_replacement_exhausted(
        &self,
        family: &ReplacementFamily,
        reason: &str,
    ) -> Result<bool> {
        let now = now_rfc3339();
        let update_family = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&family.wallet)))
                    .key("tx_hash", s(model::family_sk(family.nonce)))
                    .update_expression(
                        "SET family_state = :exhausted, exhaustion_reason = :reason, updated_at = :now REMOVE claim_generation, claim_until_block",
                    )
                    .condition_expression("family_state = :active AND active_generation = :generation")
                    .expression_attribute_values(":exhausted", s("EXHAUSTED"))
                    .expression_attribute_values(":reason", s(reason))
                    .expression_attribute_values(":now", s(now.clone()))
                    .expression_attribute_values(":active", s("ACTIVE"))
                    .expression_attribute_values(":generation", n(family.active_generation))
                    .build(),
            )?)
            .build();
        let update_tracker = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&family.wallet)))
                    .key(
                        "tx_hash",
                        s(format!("{:?}", family.active_hash).to_lowercase()),
                    )
                    .update_expression("SET replacement_exhausted = :true, updated_at = :now")
                    .condition_expression("replacement_active = :true")
                    .expression_attribute_values(":true", b(true))
                    .expression_attribute_values(":now", s(now))
                    .build(),
            )?)
            .build();
        match self.transact(vec![update_family, update_tracker]).await? {
            None => Ok(true),
            Some(codes) if cond_failed(&codes, 0) => Ok(false),
            Some(codes) => Err(NonceError::Dynamo(format!(
                "mark_replacement_exhausted transaction cancelled: {codes:?}"
            ))),
        }
    }

    /// Terminalize a family after the nonce is finalized and before the winning
    /// tracker leaves active status. Legacy transactions have no family row and return
    /// `Ok(false)`. The TTL prevents internal family rows leaking forever.
    pub async fn complete_replacement_family(
        &self,
        address: Address,
        nonce: u64,
        winner_hash: B256,
        outcome: &str,
        ttl_epoch_secs: i64,
    ) -> Result<bool> {
        let out = self
            .client
            .update_item()
            .table_name(&self.table)
            .key("wallet", s(self.pk(&address)))
            .key("tx_hash", s(model::family_sk(nonce)))
            .update_expression(
                "SET family_state = :outcome, winner_hash = :winner, updated_at = :now, #ttl = :ttl REMOVE claim_generation, claim_until_block",
            )
            .condition_expression(
                "attribute_exists(tx_hash) AND (family_state IN (:active, :exhausted) OR ((:outcome = :confirmed OR :outcome = :failed) AND family_state = :consumed))",
            )
            .expression_attribute_names("#ttl", "ttl")
            .expression_attribute_values(":outcome", s(outcome))
            .expression_attribute_values(":active", s("ACTIVE"))
            .expression_attribute_values(":exhausted", s("EXHAUSTED"))
            .expression_attribute_values(":consumed", s("CONSUMED"))
            .expression_attribute_values(":confirmed", s("CONFIRMED"))
            .expression_attribute_values(":failed", s("FAILED"))
            .expression_attribute_values(
                ":winner",
                s(format!("{winner_hash:?}").to_lowercase()),
            )
            .expression_attribute_values(":now", s(now_rfc3339()))
            .expression_attribute_values(":ttl", n(ttl_epoch_secs))
            .send()
            .await;
        match out {
            Ok(_) => Ok(true),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|svc| svc.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(e) => Err(NonceError::Dynamo(e.to_string())),
        }
    }

    /// Atomically append a signed replacement and make it active. The prior candidate
    /// remains PENDING but `replacement_active=false`: the watcher continues receipt
    /// checks (an earlier candidate may still win) but never re-injects or bumps it.
    #[allow(clippy::too_many_arguments)]
    pub async fn activate_replacement(
        &self,
        family: &ReplacementFamily,
        new_hash: B256,
        signed_raw_tx: &[u8],
        new_max_fee_per_gas: u128,
        new_max_priority_fee_per_gas: u128,
        current_block: u64,
        action: &str,
    ) -> Result<bool> {
        validate_signed_raw_tx(signed_raw_tx)?;
        let new_generation = family.active_generation.saturating_add(1);
        let new_hash_hex = format!("{new_hash:?}").to_lowercase();
        let old_hash_hex = format!("{:?}", family.active_hash).to_lowercase();
        let now = now_rfc3339();
        let next_eligible = current_block.saturating_add(family.policy.bump_every_blocks);

        let update_family = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&family.wallet)))
                    .key("tx_hash", s(model::family_sk(family.nonce)))
                    .update_expression(
                        "SET active_generation = :newgen, active_hash = :newhash, active_max_fee_per_gas = :mf, active_max_priority_fee_per_gas = :pf, next_eligible_block = :nextblock, updated_at = :now REMOVE claim_generation, claim_until_block",
                    )
                    .condition_expression(
                        "family_state = :active AND active_generation = :oldgen AND active_hash = :oldhash AND claim_generation = :newgen",
                    )
                    .expression_attribute_values(":newgen", n(new_generation))
                    .expression_attribute_values(":newhash", s(new_hash_hex.clone()))
                    .expression_attribute_values(":mf", n(new_max_fee_per_gas))
                    .expression_attribute_values(":pf", n(new_max_priority_fee_per_gas))
                    .expression_attribute_values(":nextblock", n(next_eligible))
                    .expression_attribute_values(":now", s(now.clone()))
                    .expression_attribute_values(":active", s("ACTIVE"))
                    .expression_attribute_values(":oldgen", n(family.active_generation))
                    .expression_attribute_values(":oldhash", s(old_hash_hex.clone()))
                    .build(),
            )?)
            .build();

        let update_old = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&family.wallet)))
                    .key("tx_hash", s(old_hash_hex))
                    .update_expression(
                        "SET replacement_active = :false, replacement_successor_hash = :newhash, updated_at = :now",
                    )
                    .condition_expression(
                        "replacement_active = :true AND replacement_generation = :oldgen AND (#st = :signed OR #st = :pending)",
                    )
                    .expression_attribute_names("#st", "status")
                    .expression_attribute_values(":false", b(false))
                    .expression_attribute_values(":true", b(true))
                    .expression_attribute_values(":newhash", s(new_hash_hex.clone()))
                    .expression_attribute_values(":now", s(now.clone()))
                    .expression_attribute_values(":oldgen", n(family.active_generation))
                    .expression_attribute_values(":signed", s("SIGNED"))
                    .expression_attribute_values(":pending", s("PENDING"))
                    .build(),
            )?)
            .build();

        let put_new = TransactWriteItem::builder()
            .put(map_build(
                Put::builder()
                    .table_name(&self.table)
                    .item("wallet", s(self.pk(&family.wallet)))
                    .item("tx_hash", s(new_hash_hex.clone()))
                    .item("status", s("SIGNED"))
                    .item("chain_id", n(self.chain_id))
                    .item("nonce", n(family.nonce))
                    .item(
                        "signed_raw_tx",
                        s(format!("0x{}", hex_encode(signed_raw_tx))),
                    )
                    .item("submitted_at", s(now.clone()))
                    .item("max_fee_per_gas", n(new_max_fee_per_gas))
                    .item("max_priority_fee_per_gas", n(new_max_priority_fee_per_gas))
                    .item("family_nonce", n(family.nonce))
                    .item("replacement_generation", n(new_generation))
                    .item("replacement_active", b(true))
                    .item("replacement_action", s(action))
                    .item("next_eligible_replacement_block", n(next_eligible))
                    .item("replacement_max_bumps", n(family.policy.max_bumps))
                    .item(
                        "replacement_on_exhaust",
                        s(family.policy.on_exhaust.as_str()),
                    )
                    .condition_expression("attribute_not_exists(tx_hash)")
                    .build(),
            )?)
            .build();

        let update_reservation = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&family.wallet)))
                    .key("tx_hash", s(model::reservation_sk(family.nonce)))
                    .update_expression(
                        "SET real_tx_hash = :newhash, max_fee_per_gas = :mf, max_priority_fee_per_gas = :pf, updated_at = :now",
                    )
                    .condition_expression("#st = :signed OR #st = :broadcast")
                    .expression_attribute_names("#st", "state")
                    .expression_attribute_values(":newhash", s(new_hash_hex))
                    .expression_attribute_values(":mf", n(new_max_fee_per_gas))
                    .expression_attribute_values(":pf", n(new_max_priority_fee_per_gas))
                    .expression_attribute_values(":now", s(now))
                    .expression_attribute_values(":signed", s(ReservationState::Signed.as_str()))
                    .expression_attribute_values(":broadcast", s(ReservationState::Broadcast.as_str()))
                    .build(),
            )?)
            .build();

        match self
            .transact(vec![update_family, update_old, put_new, update_reservation])
            .await?
        {
            None => Ok(true),
            Some(codes) if cond_failed(&codes, 0) => Ok(false),
            Some(codes) => Err(NonceError::Dynamo(format!(
                "activate_replacement transaction cancelled: {codes:?}"
            ))),
        }
    }

    // ---- confirm ----

    /// Retire a `SIGNED` reservation whose **first** `eth_sendRawTransaction` was
    /// definitively refused by the node, so the bytes never entered any mempool.
    ///
    /// Only the broadcaster may call this, and only for a rejection classified
    /// [`SendRejection::Definitive`](crate::send_error::SendRejection::Definitive) on the
    /// very first send of bytes that have never left the process. The watcher must
    /// **not** use it for rebroadcast outcomes: bytes from an earlier ambiguous send may
    /// still be gossiping and could mine later.
    ///
    /// One `TransactWriteItems`:
    /// 1. delete the reservation, conditional on `state = SIGNED` (never `BROADCAST`);
    /// 2. move the tracker row `SIGNED -> REJECTED`, recording the node's reason and a
    ///    terminal `ttl` (`ttl_epoch_secs`), conditional on `status = SIGNED`;
    /// 3. decrement `pending_count` (conditional on it being positive);
    /// 4. recycle the nonce into the gap pool — a definitively refused nonce is unused;
    /// 5. delete any replacement-family row for the recycled nonce, so its conditional
    ///    create cannot poison the next request that reuses the gap.
    ///
    /// Returns `Ok(true)` when retired, `Ok(false)` when the reservation or tracker is no
    /// longer `SIGNED` (already broadcast or already resolved — nothing to retire).
    pub async fn reject_signed(
        &self,
        address: Address,
        nonce: u64,
        tx_hash: B256,
        reason: &str,
        ttl_epoch_secs: i64,
    ) -> Result<bool> {
        let hash_hex = format!("{tx_hash:?}").to_lowercase();
        let now = now_rfc3339();
        // Bound the stored reason; the node message is untrusted input.
        let reason: String = reason.chars().take(512).collect();

        let delete_reservation = TransactWriteItem::builder()
            .delete(map_build(
                Delete::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&address)))
                    .key("tx_hash", s(model::reservation_sk(nonce)))
                    .condition_expression("#st = :signed")
                    .expression_attribute_names("#st", "state")
                    .expression_attribute_values(":signed", s(ReservationState::Signed.as_str()))
                    .build(),
            )?)
            .build();
        let update_tracker = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&address)))
                    .key("tx_hash", s(hash_hex.clone()))
                    .update_expression(
                        "SET #st = :rejected, #err = :reason, updated_at = :now, #ttl = :ttl",
                    )
                    .condition_expression("#st = :signed")
                    .expression_attribute_names("#st", "status")
                    .expression_attribute_names("#err", "error")
                    .expression_attribute_names("#ttl", "ttl")
                    .expression_attribute_values(":rejected", s("REJECTED"))
                    .expression_attribute_values(":signed", s("SIGNED"))
                    .expression_attribute_values(":reason", s(reason))
                    .expression_attribute_values(":now", s(now.clone()))
                    .expression_attribute_values(":ttl", n(ttl_epoch_secs))
                    .build(),
            )?)
            .build();
        let dec_pending = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&address)))
                    .key("tx_hash", s(model::NONCE_STATE_SK))
                    .update_expression("ADD pending_count :neg SET updated_at = :now")
                    .condition_expression("attribute_exists(next_nonce) AND pending_count > :zero")
                    .expression_attribute_values(":neg", n(-1))
                    .expression_attribute_values(":zero", n(0))
                    .expression_attribute_values(":now", s(now))
                    .build(),
            )?)
            .build();
        let put_gap = TransactWriteItem::builder()
            .put(map_build(
                Put::builder()
                    .table_name(&self.table)
                    .key_gap(&self.pk(&address), nonce)
                    .build(),
            )?)
            .build();
        // Unconditional delete is safe for legacy/non-family transactions (deleting a
        // missing item is a no-op) and atomic with recycling for family transactions.
        let delete_family = TransactWriteItem::builder()
            .delete(map_build(
                Delete::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(&address)))
                    .key("tx_hash", s(model::family_sk(nonce)))
                    .build(),
            )?)
            .build();

        match self
            .transact(vec![
                delete_reservation,
                update_tracker,
                dec_pending,
                put_gap,
                delete_family,
            ])
            .await?
        {
            None => {
                warn!(
                    wallet = ?address,
                    nonce,
                    tx_hash = %hash_hex,
                    "Node definitively rejected first send; reservation retired and nonce recycled"
                );
                Ok(true)
            }
            Some(codes) if cond_failed(&codes, 0) || cond_failed(&codes, 1) => {
                debug!(
                    wallet = ?address,
                    nonce,
                    tx_hash = %hash_hex,
                    "reject_signed is a no-op (reservation/tracker no longer SIGNED)"
                );
                Ok(false)
            }
            Some(codes) => Err(NonceError::Dynamo(format!(
                "reject_signed transaction cancelled: {codes:?}"
            ))),
        }
    }

    /// Mark a nonce confirmed on-chain. Idempotent, decrements `pending_count` exactly
    /// once per nonce, and advances the confirmed watermark, draining a contiguous run of
    /// out-of-order `confirmed#` markers above it. No item is acted on twice within a
    /// single transaction.
    ///
    /// The per-transaction drain is capped at [`MAX_DRAIN_MARKERS`] to stay within
    /// DynamoDB's 100-item `TransactWriteItems` limit. If a contiguous run of confirmed
    /// markers exceeds the cap, the primary transaction advances as far as it can and the
    /// remainder is drained by [`Self::drain_residual_markers`] in additional bounded,
    /// idempotent transactions — no marker is ever lost.
    pub async fn confirm_transaction(&self, address: Address, nonce: u64) -> Result<()> {
        // The primary confirm advances the watermark by at most `MAX_DRAIN_MARKERS`
        // markers. Only when it reports the drain was capped do we continue draining the
        // residual run, keeping the common (no-residue) path free of extra reads.
        if self.confirm_one(address, nonce).await? {
            self.drain_residual_markers(address).await?;
        }
        Ok(())
    }

    /// Perform this nonce's confirm in a single bounded transaction. Returns `true` when
    /// the marker drain was capped (a residual run may remain above the new watermark),
    /// `false` otherwise.
    async fn confirm_one(&self, address: Address, nonce: u64) -> Result<bool> {
        for _ in 0..CONFIRM_MAX_RETRIES {
            let Some(state) = self.get_nonce_state(&address, true).await? else {
                // Nothing to confirm against; treat as idempotent no-op.
                return Ok(false);
            };
            let confirmed = get_n(&state, "confirmed_nonce").unwrap_or(0);

            if nonce < confirmed {
                // The watermark is already past this nonce. Normally that means this
                // nonce was confirmed earlier (idempotent replay) and only residue remains.
                // But monotonic reconciliation (`reconcile_upward` / `force_sync`) can
                // raise `confirmed_nonce` past a reservation that is still live — it never
                // touches `pending_count`. If that reservation is still here, retire it
                // and release its pending slot atomically; otherwise this would leak one
                // `pending_count` per reconciled-over confirmation and eventually wedge
                // the wallet at `max_pending_per_wallet`.
                self.retire_below_watermark(&address, nonce).await?;
                return Ok(false);
            }

            let in_order = nonce == confirmed;
            let (new_watermark, drained) = if in_order {
                // Gather the contiguous run of out-of-order markers above the watermark
                // (the async I/O), bounded by the item cap, then let the pure
                // `drain_watermark` compute the advance. `checked_add` guards the top of
                // the u64 range so a run approaching `u64::MAX` cannot overflow.
                let mut present = std::collections::BTreeSet::new();
                if let Some(mut probe) = confirmed.checked_add(1) {
                    while present.len() < MAX_DRAIN_MARKERS
                        && self.marker_exists(&address, probe).await?
                    {
                        present.insert(probe);
                        match probe.checked_add(1) {
                            Some(next) => probe = next,
                            None => break,
                        }
                    }
                }
                model::drain_watermark(confirmed, |w| present.contains(&w))
            } else {
                (confirmed, Vec::new())
            };

            let mut items: Vec<TransactWriteItem> = Vec::new();

            // Advance watermark (in-order) and always decrement pending by one, guarded so
            // a concurrent watermark change forces a retry.
            let ns_update = Update::builder()
                .table_name(&self.table)
                .key("wallet", s(self.pk(&address)))
                .key("tx_hash", s(model::NONCE_STATE_SK))
                .update_expression(
                    "SET confirmed_nonce = :wm, updated_at = :now ADD pending_count :neg",
                )
                .condition_expression("confirmed_nonce = :cur")
                .expression_attribute_values(":wm", n(new_watermark))
                .expression_attribute_values(":cur", n(confirmed))
                .expression_attribute_values(":neg", n(-1))
                .expression_attribute_values(":now", s(now_rfc3339()))
                .build();
            items.push(
                TransactWriteItem::builder()
                    .update(map_build(ns_update)?)
                    .build(),
            );

            // Retire this nonce's reservation exactly once (condition guarantees single decrement).
            items.push(
                TransactWriteItem::builder()
                    .delete(map_build(
                        Delete::builder()
                            .table_name(&self.table)
                            .key("wallet", s(self.pk(&address)))
                            .key("tx_hash", s(model::reservation_sk(nonce)))
                            .condition_expression("attribute_exists(tx_hash)")
                            .build(),
                    )?)
                    .build(),
            );

            // Drop any gap entry for this nonce (chain spent it; never reuse).
            items.push(
                TransactWriteItem::builder()
                    .delete(map_build(
                        Delete::builder()
                            .table_name(&self.table)
                            .key("wallet", s(self.pk(&address)))
                            .key("tx_hash", s(model::gap_sk(nonce)))
                            .build(),
                    )?)
                    .build(),
            );

            if in_order {
                // Delete the drained out-of-order markers.
                for m in &drained {
                    items.push(
                        TransactWriteItem::builder()
                            .delete(map_build(
                                Delete::builder()
                                    .table_name(&self.table)
                                    .key("wallet", s(self.pk(&address)))
                                    .key("tx_hash", s(model::confirmed_sk(*m)))
                                    .build(),
                            )?)
                            .build(),
                    );
                }
            } else {
                // Out-of-order: leave a marker so a later in-order confirm drains it.
                items.push(
                    TransactWriteItem::builder()
                        .put(map_build(
                            Put::builder()
                                .table_name(&self.table)
                                .item("wallet", s(self.pk(&address)))
                                .item("tx_hash", s(model::confirmed_sk(nonce)))
                                .item("nonce", n(nonce))
                                .build(),
                        )?)
                        .build(),
                );
            }

            match self.transact(items).await? {
                None => {
                    info!(wallet = ?address, nonce, confirmed_watermark = new_watermark, "Transaction confirmed");
                    // Signal a capped drain so the caller finishes any residual run.
                    return Ok(in_order && drained.len() == MAX_DRAIN_MARKERS);
                }
                Some(codes) => {
                    // Reservation already gone (idempotent replay) => item index 1.
                    if cond_failed(&codes, 1) {
                        debug!(wallet = ?address, nonce, "confirm is a no-op (reservation already retired)");
                        return Ok(false);
                    }
                    // Watermark moved under us (index 0) => retry.
                    if cond_failed(&codes, 0) {
                        continue;
                    }
                    return Err(NonceError::Dynamo(format!(
                        "confirm_transaction cancelled: {codes:?}"
                    )));
                }
            }
        }
        Err(NonceError::Dynamo(
            "confirm_transaction exhausted watermark retries".to_string(),
        ))
    }

    /// Drain a residual contiguous run of `confirmed#` markers sitting **at** the
    /// confirmed watermark — left behind when a single `confirm_one` capped its drain at
    /// [`MAX_DRAIN_MARKERS`]. Each drained nonce was confirmed out of order, so its
    /// `pending_count` was already decremented and its reservation already retired when
    /// its marker was written; advancing over it is therefore a marker-only watermark
    /// move that touches neither `pending_count` nor any reservation.
    ///
    /// A marker can only sit at the watermark as capped-drain residue (an out-of-order
    /// confirm always writes its marker strictly above the watermark), so this is a
    /// no-op in normal operation. Progress is made in bounded, idempotent transactions
    /// (1 nonce-state update + up to `MAX_DRAIN_MARKERS` deletes, well within the
    /// 100-item limit); the watermark only ever advances over markers deleted in the
    /// same transaction, so no marker is lost, and the loop terminates because each
    /// success strictly advances the (monotonic) watermark over a finite marker set.
    async fn drain_residual_markers(&self, address: Address) -> Result<()> {
        loop {
            let Some(state) = self.get_nonce_state(&address, true).await? else {
                return Ok(());
            };
            let watermark = get_n(&state, "confirmed_nonce").unwrap_or(0);

            // Gather the contiguous run of markers starting at the watermark, bounded by
            // the item cap. A marker at the watermark itself is the residue signal.
            let mut probe = watermark;
            let mut drained: Vec<u64> = Vec::new();
            while drained.len() < MAX_DRAIN_MARKERS && self.marker_exists(&address, probe).await? {
                drained.push(probe);
                match probe.checked_add(1) {
                    Some(next) => probe = next,
                    None => break,
                }
            }
            if drained.is_empty() {
                return Ok(()); // no residue at the watermark — done
            }
            let new_watermark = drained
                .last()
                .map(|w| w.saturating_add(1))
                .unwrap_or(watermark);

            let mut items: Vec<TransactWriteItem> = Vec::new();
            // Advance the watermark only; `pending_count` is untouched (already
            // decremented when each of these nonces confirmed out of order).
            items.push(
                TransactWriteItem::builder()
                    .update(map_build(
                        Update::builder()
                            .table_name(&self.table)
                            .key("wallet", s(self.pk(&address)))
                            .key("tx_hash", s(model::NONCE_STATE_SK))
                            .update_expression("SET confirmed_nonce = :wm, updated_at = :now")
                            .condition_expression("confirmed_nonce = :cur")
                            .expression_attribute_values(":wm", n(new_watermark))
                            .expression_attribute_values(":cur", n(watermark))
                            .expression_attribute_values(":now", s(now_rfc3339()))
                            .build(),
                    )?)
                    .build(),
            );
            for m in &drained {
                items.push(
                    TransactWriteItem::builder()
                        .delete(map_build(
                            Delete::builder()
                                .table_name(&self.table)
                                .key("wallet", s(self.pk(&address)))
                                .key("tx_hash", s(model::confirmed_sk(*m)))
                                .build(),
                        )?)
                        .build(),
                );
            }

            match self.transact(items).await? {
                None => {
                    debug!(wallet = ?address, from = watermark, to = new_watermark, "Drained residual confirmed markers");
                    // If the drain was capped again, loop to continue; else the run ended.
                    if drained.len() < MAX_DRAIN_MARKERS {
                        return Ok(());
                    }
                }
                Some(codes) => {
                    // Watermark moved under us — re-read and retry.
                    if cond_failed(&codes, 0) {
                        continue;
                    }
                    return Err(NonceError::Dynamo(format!(
                        "drain_residual_markers cancelled: {codes:?}"
                    )));
                }
            }
        }
    }

    /// Retire a nonce that is already **below** the confirmed watermark.
    ///
    /// Invariant this protects: `pending_count` equals the number of live `reservation#`
    /// rows. Every path that deletes a reservation must decrement `pending_count` in the
    /// same transaction. Reconciliation raises `confirmed_nonce` without touching
    /// reservations, so a below-watermark confirm may still find a live reservation here.
    ///
    /// One `TransactWriteItems`: delete the reservation (conditional on it existing),
    /// decrement `pending_count` (conditional on it being positive), and sweep the gap and
    /// out-of-order marker for this nonce. Cancellation reasons:
    /// - index 0 failed → no reservation: an idempotent replay, sweep residue only;
    /// - index 1 failed → a live reservation but `pending_count` is already zero: the
    ///   counter has drifted low, so retire the reservation without decrementing rather
    ///   than leave it to be retried forever.
    async fn retire_below_watermark(&self, address: &Address, nonce: u64) -> Result<()> {
        let delete_reservation = TransactWriteItem::builder()
            .delete(map_build(
                Delete::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(address)))
                    .key("tx_hash", s(model::reservation_sk(nonce)))
                    .condition_expression("attribute_exists(tx_hash)")
                    .build(),
            )?)
            .build();
        let dec_pending = TransactWriteItem::builder()
            .update(map_build(
                Update::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(address)))
                    .key("tx_hash", s(model::NONCE_STATE_SK))
                    .update_expression("ADD pending_count :neg SET updated_at = :now")
                    .condition_expression("pending_count > :zero")
                    .expression_attribute_values(":neg", n(-1))
                    .expression_attribute_values(":zero", n(0))
                    .expression_attribute_values(":now", s(now_rfc3339()))
                    .build(),
            )?)
            .build();
        let delete_gap = TransactWriteItem::builder()
            .delete(map_build(
                Delete::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(address)))
                    .key("tx_hash", s(model::gap_sk(nonce)))
                    .build(),
            )?)
            .build();
        let delete_marker = TransactWriteItem::builder()
            .delete(map_build(
                Delete::builder()
                    .table_name(&self.table)
                    .key("wallet", s(self.pk(address)))
                    .key("tx_hash", s(model::confirmed_sk(nonce)))
                    .build(),
            )?)
            .build();

        match self
            .transact(vec![
                delete_reservation,
                dec_pending,
                delete_gap,
                delete_marker,
            ])
            .await?
        {
            None => {
                info!(
                    wallet = ?address,
                    nonce,
                    "Retired live reservation below the confirmed watermark; pending slot released"
                );
                Ok(())
            }
            Some(codes) if cond_failed(&codes, 0) => {
                debug!(wallet = ?address, nonce, "confirm below watermark is a no-op (no live reservation)");
                self.cleanup_confirmed_residue(address, nonce).await;
                Ok(())
            }
            Some(codes) if cond_failed(&codes, 1) => {
                warn!(
                    wallet = ?address,
                    nonce,
                    "Live reservation below watermark but pending_count is already 0; retiring without decrement"
                );
                self.cleanup_confirmed_residue(address, nonce).await;
                Ok(())
            }
            Some(codes) => Err(NonceError::Dynamo(format!(
                "retire_below_watermark cancelled: {codes:?}"
            ))),
        }
    }

    /// Best-effort cleanup of residual markers for a nonce already below the watermark.
    async fn cleanup_confirmed_residue(&self, address: &Address, nonce: u64) {
        for sk in [
            model::reservation_sk(nonce),
            model::gap_sk(nonce),
            model::confirmed_sk(nonce),
        ] {
            let _ = self
                .client
                .delete_item()
                .table_name(&self.table)
                .key("wallet", s(self.pk(address)))
                .key("tx_hash", s(sk))
                .send()
                .await;
        }
    }

    // ---- diagnostics / reads ----

    /// Detect nonce gaps (holes between the confirmed watermark and `next_nonce` that
    /// have neither a live reservation nor an existing gap entry).
    pub async fn detect_gaps(&self, address: Address) -> Result<Vec<u64>> {
        let Some(state) = self.get_nonce_state(&address, true).await? else {
            return Ok(vec![]);
        };
        let confirmed = get_n(&state, "confirmed_nonce").unwrap_or(0);
        let next = get_n(&state, "next_nonce").unwrap_or(0);

        let reservations = self
            .query_prefix(&address, model::RESERVATION_PREFIX, false)
            .await?;
        let reserved: std::collections::BTreeSet<u64> = reservations
            .iter()
            .filter_map(|i| get_n(i, "nonce"))
            .collect();
        let existing_gaps: std::collections::BTreeSet<u64> = self
            .get_available_gaps(address)
            .await?
            .into_iter()
            .collect();

        let gaps: Vec<u64> = (confirmed..next)
            .filter(|nc| !reserved.contains(nc) && !existing_gaps.contains(nc))
            .collect();
        if !gaps.is_empty() {
            warn!(wallet = ?address, gaps = ?gaps, "Nonce gaps detected");
        }
        Ok(gaps)
    }

    /// Reconcile wallet state upward against the chain **without destroying in-flight
    /// state**. Despite the historical name (kept for API compatibility), this is
    /// monotonic and non-destructive, matching the same contract as
    /// [`Self::reconcile_upward`]: it **never** deletes reservation/gap/confirmed rows
    /// and **never** lowers `next_nonce`, `confirmed_nonce`, or `pending_count`. It
    /// re-reads the chain's pending/latest counts and conditionally raises
    /// `next_nonce`/`confirmed_nonce` only when the stored value is strictly behind the
    /// chain, so an already-consumed nonce can never be re-issued and ahead-of-chain
    /// in-flight work is preserved. If no state row exists yet it seeds one from the
    /// chain. Returns `(old_next_nonce, new_next_nonce)`.
    pub async fn force_sync(&self, address: Address) -> Result<(u64, u64)> {
        let chain_pending = self
            .provider
            .get_transaction_count(address)
            .block_id(BlockNumberOrTag::Pending.into())
            .await?;
        let chain_confirmed = self
            .provider
            .get_transaction_count(address)
            .block_id(BlockNumberOrTag::Latest.into())
            .await?;

        let old = self
            .get_nonce_state(&address, true)
            .await?
            .and_then(|i| get_n(&i, "next_nonce"))
            .unwrap_or(0);

        // Seed a fresh row only if none exists; the conditional guard means an existing
        // row (and its counters/pending_count) is never overwritten.
        let seed = self
            .client
            .put_item()
            .table_name(&self.table)
            .item("wallet", s(self.pk(&address)))
            .item("tx_hash", s(model::NONCE_STATE_SK))
            .item("next_nonce", n(chain_pending))
            .item("confirmed_nonce", n(chain_confirmed))
            .item("pending_count", n(0))
            .item("updated_at", s(now_rfc3339()))
            .condition_expression("attribute_not_exists(tx_hash)")
            .send()
            .await;
        if let Err(e) = seed {
            let is_conditional = e
                .as_service_error()
                .map(|svc| svc.is_conditional_check_failed_exception())
                .unwrap_or(false);
            if !is_conditional {
                return Err(NonceError::Dynamo(e.to_string()));
            }
            // Row exists — raise counters monotonically toward the chain, never lowering.
            self.raise_counter_if_behind(&address, "next_nonce", chain_pending)
                .await?;
            self.raise_counter_if_behind(&address, "confirmed_nonce", chain_confirmed)
                .await?;
        }

        let new_next = self
            .get_nonce_state(&address, true)
            .await?
            .and_then(|i| get_n(&i, "next_nonce"))
            .unwrap_or(chain_pending);
        info!(wallet = ?address, old, new = new_next, chain_confirmed, "Wallet synced upward with chain (non-destructive)");
        Ok((old, new_next))
    }

    /// Get a single pending/in-flight transaction by nonce (from its reservation row).
    pub async fn get_pending_tx(
        &self,
        address: Address,
        nonce: u64,
    ) -> Result<Option<PendingTransaction>> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("wallet", s(self.pk(&address)))
            .key("tx_hash", s(model::reservation_sk(nonce)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| NonceError::Dynamo(e.to_string()))?;
        Ok(out.item.map(|i| reservation_to_pending(&i)))
    }

    /// Get all in-flight transactions for a wallet (reservation rows), nonce-ascending.
    pub async fn get_all_pending(&self, address: Address) -> Result<Vec<PendingTransaction>> {
        let rows = self
            .query_prefix(&address, model::RESERVATION_PREFIX, true)
            .await?;
        let mut txs: Vec<PendingTransaction> = rows.iter().map(reservation_to_pending).collect();
        txs.sort_by_key(|t| t.nonce);
        Ok(txs)
    }

    /// Find stuck transactions (older than the configured threshold).
    pub async fn find_stuck_transactions(
        &self,
        address: Address,
    ) -> Result<Vec<PendingTransaction>> {
        let pending = self.get_all_pending(address).await?;
        let stuck: Vec<_> = pending
            .into_iter()
            .filter(|tx| tx.is_stuck(self.config.stuck_threshold))
            .collect();
        if !stuck.is_empty() {
            warn!(wallet = ?address, count = stuck.len(), "Found stuck transactions");
        }
        Ok(stuck)
    }

    /// Discover stale `RESERVED` reservations for this chain via the `status-chain-index`
    /// GSI — nonces handed out but never signed (crash between reserve and sign). Only
    /// rows older than `config.reservation_stale_threshold` are returned.
    pub async fn find_stale_reservations(&self) -> Result<Vec<StaleReservation>> {
        let cutoff = chrono::Utc::now()
            - chrono::Duration::from_std(self.config.reservation_stale_threshold)
                .unwrap_or_else(|_| chrono::Duration::seconds(300));

        let mut result = Vec::new();
        let mut last: Option<HashMap<String, AttributeValue>> = None;
        loop {
            let mut req = self
                .client
                .query()
                .table_name(&self.table)
                .index_name(STATUS_CHAIN_INDEX)
                .key_condition_expression("#st = :reserved AND chain_id = :cid")
                .expression_attribute_names("#st", "status")
                .expression_attribute_values(":reserved", s(ReservationState::Reserved.as_str()))
                .expression_attribute_values(":cid", n(self.chain_id));
            if let Some(start) = last.take() {
                req = req.set_exclusive_start_key(Some(start));
            }
            let out = req
                .send()
                .await
                .map_err(|e| NonceError::Dynamo(e.to_string()))?;
            for item in out.items.unwrap_or_default() {
                let reserved_at = get_s(&item, "reserved_at")
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&chrono::Utc));
                // Only surface genuinely stale rows.
                if reserved_at.map(|ts| ts <= cutoff).unwrap_or(true)
                    && let Some(wallet_s) = get_s(&item, "wallet")
                    && let Ok(wallet) = wallet_s.parse::<Address>()
                    && let Some(nonce) = get_n(&item, "nonce")
                {
                    result.push(StaleReservation {
                        wallet,
                        nonce,
                        chain_id: self.chain_id,
                        reserved_at,
                    });
                }
            }
            match out.last_evaluated_key {
                Some(k) => last = Some(k),
                None => break,
            }
        }
        Ok(result)
    }

    /// Get comprehensive wallet state.
    pub async fn get_wallet_state(&self, address: Address) -> Result<WalletState> {
        let state = self.get_nonce_state(&address, true).await?;
        let next_nonce = state
            .as_ref()
            .and_then(|i| get_n(i, "next_nonce"))
            .unwrap_or(0);
        let confirmed_nonce = state
            .as_ref()
            .and_then(|i| get_n(i, "confirmed_nonce"))
            .unwrap_or(0);

        let pending_count = state
            .as_ref()
            .and_then(|i| get_n(i, "pending_count"))
            .unwrap_or(0);

        let reusable_gaps = self.get_available_gaps(address).await?;
        let gaps = self.detect_gaps(address).await?;
        let pending = self.get_all_pending(address).await?;

        let oldest_pending_age = pending
            .iter()
            .map(|tx| {
                chrono::Utc::now()
                    .signed_duration_since(tx.timestamp)
                    .to_std()
                    .unwrap_or(Duration::ZERO)
            })
            .max();

        Ok(WalletState {
            address,
            chain_id: self.chain_id,
            next_nonce,
            confirmed_nonce,
            pending_count,
            oldest_pending_age,
            gaps,
            reusable_gaps,
        })
    }

    /// Count of gap nonces available for reuse.
    pub async fn get_gap_count(&self, address: Address) -> Result<u64> {
        Ok(self.get_available_gaps(address).await?.len() as u64)
    }

    /// All gap nonces available for reuse, ascending.
    pub async fn get_available_gaps(&self, address: Address) -> Result<Vec<u64>> {
        let rows = self.query_prefix(&address, model::GAP_PREFIX, true).await?;
        // Derive the nonce from the sort key (authoritative) rather than the attribute.
        let mut gaps: Vec<u64> = rows
            .iter()
            .filter_map(|i| get_s(i, "tx_hash").and_then(model::nonce_from_sk))
            .collect();
        gaps.sort_unstable();
        Ok(gaps)
    }
}

/// Outcome of one gap-reuse attempt.
enum GapOutcome {
    Reserved(u64),
    NoGap,
    Contended,
    MaxPending { count: u64 },
}

/// Map a reservation row into a `PendingTransaction` snapshot.
fn reservation_to_pending(item: &HashMap<String, AttributeValue>) -> PendingTransaction {
    let nonce = get_n(item, "nonce").unwrap_or(0);
    let tx_hash = get_s(item, "real_tx_hash")
        .and_then(|h| h.parse::<B256>().ok())
        .unwrap_or(B256::ZERO);
    let timestamp = get_s(item, "signed_at")
        .or_else(|| get_s(item, "reserved_at"))
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now);
    let retry_count = get_n(item, "retry_count").unwrap_or(0) as u32;
    // A reservation snapshot is always in-flight from the caller's perspective; terminal
    // status lives on the durable tracker row, which the watcher owns.
    let status = TxStatus::Pending;
    PendingTransaction {
        nonce,
        tx_hash,
        gas_price: parse_u256(item, "gas_price"),
        max_fee_per_gas: parse_u256(item, "max_fee_per_gas"),
        max_priority_fee_per_gas: parse_u256(item, "max_priority_fee_per_gas"),
        timestamp,
        retry_count,
        status,
    }
}

/// Validate signed raw transaction bytes before any DynamoDB work: reject empty input
/// and anything larger than [`MAX_SIGNED_TX_BYTES`]. Pure and side-effect free so it is
/// unit-testable without an AWS endpoint.
fn validate_signed_raw_tx(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(NonceError::InvalidSignedTx(
            "signed raw transaction is empty".to_string(),
        ));
    }
    if bytes.len() > MAX_SIGNED_TX_BYTES {
        return Err(NonceError::InvalidSignedTx(format!(
            "signed raw transaction is {} bytes, exceeds the {}-byte limit",
            bytes.len(),
            MAX_SIGNED_TX_BYTES
        )));
    }
    Ok(())
}

/// Lowercase hex-encode without a dependency (avoids pulling `hex` into this crate).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Convenience extension so gap `Put`s read cleanly in the transaction builders.
trait PutBuilderExt {
    fn key_gap(self, wallet: &str, nonce: u64) -> Self;
}

impl PutBuilderExt for aws_sdk_dynamodb::types::builders::PutBuilder {
    fn key_gap(self, wallet: &str, nonce: u64) -> Self {
        self.item("wallet", s(wallet.to_string()))
            .item("tx_hash", s(model::gap_sk(nonce)))
            .item("nonce", n(nonce))
    }
}

#[cfg(test)]
mod tests {
    //! Pure key/model/state tests — no DynamoDB endpoint, no AWS calls, never skipped.

    use super::model::*;
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn replacement_family_key_round_trips_nonce() {
        assert_eq!(family_sk(42), "family#00000000000000000042");
        assert_eq!(nonce_from_sk(&family_sk(42)), Some(42));
        assert!(family_sk(9) < family_sk(10));
    }

    #[test]
    fn sort_keys_are_zero_padded_to_20_digits_and_sort_numerically() {
        assert_eq!(reservation_sk(42), "reservation#00000000000000000042");
        assert_eq!(gap_sk(42), "gap#00000000000000000042");
        assert_eq!(confirmed_sk(42), "confirmed#00000000000000000042");
        // Lexical ordering must equal numeric ordering.
        assert!(gap_sk(9) < gap_sk(10));
        assert!(gap_sk(10) < gap_sk(100));
        assert!(reservation_sk(u64::MAX) > reservation_sk(u64::MAX - 1));
    }

    #[test]
    fn nonce_round_trips_through_sort_keys() {
        for nonce in [0u64, 1, 42, 1_000_000, u64::MAX] {
            assert_eq!(nonce_from_sk(&reservation_sk(nonce)), Some(nonce));
            assert_eq!(nonce_from_sk(&gap_sk(nonce)), Some(nonce));
            assert_eq!(nonce_from_sk(&confirmed_sk(nonce)), Some(nonce));
        }
        // Non-namespaced sort keys yield no nonce.
        assert_eq!(nonce_from_sk(NONCE_STATE_SK), None);
        assert_eq!(nonce_from_sk("0xabc123"), None);
    }

    #[test]
    fn wallet_pk_is_lowercased_hex_address() {
        let addr: Address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
            .parse()
            .unwrap();
        let pk = wallet_pk(&addr);
        assert_eq!(pk, "0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
        // Must round-trip back to the same address the watcher re-derives.
        assert_eq!(pk.parse::<Address>().unwrap(), addr);
    }

    #[test]
    fn drain_watermark_advances_over_contiguous_markers_only() {
        // No markers present -> advance by exactly one.
        let (wm, drained) = drain_watermark(5, |_| false);
        assert_eq!(wm, 6);
        assert!(drained.is_empty());

        // Contiguous out-of-order markers 6,7 present but 8 absent.
        let present: BTreeSet<u64> = [6, 7].into_iter().collect();
        let (wm, drained) = drain_watermark(5, |w| present.contains(&w));
        assert_eq!(wm, 8, "watermark drains through 6,7 to 8");
        assert_eq!(drained, vec![6, 7]);

        // A gap in the markers stops the drain (9 present but 8 missing => stop at 6).
        let present: BTreeSet<u64> = [9].into_iter().collect();
        let (wm, drained) = drain_watermark(5, |w| present.contains(&w));
        assert_eq!(wm, 6);
        assert!(drained.is_empty());
    }

    #[test]
    fn reservation_state_round_trips() {
        for st in [
            ReservationState::Reserved,
            ReservationState::Signed,
            ReservationState::Broadcast,
        ] {
            assert_eq!(ReservationState::from_str(st.as_str()), Some(st));
        }
        assert_eq!(ReservationState::from_str("NOPE"), None);
    }

    #[test]
    fn cond_failed_reads_reason_codes_by_index() {
        let codes = vec![
            Some("ConditionalCheckFailed".to_string()),
            Some("None".to_string()),
            None,
        ];
        assert!(super::cond_failed(&codes, 0));
        assert!(!super::cond_failed(&codes, 1));
        assert!(!super::cond_failed(&codes, 2));
        assert!(!super::cond_failed(&codes, 9));
    }

    #[test]
    fn hex_encode_is_lowercase_and_exact() {
        assert_eq!(hex_encode(&[0x02, 0xf8, 0x00, 0xff]), "02f800ff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn validate_signed_raw_tx_rejects_empty_and_oversized() {
        // Empty input is rejected before any DynamoDB work.
        assert!(matches!(
            super::validate_signed_raw_tx(&[]),
            Err(NonceError::InvalidSignedTx(_))
        ));
        // A small, realistic transaction is accepted.
        assert!(super::validate_signed_raw_tx(&[0x02; 128]).is_ok());
        // Exactly at the limit is accepted; one byte over is rejected.
        let at_limit = vec![0u8; MAX_SIGNED_TX_BYTES];
        assert!(super::validate_signed_raw_tx(&at_limit).is_ok());
        let over_limit = vec![0u8; MAX_SIGNED_TX_BYTES + 1];
        assert!(matches!(
            super::validate_signed_raw_tx(&over_limit),
            Err(NonceError::InvalidSignedTx(_))
        ));
        // The bound must account for the 2x hex expansion plus the `0x` prefix that
        // `record_signed` applies before storing the bytes, and still leave room under
        // DynamoDB's 400 KiB item limit for the tracker's other attributes. That
        // invariant is enforced at compile time by the `const _` assert on the constant.
    }

    #[test]
    fn drain_watermark_caps_at_max_markers() {
        // An unbounded run of present markers drains exactly MAX_DRAIN_MARKERS and the
        // watermark advances by exactly that many (plus the in-order nonce).
        let (wm, drained) = drain_watermark(0, |_| true);
        assert_eq!(drained.len(), MAX_DRAIN_MARKERS);
        assert_eq!(drained.first(), Some(&1));
        assert_eq!(drained.last(), Some(&(MAX_DRAIN_MARKERS as u64)));
        assert_eq!(wm, MAX_DRAIN_MARKERS as u64 + 1);
        // Watermark is always one past the last drained marker (never skips a marker).
        assert_eq!(wm, drained.last().unwrap() + 1);
    }

    #[test]
    fn drain_watermark_is_overflow_safe_at_u64_max() {
        // Confirming the maximum nonce: nothing exists above it, no panic, fixed point.
        let (wm, drained) = drain_watermark(u64::MAX, |_| true);
        assert_eq!(wm, u64::MAX);
        assert!(drained.is_empty());

        // A run reaching u64::MAX stops cleanly and the watermark saturates.
        let start = u64::MAX - 2;
        let (wm, drained) = drain_watermark(start, |_| true);
        assert_eq!(drained, vec![u64::MAX - 1, u64::MAX]);
        assert_eq!(wm, u64::MAX);
    }

    #[test]
    fn contiguous_markers_caps_and_is_overflow_safe() {
        // Respects the cap.
        let run = contiguous_markers(10, 3, |_| true);
        assert_eq!(run, vec![10, 11, 12]);
        // Stops at the first absent marker.
        let present: BTreeSet<u64> = [5, 6].into_iter().collect();
        let run = contiguous_markers(5, 96, |w| present.contains(&w));
        assert_eq!(run, vec![5, 6]);
        // Does not overflow when the probe reaches u64::MAX.
        let run = contiguous_markers(u64::MAX, 96, |_| true);
        assert_eq!(run, vec![u64::MAX]);
    }
}
