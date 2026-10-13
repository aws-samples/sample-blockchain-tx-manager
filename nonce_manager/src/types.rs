//! Core types for nonce management

use alloy::primitives::{Address, B256, U256};

/// Caller-facing fee urgency. The Lambda maps each tier to a live fee-history
/// percentile and base-fee headroom; the watcher merely carries the stored value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FeeSpeed {
    Slow,
    Standard,
    Fast,
}

impl FeeSpeed {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Slow => "slow",
            Self::Standard => "standard",
            Self::Fast => "fast",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "slow" => Some(Self::Slow),
            "standard" => Some(Self::Standard),
            "fast" => Some(Self::Fast),
            _ => None,
        }
    }
}

/// Action when no further policy-authorized speed-up can be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExhaustionAction {
    Hold,
    Cancel,
}

impl ExhaustionAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Cancel => "cancel",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "hold" => Some(Self::Hold),
            "cancel" => Some(Self::Cancel),
            _ => None,
        }
    }
}

/// Fully resolved immutable policy written with the original signed handoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedReplacementPolicy {
    pub fee_speed: FeeSpeed,
    pub bump_every_blocks: u64,
    pub max_bumps: u32,
    pub on_exhaust: ExhaustionAction,
    pub max_fee_per_gas_wei: u128,
    pub max_total_fee_wei: U256,
}

/// Initial immutable intent and policy for a same-nonce replacement family.
#[derive(Debug, Clone)]
pub struct ReplacementFamilyInit {
    pub to: Address,
    pub value: U256,
    pub data: alloy::primitives::Bytes,
    pub gas_limit: u64,
    pub policy: ResolvedReplacementPolicy,
    pub current_block: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

/// Consistent snapshot consumed by the replacement worker.
#[derive(Debug, Clone)]
pub struct ReplacementFamily {
    pub wallet: Address,
    pub nonce: u64,
    pub chain_id: u64,
    pub to: Address,
    pub value: U256,
    pub data: alloy::primitives::Bytes,
    pub gas_limit: u64,
    pub policy: ResolvedReplacementPolicy,
    pub active_generation: u32,
    pub active_hash: B256,
    pub active_max_fee_per_gas: u128,
    pub active_max_priority_fee_per_gas: u128,
    pub next_eligible_block: u64,
    pub state: String,
}
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Transaction status in the nonce manager
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxStatus {
    Pending,
    Confirmed,
    Failed,
    Replaced,
}

/// Lifecycle state of a per-nonce `reservation#<nonce>` row.
///
/// This is the internal recovery marker the nonce authority owns. It advances
/// monotonically `Reserved -> Signed -> Broadcast`:
///
/// * `Reserved` — nonce handed out, nothing signed yet. The row carries `status`
///   and `chain_id` attributes so it appears in the `status-chain-index` GSI and a
///   crash before signing is globally discoverable.
/// * `Signed` — a raw transaction has been signed and the durable tracker row
///   (keyed by the real tx hash) exists. The recovery marker (`status`/`chain_id`)
///   has been removed, so the reservation leaves the GSI.
/// * `Broadcast` — the raw transaction has been handed to the mempool.
///
/// A reservation may only be released/failed while `Reserved`; once `Signed` or
/// `Broadcast` the real tracker row exists and only the watcher may retire it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReservationState {
    Reserved,
    Signed,
    Broadcast,
}

impl ReservationState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReservationState::Reserved => "RESERVED",
            ReservationState::Signed => "SIGNED",
            ReservationState::Broadcast => "BROADCAST",
        }
    }

    /// Parse from the canonical uppercase wire form. Returns `Option` (not the
    /// fallible `FromStr` trait) because callers branch on validity rather than
    /// propagating a parse error.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "RESERVED" => Some(ReservationState::Reserved),
            "SIGNED" => Some(ReservationState::Signed),
            "BROADCAST" => Some(ReservationState::Broadcast),
            _ => None,
        }
    }
}

/// Pending transaction record.
///
/// Stored in DynamoDB on the per-nonce `reservation#<nonce>` row (fee fields, the
/// real tx hash, and timestamps are filled in by `record_signed`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransaction {
    pub nonce: u64,
    pub tx_hash: B256,
    pub gas_price: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub timestamp: DateTime<Utc>,
    pub retry_count: u32,
    pub status: TxStatus,
}

impl PendingTransaction {
    pub fn new(
        nonce: u64,
        tx_hash: B256,
        gas_price: Option<U256>,
        max_fee_per_gas: Option<U256>,
        max_priority_fee_per_gas: Option<U256>,
    ) -> Self {
        Self {
            nonce,
            tx_hash,
            gas_price,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            timestamp: Utc::now(),
            retry_count: 0,
            status: TxStatus::Pending,
        }
    }

    /// Check if transaction is stuck based on threshold
    pub fn is_stuck(&self, threshold: Duration) -> bool {
        let age = Utc::now().signed_duration_since(self.timestamp);
        age.to_std().map(|d| d > threshold).unwrap_or(false)
    }

    /// Calculate bumped gas price (for replacement tx)
    pub fn bumped_gas_price(&self, bump_percentage: u64) -> Option<U256> {
        self.gas_price.map(|gp| {
            let bump = gp * U256::from(bump_percentage) / U256::from(100);
            gp + bump
        })
    }

    /// Calculate bumped EIP-1559 fees
    pub fn bumped_eip1559_fees(&self, bump_percentage: u64) -> (Option<U256>, Option<U256>) {
        let bump = |v: Option<U256>| {
            v.map(|fee| {
                let increase = fee * U256::from(bump_percentage) / U256::from(100);
                fee + increase
            })
        };
        (
            bump(self.max_fee_per_gas),
            bump(self.max_priority_fee_per_gas),
        )
    }
}

/// Configuration for the nonce manager
#[derive(Debug, Clone)]
pub struct NonceManagerConfig {
    /// Maximum pending transactions per wallet before blocking new reservations
    pub max_pending_per_wallet: u64,

    /// Time after which a pending transaction is considered stuck
    pub stuck_threshold: Duration,

    /// Percentage to bump gas price for replacement transactions
    pub gas_bump_percentage: u64,

    /// Age after which a still-`RESERVED` reservation row is considered stale and
    /// surfaced by `find_stale_reservations` for crash recovery (reserved but never
    /// signed).
    pub reservation_stale_threshold: Duration,

    /// Advisory TTL horizon for resolved transaction data. The nonce authority never
    /// writes a `ttl` on unresolved work (reservation/tracker rows); the terminal
    /// watcher applies TTL once a transaction reaches a terminal state.
    pub pending_tx_ttl: Duration,
}

impl Default for NonceManagerConfig {
    fn default() -> Self {
        Self {
            max_pending_per_wallet: 100,
            stuck_threshold: Duration::from_secs(300), // 5 minutes
            gas_bump_percentage: 15,
            reservation_stale_threshold: Duration::from_secs(300), // 5 minutes
            pending_tx_ttl: Duration::from_secs(86400),            // 24 hours
        }
    }
}

/// Result of a nonce reservation attempt
#[derive(Debug)]
pub enum ReservationResult {
    Success(u64),
    MaxPendingExceeded { count: u64, max: u64 },
    NotInitialized,
}

/// Wallet state snapshot
#[derive(Debug, Clone)]
pub struct WalletState {
    pub address: Address,
    /// EVM chain ID this state belongs to
    pub chain_id: u64,
    pub next_nonce: u64,
    pub confirmed_nonce: u64,
    pub pending_count: u64,
    pub oldest_pending_age: Option<Duration>,
    /// Gaps detected between confirmed and pending (not yet in reuse pool)
    pub gaps: Vec<u64>,
    /// Gap nonces available for immediate reuse
    pub reusable_gaps: Vec<u64>,
}

/// A stale `RESERVED` reservation surfaced from the `status-chain-index` GSI —
/// a nonce that was handed out but crashed before it was signed. The recovery
/// sweep resolves each against the chain (finalize if the slot has been spent,
/// recycle if not).
#[derive(Debug, Clone)]
pub struct StaleReservation {
    pub wallet: Address,
    pub nonce: u64,
    pub chain_id: u64,
    pub reserved_at: Option<DateTime<Utc>>,
}
