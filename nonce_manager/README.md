# nonce_manager

Core library for atomic Ethereum nonce management with **DynamoDB as the sole nonce
authority**.

## Overview

Managing nonces in high-concurrency environments is notoriously difficult. This library
solves the problem with DynamoDB conditional `TransactWriteItems`, so no two transactions
ever get the same nonce, while handling gap recovery when transactions fail.

Nonce state and the durable tracker rows the watcher reads live in **one** per-chain
table. Every multi-key state change is a single `TransactWriteItems` (ACID), so there is
no second store and no window between two unsynchronized writes. A reservation is durable
before the caller returns — a reserved nonce survives a crash and is recoverable via the
`status-chain-index` GSI.

## Multi-Chain Support

The nonce manager supports multiple EVM chains simultaneously. Each `DynamoNonceManager`
instance is bound to a specific `chain_id` and a per-chain tracker table, ensuring
complete nonce isolation between networks. The same wallet address on Ethereum mainnet
(chain_id=1) and Polygon (chain_id=137) has independent nonce tracking because each chain
has its own table.

```rust
use std::sync::Arc;
// Each chain has its own tracker table; a DynamoDB client is shared.
let eth_manager = DynamoNonceManager::with_defaults(ddb.clone(), "eth-tracker", Arc::new(eth_provider), 1);        // Ethereum
let polygon_manager = DynamoNonceManager::with_defaults(ddb.clone(), "polygon-tracker", Arc::new(poly_provider), 137); // Polygon
let arb_manager = DynamoNonceManager::with_defaults(ddb.clone(), "arb-tracker", Arc::new(arb_provider), 42161);   // Arbitrum
```

## Key Features

- **Per-chain isolation** - each manager owns one chain's tracker table
- **Atomic nonce reservation** via conditional `TransactWriteItems` (no race conditions)
- **Durable before return** - the reservation is committed before the caller returns
- **Gap detection and reuse** - failed transaction nonces are recycled
- **Concurrent transaction limits** - prevents runaway nonce allocation
- **Crash recovery** - `RESERVED` rows are discoverable via the `status-chain-index` GSI
- **Lambda-optimized executor** - single-shot pattern for serverless
- **Blockchain sync** - reconciles DynamoDB state with on-chain nonces

## Architecture

DynamoDB is the sole nonce authority. All rows for a wallet share the `wallet` partition
key; sort keys are namespaced. Internal rows omit `status`/`chain_id` so they stay out of
the `status-chain-index` GSI the watcher queries — with one deliberate exception: a
`RESERVED` reservation carries `status`/`chain_id` on purpose so a crash between reserve
and sign is globally discoverable. `record_signed` removes that recovery marker as it
creates the durable tracker row, so the reservation leaves the GSI the instant signed
bytes exist.

```
┌───────────────────────────────────────────────────────────────────────┐
│                        DynamoNonceManager                              │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  reserve_nonce()        ──▶  TransactWriteItems (conditional)         │
│  release_nonce()        ──▶  TransactWriteItems (still RESERVED)      │
│  record_signed()        ──▶  TransactWriteItems (durable tracker row) │
│  mark_broadcast()       ──▶  UpdateItem                               │
│  confirm_transaction()  ──▶  TransactWriteItems (advance watermark)   │
│  mark_failed()          ──▶  TransactWriteItems (register gap)        │
│  find_stale_reservations() ─▶ Query status-chain-index (RESERVED)     │
│                                                                       │
│  Rows in the per-chain tracker table (PK wallet, SK namespaced):      │
│  • nonce-state                     - next/confirmed watermark    (no GSI) │
│  • reservation#<20-digit nonce>    - per-nonce reservation  (GSI only    │
│                                      while RESERVED)                  │
│  • gap#<20-digit nonce>            - reusable gap                 (no GSI) │
│  • confirmed#<20-digit nonce>      - out-of-order confirmed marker (no GSI)│
│  • <0x tx hash>                    - durable tracker row (watcher) (in GSI)│
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

## Usage

### Basic Nonce Reservation

```rust
use std::sync::Arc;
use nonce_manager::{DynamoNonceManager, NonceManagerConfig};

// Create manager for Ethereum mainnet (chain_id = 1)
let manager = DynamoNonceManager::new(ddb_client, "eth-tracker", Arc::new(provider), 1, NonceManagerConfig::default());

// Initialize wallet (fetches on-chain nonce if not tracked)
manager.initialize_wallet(address).await?;

// Reserve next nonce (prefers gap reuse). Durable before this returns.
let nonce = manager.reserve_nonce(address).await?;

// If simulation fails (still RESERVED, not yet signed), release the nonce
manager.release_nonce(address, nonce).await?;

// After signing, persist the exact signed bytes + tx hash (durable tracker row)…
manager.record_signed(address, nonce, tx_hash, &signed_raw_tx, Some(gas_price), None, None).await?;
// …then broadcast, then mark the tracker row broadcast
manager.mark_broadcast(address, nonce, tx_hash).await?;

// When confirmed on-chain
manager.confirm_transaction(address, nonce).await?;

// If a reserved-but-unsigned nonce is abandoned, mark it for gap reuse
manager.mark_failed(address, nonce).await?;
```

### Lambda Executor (Recommended for Serverless)

```rust
use nonce_manager::{LambdaExecutor, LambdaSubmitResult, FailureType};

let executor = LambdaExecutor::new(manager);

let result = executor.submit(
    address,
    |nonce| async move {
        // Simulate transaction
        provider.call(&tx.with_nonce(nonce)).await
            .map_err(|e| e.to_string())?;
        Ok(())
    },
    |nonce| async move {
        // Sign, then broadcast the raw transaction
        let pending = provider.send_transaction(tx.with_nonce(nonce)).await?;
        Ok((*pending.tx_hash(), signed_raw_tx, gas_price))
    },
    |error| {
        // Classify error for retry logic
        if error.contains("nonce too low") {
            FailureType::NodeRejected
        } else {
            FailureType::Transient
        }
    },
).await;

match result {
    LambdaSubmitResult::Accepted { nonce, tx_hash } => { /* success */ }
    LambdaSubmitResult::SimulationFailed { .. } => { /* nonce released */ }
    LambdaSubmitResult::BroadcastFailed { .. } => { /* ambiguous — see recovery */ }
    LambdaSubmitResult::ReservationFailed { .. } => { /* max pending exceeded */ }
}
```

## Modules

| Module | Description |
|--------|-------------|
| `manager` | Core `DynamoNonceManager` with all nonce operations |
| `lambda` | `LambdaExecutor` for single-shot serverless execution |
| `flow` | `TransactionFlow` helper for the simulate→sign→broadcast pattern |
| `retry` | `ConcurrentExecutor` with automatic retry logic |
| `batch` | `BatchExecutor` for parallel transaction submission |
| `types` | `PendingTransaction`, `WalletState`, `TxStatus`, `ReservationState`, `StaleReservation`, `NonceManagerConfig` |

## Configuration

```rust
NonceManagerConfig {
    max_pending_per_wallet: 100,                        // Prevent runaway allocation
    stuck_threshold: Duration::from_secs(300),          // 5 min before tx is "stuck"
    gas_bump_percentage: 15,                            // For replacement transactions
    reservation_stale_threshold: Duration::from_secs(300), // RESERVED-but-unsigned recovery age
    pending_tx_ttl: Duration::from_secs(86400),         // Advisory TTL horizon (terminal only)
}
```

The nonce authority never writes a `ttl` on unresolved work (reservation/tracker rows);
the watcher applies TTL only once a transaction reaches a terminal state.

## Gap Recovery Flow

```
1. A reserved nonce is abandoned before it is signed (simulation revert, crash, etc.)
2. release_nonce()/mark_failed() moves the nonce to a gap# row (single transaction)
3. Next reserve_nonce() checks the lowest gap# row first
4. If a gap exists, it is consumed (deleted) and returned in the same transaction
5. Otherwise the sequential nonce-state watermark is advanced
6. In both cases the reservation and any pending accounting change atomically
```

No nonce is permanently lost, even under high concurrency: every branch is one ACID
`TransactWriteItems`, so a crash leaves the store in a consistent, recoverable state.

### Key Behaviors

- **`release_nonce()`** (pre-broadcast failure, still `RESERVED`) and **`mark_failed()`**
  both route the nonce to a `gap#` row. Neither ever rewinds the `nonce-state` watermark.
  Once a reservation is `SIGNED`/`BROADCAST` the durable tracker row exists and only the
  watcher may retire it.
- **`confirm_transaction()`** advances the confirmed watermark with strict ordering and
  drains contiguous out-of-order `confirmed#` markers, cleaning up superseded gaps in the
  same transaction.
- **`initialize_wallet()`** conditionally creates state on first use, then reconciles
  `next_nonce` and `confirmed_nonce` upward from the chain. It never lowers either
  watermark, so legitimate in-flight reservations are preserved.
- **`force_sync()`** is an explicit chain re-read with the same monotonic,
  non-destructive rule. Despite the compatibility name, it does not reset counters or
  delete reservation, gap, or confirmed-marker rows.
- **`record_signed()` → `mark_broadcast()`** persists the exact signed bytes and tx hash
  (durable tracker row) *before* the raw transaction is sent, then marks it broadcast.
  After an ambiguous broadcast failure the signed bytes are already durable, so recovery
  is an identical rebroadcast of the stored raw transaction — never a re-sign under a new
  nonce.
- **`find_stale_reservations()`** queries the `status-chain-index` GSI for `RESERVED`
  rows older than `reservation_stale_threshold` — nonces handed out but never signed —
  so a crashed reservation is globally discoverable and can be finalized or recycled.

## Future Gap-Pool Optimization Roadmap

The current implementation favors correctness and recoverability over minimizing every
DynamoDB read. It queries the wallet's lowest `gap#` row before sequential allocation,
then claims it with a conditional transaction. The following are **future optimizations,
not current behavior or release requirements**. Implement them only when production
measurements show the stated trigger.

| Priority | Optimization | Trigger | Expected benefit |
|---|---|---|---|
| **0 — measure first** | Emit gap-query latency/hit rate, gap depth, conditional-conflict retries, stale-gap deletions, and per-wallet reservation latency | Before changing the allocation algorithm | Establishes whether the gap path is material and provides a regression baseline |
| **1** | Add an atomic `gap_count` attribute to `nonce-state` | Empty gap queries are a meaningful share of reservation cost or latency | Skips the gap `Query` when `gap_count == 0`, which should be the normal case |
| **2** | Tune bounded gap-claim retries with jitter; optionally query a small candidate page under measured contention | Conditional gap-claim conflicts materially increase p95/p99 reservation latency | Reduces repeated contention on the same lowest gap without weakening single-claim semantics |
| **3** | Add a bounded reconciliation sweep that batch-removes `gap#` rows below the monotonic confirmed watermark | Stale-gap deletion metrics or gap depth show persistent accumulation | Reduces storage and avoids repeated discovery of provably consumed entries |
| **4** | Add an explicit same-nonce replacement/filler policy for signed transactions that must be abandoned | Operations require cancellation or fee replacement rather than identical rebroadcast | Restores wallet liveness without assigning the nonce to an unrelated business intent |
| **5 — last resort** | Add Redis/Valkey only as a derived lowest-gap hint | Benchmarks show DynamoDB gap lookup remains a material bottleneck after priorities 1–3 | Can reduce lookup latency while DynamoDB remains the sole authority |

### Priority 1 transaction shape

`gap_count` must be maintained in the same transactions as the gap rows; it is never an
eventually consistent estimate.

Gap creation:

```text
Delete reservation#N (condition state = RESERVED)
Decrement pending_count
Increment gap_count
Put gap#N (condition not exists)
```

Gap claim:

```text
Delete gap#N (condition exists and N >= confirmed_nonce)
Decrement gap_count
Increment pending_count
Put reservation#N (condition not exists)
```

Normal reservation first reads `nonce-state`. When `gap_count == 0`, it proceeds directly
to sequential allocation. When `gap_count > 0`, it queries and conditionally claims the
lowest `gap#` row. A transaction cancellation changes neither the row nor the counters.

### Non-negotiable safety constraints

Every optimization above must preserve these invariants and their DynamoDB Local
regression tests:

- DynamoDB remains the sole nonce and gap authority.
- A gap is claimed only by a conditional delete in the same transaction that creates the
  replacement reservation.
- No nonce below `confirmed_nonce` may be returned, even if a stale `gap#` row exists.
- Only an unsigned `RESERVED` nonce may be recycled. `SIGNED` and `BROADCAST` transactions
  retain their nonce and exact signed bytes.
- Unresolved reservations, signed transactions, and gap rows do not expire by TTL.
- Automatic reconciliation is monotonic; it never lowers a watermark to manufacture a
  reusable nonce.
- A cache miss, cache loss, retry, or process crash may reduce performance but must never
  change which nonce DynamoDB authoritatively assigns.

Do not shard one wallet's nonce-state item to increase write parallelism: Ethereum itself
requires that wallet's nonce sequence to be serialized. Scale horizontally across wallets
and per-chain tables instead.

If Redis/Valkey is ever introduced at priority 5, it may suggest a candidate nonce only.
The DynamoDB conditional transaction remains the decision point; Redis loss must be
recoverable by rebuilding hints from `gap#` rows, with no correctness impact.

### WalletState Fields

`get_wallet_state()` returns a `WalletState` with:
- `chain_id` — the chain this state applies to
- `next_nonce` / `confirmed_nonce` — the watermark
- `pending_count` — reservations/tracked transactions in flight
- `gaps` — nonces detected as missing (not yet in the reuse pool)
- `reusable_gaps` — nonces already in `gap#` rows, available for immediate reuse
