# tx_watcher

Long-running ECS/Fargate service for transaction finality tracking with chain reorganization detection.

## Overview

After `tx_broadcast_lambda` submits a transaction to the mempool, this service takes over to track it through to finality. It subscribes to new blocks via WebSocket, checks for transaction receipts, updates confirmation counts, and handles chain reorganizations.

## Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Watcher Event Loop                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  WebSocket Block Subscription                                   │
│              │                                                  │
│              ▼                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ For each new block:                                      │   │
│  │                                                          │   │
│  │  1. Check for reorgs (compare parent hash)               │   │
│  │     • If reorg: atomically reset affected txs to PENDING │   │
│  │       (single DynamoDB UpdateItem per tx)                │   │
│  │                                                          │   │
│  │  2. Check PENDING transactions                           │   │
│  │     • Fetch receipts in parallel (10 concurrent)         │   │
│  │     • If mined: update to MINED with block info          │   │
│  │     • Record in reorg detector                           │   │
│  │                                                          │   │
│  │  3. Update MINED transaction confirmations               │   │
│  │     • If confirmations >= required: mark CONFIRMED       │   │
│  │     • Remove from reorg tracking                         │   │
│  │                                                          │   │
│  │  4. Finalize old transactions                            │   │
│  │     • Remove from cache after finality threshold         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Periodic: Refresh cache from DynamoDB (every 60s)              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Reorg Detection

The watcher tracks recent block hashes to detect chain reorganizations:

```
Normal chain:     100 ─▶ 101 ─▶ 102 ─▶ 103
                              ↑
Reorg detected:   100 ─▶ 101 ─▶ 102' ─▶ 103'
                              │
                              └─ parent_hash mismatch!

When reorg detected:
1. Resolve fork point via hash_to_number lookup on new block's parent_hash (O(1))
2. All tracked blocks between (fork_point + 1) and new block height are orphaned
3. Find transactions confirmed in orphaned blocks
4. Atomically reset each to PENDING (single DynamoDB UpdateItem per tx)
   - Clears block_number, block_hash; zeroes confirmations
   - ConditionExpression ensures only MINED/CONFIRMED txs are affected
5. If parent_hash is not tracked at all, conservatively orphan all tracked blocks
```

### Finality Threshold

Transactions are tracked for reorg until `required_confirmations + 20` blocks. After that, they're considered final and removed from tracking.

## Transaction States

```
PENDING ──┬──▶ MINED ──┬──▶ CONFIRMED
          │            │
          │            └──▶ PENDING (reorg: atomic reset, no intermediate state)
          │
          ├──▶ FAILED (reverted on-chain)
          │
          ├──▶ DROPPED (removed from mempool)
          │
          └──▶ REPLACED (higher gas replacement)
```

Note: On reorg, transactions transition directly from MINED/CONFIRMED back to PENDING in a single atomic DynamoDB write. There is no intermediate REORGED status written to the database.

## DynamoDB Operations

The watcher queries and updates the `tx_tracker` table:

| Operation | Method | Description |
|-----------|--------|-------------|
| Get active txs | GSI query | `status = PENDING` or `status = MINED` |
| Update mined | UpdateItem | Set block_number, block_hash, success, confirmations |
| Mark confirmed | UpdateItem | Set status = CONFIRMED |
| Reorg to pending | UpdateItem | Atomic: set status = PENDING, remove block_number/block_hash, zero confirmations. Condition: status IN (MINED, CONFIRMED) |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WS_RPC_URL` | Ethereum WebSocket RPC | `ws://localhost:8546` |
| `DYNAMODB_TABLE` | Transaction tracking table | **required** |
| `CHAIN_ID` | Ethereum chain ID | **required** |
| `REQUIRED_CONFIRMATIONS` | Blocks for finality | `12` |
| `STUCK_THRESHOLD_SECS` | Pending TX timeout | `300` |
| `TTL_DAYS` | DynamoDB record TTL | `7` |
| `RECONNECT_DELAY_SECS` | WebSocket reconnect delay | `5` |

## Modules

| Module | Description |
|--------|-------------|
| `watcher` | Main `TransactionWatcher` with block processing loop |
| `reorg` | `ReorgDetector` for chain reorganization handling |
| `store` | `TxStore` for DynamoDB operations |
| `config` | Environment configuration |
| `error` | Error types |

## Caching

The watcher maintains an in-memory cache of active transactions to avoid repeated DynamoDB queries:

- Cache is refreshed every 60 seconds
- Cache is refreshed after handling a reorg
- Transactions are removed from cache after reaching finality

## Building

```bash
# Build for container (ARM64)
cargo build --release --target aarch64-unknown-linux-gnu

# Or use Docker
docker build -t tx-watcher .
```

## Running Locally

```bash
# Set environment
export WS_RPC_URL=wss://your-node/ws
export DYNAMODB_TABLE=tx_tracker
export CHAIN_ID=1
export REQUIRED_CONFIRMATIONS=12

# Run
cargo run --release
```

## Graceful Shutdown

The watcher handles `SIGTERM`/`SIGINT` for graceful shutdown, allowing in-flight operations to complete before exiting.
