# tx_watcher

> [!NOTE]
> This is sample code from a source-only reference architecture, provided as-is under MIT-0 without warranty or support. It is not a production-ready deployment. See [Known Limitations and Customer Responsibilities](../docs/known-limitations.md).

Long-running ECS/Fargate service for transaction finality tracking with chain reorganization detection.

## Overview

After `tx_broadcast_lambda` durably records and broadcasts a transaction, this service takes over to track it through to finality. It subscribes to new blocks via WebSocket, checks for transaction receipts, updates confirmation counts, handles chain reorganizations, rebroadcasts or re-injects the exact stored signed bytes when a transaction has not been acknowledged or has gone stale, detects nonces consumed by other transactions, and enqueues policy-authorized same-nonce fee replacements. It cannot sign: replacement signing happens in the separately permissioned replacement Lambda.

## Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Watcher Event Loop                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Subscribe to new blocks via WebSocket                           │
│     • On reconnect or a header gap, backfill up to 256 missed       │
│       blocks; reconnect if no header within BLOCK_STALL_TIMEOUT_SECS│
│              │                                                      │
│              ▼                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ For each block:                                                │ │
│  │                                                                │ │
│  │  2. Track block hash; detect reorgs (parent hash mismatch)     │ │
│  │  6. If reorg: atomically reset affected MINED/CONFIRMED txs    │ │
│  │     back to SIGNED (bytes stored) or PENDING, one UpdateItem   │ │
│  │     per tx, then refresh the cache                             │ │
│  │                                                                │ │
│  │  9. Rebroadcast SIGNED rows with identical bytes, once the row │ │
│  │     is at least 90 s past submitted_at                         │ │
│  │     (SIGNED_REBROADCAST_GRACE_SECS); ack → PENDING             │ │
│  │                                                                │ │
│  │ 10. Enqueue due replacements: for an active family whose       │ │
│  │     bump cadence has elapsed, take a leased DynamoDB claim and │ │
│  │     send an identity-only message to REPLACEMENT_QUEUE_URL     │ │
│  │                                                                │ │
│  │  4. Fetch receipts for PENDING (and inactive SIGNED) txs       │ │
│  │     • 10 concurrent lookups                                    │ │
│  │  5. Receipt found: finalize nonce, then MINED (success) or     │ │
│  │     FAILED (reverted)                                          │ │
│  │  7. No receipt, older than STUCK_THRESHOLD_SECS, chain nonce   │ │
│  │     already past this nonce: finalize nonce, mark DROPPED      │ │
│  │  8. No receipt, older than STUCK_THRESHOLD_SECS, nonce still   │ │
│  │     unconsumed: re-inject the exact stored bytes (same hash),  │ │
│  │     at most once per threshold interval                        │ │
│  │                                                                │ │
│  │  5. Update MINED confirmations from the receipt's block        │ │
│  │     • confirmations >= REQUIRED_CONFIRMATIONS: finalize nonce, │ │
│  │       mark CONFIRMED                                           │ │
│  │                                                                │ │
│  │     Finalize: at required_confirmations + 20 blocks, close the │ │
│  │     replacement family, mark losing siblings REPLACED, drop    │ │
│  │     the tx from reorg tracking and the cache                   │ │
│  │                                                                │ │
│  │     Persist watcher cursor; write heartbeat; emit EMF metrics  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  Every 60 s: 3. refresh the cache from DynamoDB (SIGNED, PENDING,   │
│  MINED rows for CHAIN_ID) and resolve stale RESERVED reservations   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

Step numbers refer to the watcher flow in the [root README](../README.md#tx_watcher); the
box shows the order in which `src/watcher.rs::process_block` runs them.

The SIGNED rebroadcast grace period exists because a `SIGNED` row also exists while the
broadcast Lambda is still inside its own first send. The Lambda's timeout is 30 s; waiting
three times that leaves the first send exclusively to the Lambda, so any row the watcher
picks up belongs to an invocation that has finished or died.

## Reorg Detection

The watcher tracks recent block hashes (up to 256) to detect chain reorganizations:

```
Normal chain:     100 ─▶ 101 ─▶ 102 ─▶ 103
                              ↑
Reorg detected:   100 ─▶ 101 ─▶ 102' ─▶ 103'
                              │
                              └─ parent_hash mismatch!

When reorg detected:
1. Resolve fork point via hash_to_number lookup on new block's parent_hash (O(1))
2. All tracked blocks between (fork_point + 1) and new block height are orphaned
3. Find transactions mined or confirmed in orphaned blocks
4. Atomically reset each in a single DynamoDB UpdateItem
   - To SIGNED when the row carries its exact signed bytes (so they are rebroadcast
     verbatim), otherwise to PENDING
   - Clears block_number, block_hash; zeroes confirmations
   - ConditionExpression ensures only MINED/CONFIRMED txs are affected
5. If parent_hash is not tracked at all, conservatively orphan all tracked blocks
```

There is no intermediate REORGED status. On restart the watcher resumes from a persisted
cursor row (`watcher#<chain_id>` / `cursor`) and backfills reorg tracking from there,
bounded to the most recent 256 blocks.

### Finality Threshold

Transactions are tracked for reorg until `required_confirmations + 20` blocks. After that,
they're considered final: the replacement family is closed, any still-active losing
same-nonce candidates are marked `REPLACED`, and the transaction is removed from tracking.

## Transaction States

```
SIGNED ──┬──▶ PENDING ──┬──▶ MINED ──┬──▶ CONFIRMED
         │              │            │          ▲
         │              │            └──▶ SIGNED or PENDING (reorg: atomic reset) ──┘
         │              │
         │              ├──▶ FAILED  (mined but reverted on-chain)
         │              │
         │              ├──▶ DROPPED (nonce consumed on-chain by a different tx)
         │              │
         │              └──▶ REPLACED (losing same-nonce candidate, at finality)
         │
         ├──▶ DROPPED   (nonce consumed by a different tx before any send was acked)
         │
         └──▶ REJECTED  (written by the Lambda: node definitively refused the first send;
                         nonce recycled. The watcher never writes REJECTED)
```

- `SIGNED`: exact signed bytes and locally computed hash are durable; the send has not
  been acknowledged. The watcher rebroadcasts the identical bytes (after the 90 s grace)
  until the node acks (`PENDING`), the nonce is consumed by these bytes (`PENDING` →
  `MINED`), or the nonce is consumed by something else (`DROPPED`).
- `PENDING`: the node acknowledged the bytes. If a `PENDING` row has no receipt for
  longer than `STUCK_THRESHOLD_SECS` and its nonce is still unconsumed, the watcher
  re-injects the identical bytes (same hash) once per threshold interval. A mempool
  eviction therefore leads to re-injection, not to `DROPPED`.
- `DROPPED`: the wallet's on-chain nonce has passed this transaction's nonce and the stored
  hash has no receipt, so a different transaction spent the nonce. The nonce is finalized as
  consumed, never recycled. The watcher re-checks the receipt once more before writing this.
- `FAILED`, `CONFIRMED`, `DROPPED` are only written after the nonce is finalized in
  DynamoDB; on any failure the row stays active and is retried on a later block.

## DynamoDB Operations

The watcher reads and writes the tracking table named by `DYNAMODB_TABLE` (there is no
default; the CDK stack names it `{resourcePrefix}-tracker`):

| Operation | Method | Description |
|-----------|--------|-------------|
| Get active txs | GSI query (`status-chain-index`) | `status` in (SIGNED, PENDING, MINED) for `CHAIN_ID`, paginated |
| Update mined | UpdateItem | Set block_number, block_hash, success, confirmations |
| Mark confirmed | UpdateItem | Set status = CONFIRMED, confirmations, TTL |
| Mark failed / dropped | UpdateItem | Set terminal status and TTL; dropped may apply to PENDING or SIGNED rows |
| Reorg reset | UpdateItem | Atomic: set status = SIGNED or PENDING, remove block_number/block_hash, zero confirmations, remove TTL. Condition: status IN (MINED, CONFIRMED) |
| Mark siblings replaced | Query + UpdateItem | At finality, set still-active same-nonce losing candidates to REPLACED |
| Cursor | PutItem / GetItem | `watcher#<chain_id>` / `cursor` row holding `last_block` |
| Nonce finalization, rebroadcast marking, stale reservation recovery, replacement claims | via `nonce_manager::DynamoNonceManager` | Shared with the Lambda so both sides use the same conditional writes |

## Environment Variables

Defaults are the values compiled into `src/config.rs`.

| Variable | Description | Default |
|----------|-------------|---------|
| `RPC_SECRET_ARN` | Secrets Manager secret `{"rpcUrl": ..., "wsRpcUrl": ...}`; when set, overrides both URL variables below. The secret must include `wsRpcUrl` for the watcher | - |
| `WS_RPC_URL` | Ethereum WebSocket RPC for block subscriptions (non-prod only) | `ws://localhost:8546` |
| `HTTP_RPC_URL` | Ethereum HTTP RPC used by the nonce manager for chain reconciliation and stale-reservation recovery (non-prod only) | `http://localhost:8545` |
| `DYNAMODB_TABLE` | Transaction tracking table | **required** (no default) |
| `CHAIN_ID` | Ethereum chain ID; must be a non-zero integer | **required** (no default; never assumes mainnet) |
| `REQUIRED_CONFIRMATIONS` | Blocks for finality | `12` |
| `STUCK_THRESHOLD_SECS` | Age after which a PENDING/SIGNED tx without a receipt is eligible for drop detection or re-injection; also the re-injection interval | `300` |
| `BLOCK_STALL_TIMEOUT_SECS` | Reconnect if no block header arrives within this window (silent WebSocket stall) | `120` |
| `RECONNECT_DELAY_SECS` | Delay before reconnecting after the subscription loop ends | `5` |
| `HEARTBEAT_PATH` | File rewritten with the epoch second after every processed block; read by the ECS health check | `/tmp/tx_watcher_heartbeat` |
| `REPLACEMENT_QUEUE_URL` | Internal send-only SQS queue for replacement requests. When unset, replacement enqueueing is disabled but receipt tracking continues | - |
| `TTL_DAYS` | TTL applied to terminal rows | `7` |

`FALLBACK_POLL_INTERVAL_SECS` (default `12`) is read into the config but not used.

## Metrics

The watcher emits one CloudWatch Embedded Metric Format document per processed block to
stdout (namespace `TxManager/Watcher`, dimension `ChainId`): `BlocksProcessed`,
`BlockLagSeconds` (now minus block timestamp), and `ActiveTransactions`. No CloudWatch SDK
or IAM permission is needed; the `awslogs` driver delivers them.

## Modules

| Module | Description |
|--------|-------------|
| `main` | Startup, AWS clients, SIGTERM/SIGINT handling |
| `watcher` | `TransactionWatcher`: subscription loop, block processing, rebroadcast, drop detection, replacement enqueueing |
| `reorg` | `ReorgDetector` for chain reorganization handling |
| `store` | `TxStore` for DynamoDB tracker operations and the watcher cursor |
| `metrics` | EMF progress document per block |
| `config` | Environment configuration |
| `error` | Error types |

## Caching

The watcher maintains an in-memory cache of active transactions (SIGNED, PENDING, MINED) to
avoid repeated DynamoDB queries:

- Cache is refreshed every 60 seconds
- Cache is refreshed after handling a reorg
- Per-transaction re-injection timestamps survive a refresh, so the rate limit is not reset
- Transactions are removed from cache after reaching finality

## Building

```bash
# Native build
cargo build --release

# Container image: run from the repository root, because the Dockerfile also copies
# ../nonce_manager.
finch build --platform linux/arm64 -f tx_watcher/Dockerfile -t tx-watcher .
```

`docker build` accepts the same arguments.

## Running Locally

```bash
# Set environment. DYNAMODB_TABLE has no default; use the name of your deployed tracker
# table (the CDK TxTrackerTableName output), for example sepolia-dev-tracker.
export WS_RPC_URL=wss://your-node/ws
export HTTP_RPC_URL=https://your-node
export DYNAMODB_TABLE=sepolia-dev-tracker
export CHAIN_ID=11155111
export REQUIRED_CONFIRMATIONS=12

# Run
cargo run --release
```

## Graceful Shutdown

The watcher handles `SIGTERM` (sent by ECS on stop) and `SIGINT` and exits the block loop
when either arrives.
