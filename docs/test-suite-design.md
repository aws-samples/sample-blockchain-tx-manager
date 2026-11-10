# Comprehensive Test Suite Design

> [!NOTE]
> This is sample code from a source-only reference architecture, provided as-is under MIT-0 without warranty or support. It is not a production-ready deployment. See [Known Limitations and Customer Responsibilities](known-limitations.md).

This document outlines the test strategy for each major component in the transaction management system.

## Overview

The system has five major testable components:
1. **Nonce Manager** - DynamoDB-backed atomic nonce coordination (sole authority)
2. **Transaction Signing** - Nitro enclave and other signing backends
3. **Transaction Encoding** - EIP-1559 transaction building and encoding
4. **Reorg Detection** - Chain reorganization tracking
5. **Transaction Watcher** - Block subscription and confirmation tracking

## Current Test Coverage

### 1. Nonce Manager (`nonce_manager/src/manager.rs`, `nonce_manager/src/lambda.rs`)

17 pure tests: no server, no AWS calls, never skipped. They exercise the key layout,
model encoding, and the reserve/retry decision logic that hold every nonce-correctness
invariant of the DynamoDB single-store design.

**Key layout and model (`manager.rs`, 11 tests):**

- `sort_keys_are_zero_padded_to_20_digits_and_sort_numerically` - sort keys order numerically
- `nonce_round_trips_through_sort_keys` - nonce ↔ sort key round-trip
- `wallet_pk_is_lowercased_hex_address` - partition key normalization
- `drain_watermark_advances_over_contiguous_markers_only` - confirm watermark only advances over drained markers
- `drain_watermark_caps_at_max_markers` - transaction item cap respected
- `drain_watermark_is_overflow_safe_at_u64_max` - no overflow at `u64::MAX`
- `contiguous_markers_caps_and_is_overflow_safe` - contiguous marker scan is bounded and overflow-safe
- `reservation_state_round_trips` - `RESERVED`/`SIGNED`/`BROADCAST` parse ↔ render
- `cond_failed_reads_reason_codes_by_index` - conditional-check reason codes read positionally
- `hex_encode_is_lowercase_and_exact` - signed-bytes hex encoding
- `validate_signed_raw_tx_rejects_empty_and_oversized` - signed raw tx size bounds

**Reserve/retry decision logic (`lambda.rs`, 6 tests):**

- `accepted_is_terminal_and_not_retryable` - success is terminal
- `transient_broadcast_retries_same_nonce_never_fresh` - ambiguous send reuses the same nonce (identical rebroadcast), never a fresh one
- `node_rejected_is_left_pending_neither_retry_path` - occupied/consumed slot left for the watcher
- `on_chain_revert_is_unspent_and_takes_a_fresh_nonce` - pre-mempool rejection reclaims a fresh nonce
- `simulation_failure_retries_with_fresh_nonce` - released simulation nonce is reclaimed
- `reservation_failure_is_terminal` - max-pending reservation failure is terminal

### 2. Transaction Signing (`tx_broadcast_lambda/src/signing/nitro.rs`)

10 tests using wiremock for HTTP mocking:

- `test_sign_hash_success` - Successful signature with address recovery
- `test_sign_hash_v27_parity` - v=27 → parity=false conversion
- `test_sign_hash_v28_parity` - v=28 → parity=true conversion
- `test_sign_hash_error_response` - Backend error handling
- `test_sign_hash_http_error` - HTTP 500 error handling
- `test_sign_hash_invalid_json` - Malformed response handling
- `test_sign_hash_missing_signature` - Missing signature field
- `test_health_check_success` - Health endpoint check
- `test_signer_info` - Signer metadata
- `test_sign_hash_strips_0x_prefix` - Hex prefix handling

Note: The handler uses a unified raw-tx flow for all signing backends. All backends implement `TransactionSigner::sign_hash()`, so adding a new backend only requires trait implementation tests; no handler changes needed.

### 3. Transaction Encoding (`tx_broadcast_lambda/src/tx.rs`)

12 tests:

- `test_build_unsigned_tx` - Basic transaction building
- `test_build_unsigned_tx_all_fields` - All field verification
- `test_signing_hash_deterministic` - Hash consistency
- `test_signing_hash_changes_with_nonce` - Nonce affects hash
- `test_signing_hash_changes_with_chain_id` - Chain ID affects hash
- `test_signing_hash_changes_with_value` - Value affects hash
- `test_nitro_signature_recovery` - Known signature recovery
- `test_nitro_signature_v27_parity` - v=27 parity conversion
- `test_nitro_signature_v28_parity` - v=28 parity conversion
- `test_encode_signed_tx_eip2718_format` - EIP-2718 type byte
- `test_encode_signed_tx_recoverable` - Signer recovery from encoded tx
- `test_tx_hash_computation` - Transaction hash validity

### 4. Reorg Detection (`tx_watcher/src/reorg.rs`)

16 tests:

- `test_no_reorg` - Sequential blocks (no reorg)
- `test_single_block_reorg` - Single block orphaned
- `test_multi_block_reorg` - Multiple blocks orphaned
- `test_tx_tracking_through_reorg` - Transaction invalidation on reorg
- `test_deep_reorg_handling` - Deep reorg detection
- `test_multiple_txs_same_block_reorg` - Multiple txs in orphaned block
- `test_finality_threshold` - Finalized transaction detection
- `test_block_pruning` - Old block cleanup
- `test_tx_removal_after_finality` - Transaction removal
- `test_get_block_by_hash` - Block lookup by hash
- `test_latest_block_tracking` - Latest block tracking
- `test_reorg_preserves_unaffected_blocks` - Unaffected block preservation
- `test_empty_detector` - Empty state handling
- `test_first_block_no_reorg` - First block handling
- `test_three_block_reorg` - 3-block reorg with txs on each orphaned block
- `test_reorg_parent_not_in_chain` - Fallback when parent hash is unknown (orphans all tracked blocks)

## Running Tests

```bash
# Unit tests (no external services required). The crates are not a Cargo workspace,
# so run each from its own directory.
(cd tx_watcher && cargo test)
(cd tx_broadcast_lambda && cargo test)
(cd nonce_manager && cargo test)  # Pure tests, no DynamoDB needed

# Run specific test
(cd tx_watcher && cargo test test_single_block_reorg)

# Everything CI runs (fmt, clippy, unit, DynamoDB Local integration, Python)
./scripts/run-tests.sh all
```

The DynamoDB Local integration tests (`nonce_manager/tests/dynamodb_local.rs`, feature
`dynamodb-local-tests`) need Java 17 and DynamoDB Local; see `scripts/run-tests.sh`.

## Test Dependencies

- `wiremock` - HTTP mocking for Nitro signer tests
- `tokio-test` - Async test utilities
