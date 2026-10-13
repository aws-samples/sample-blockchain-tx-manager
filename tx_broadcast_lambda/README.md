# tx_broadcast_lambda

AWS Lambda function for Ethereum transaction broadcasting with atomic nonce management.

## Overview

This Lambda handles the "hot path" of transaction submission: receiving a request, reserving a nonce (atomically in DynamoDB via conditional `TransactWriteItems`, durable before the handler returns), simulating, signing, persisting the exact signed bytes and tx hash to DynamoDB, and broadcasting the raw transaction to the mempool. It returns immediately after broadcast acceptance—confirmation tracking is handled by the separate `tx_watcher` service.

Because the signed bytes are persisted before the send, an ambiguous broadcast failure is recovered by re-sending the identical stored raw transaction rather than re-signing under a new nonce. Scope is EVM chains and EIP-1559 transactions.

## Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Lambda Execution Flow                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Receive request (direct invoke or SQS)                      │
│                        │                                        │
│                        ▼                                        │
│  2. Resolve signer credentials                                  │
│     • Explicit: from request.signerCredentials                  │
│     • Environment: from SECRETS_NAME env var                    │
│                        │                                        │
│                        ▼                                        │
│  3. Reserve nonce (DynamoDB nonce authority)                    │
│     • Checks gap pool first                                     │
│     • Falls back to sequential increment                        │
│                        │                                        │
│                        ▼                                        │
│  4. Simulate transaction (eth_call)                             │
│     • If fails: release nonce, return error                     │
│                        │                                        │
│                        ▼                                        │
│  5. Estimate gas (if not provided)                              │
│     • Adds configurable buffer (default 20%)                    │
│                        │                                        │
│                        ▼                                        │
│  6. Sign transaction                                            │
│     • Nitro, SecretsManager, KMS, or Coinbase backend           │
│     • All backends: hash → sign_hash → encode → raw broadcast   │
│                        │                                        │
│                        ▼                                        │
│  7. Broadcast to mempool                                        │
│     • If fails: classify error, maybe mark nonce failed         │
│                        │                                        │
│                        ▼                                        │
│  8. Record pending TX to DynamoDB                               │
│     • For tx_watcher to track                                   │
│                        │                                        │
│                        ▼                                        │
│  9. Return { success, txHash, nonce }                           │
│     • Lambda exits immediately                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## API

### Request

```json
{
  "from": "0x...",
  "to": "0x...",
  "value": "1000000000000000000",
  "data": "0x...",
  "chainId": 1,
  "gasLimit": 21000,
  "maxFeePerGas": "50000000000",
  "maxPriorityFeePerGas": "2000000000",
  "idempotencyKey": "client-supplied-unique-id",
  "signerCredentials": {
    "backend": "coinbase",
    "walletSecretArn": "arn:aws:secretsmanager:..."
  }
}
```

`from` and `to` are always required. Gas parameters are estimated if not provided.

Request-boundary rules enforced before any DynamoDB/nonce work (a violation returns a
non-retryable `INVALID_REQUEST` response, never a Lambda panic):

- **`idempotencyKey` is required for direct broadcasts.** A direct `lambda:InvokeFunction`
  broadcast must supply a non-empty (trimmed) `idempotencyKey`; a missing or blank key is
  rejected with `INVALID_REQUEST`. For SQS delivery the key is optional — the queue
  `messageId` is used automatically when the key is missing or blank. (Sign-hash requests
  are exempt: they broadcast nothing.)
- **`chainId` cannot override the deployment chain.** The Lambda's configured `CHAIN_ID`
  is authoritative. `chainId` may be omitted or must equal `CHAIN_ID`; any other value is
  rejected with `INVALID_REQUEST`. The signed transaction and nonce state are always built
  with the deployment chain, and an absent `chainId` is treated identically to one equal to
  it (including for idempotency deduplication).
- **EIP-1559 fees are all-or-nothing.** If either `maxFeePerGas` or `maxPriorityFeePerGas`
  is supplied, both must be; `maxPriorityFeePerGas` must not exceed `maxFeePerGas`, and
  neither may exceed `u128::MAX`. When neither is supplied, both are estimated.

### Response

```json
{
  "success": true,
  "txHash": "0x...",
  "nonce": 42
}
```

### Error Response

```json
{
  "success": false,
  "error": "Simulation reverted: insufficient balance",
  "errorCode": "SIMULATION_FAILED",
  "retryable": false
}
```

## Signing Backends

All backends use a unified raw transaction flow: build unsigned tx → compute signing hash → `sign_hash()` via the `TransactionSigner` trait → encode signed tx → `send_raw_transaction()`. The `SignerProvider` routes to the correct backend based on configuration or per-request credentials.

| Backend | Feature Flag | Config | Description |
|---------|-------------|--------|-------------|
| `nitro` (default) | `nitro` | `NITRO_ENDPOINT`, `NITRO_SECRET_ID` | AWS Nitro Enclave isolated signing |
| `secrets_manager` | (always) | `SECRETS_NAME` | Private keys in Secrets Manager (JSON: `{"0xAddr": "key"}`) |
| `coinbase` | `coinbase` | `walletSecretArn` in request | Coinbase Developer Platform API |
| `kms` | `kms` | `kmsKeyId` in request | AWS KMS secp256k1 signing (stub) |

### Per-Request Credentials

For multi-tenant scenarios, pass credentials in the request:

```json
{
  "signerCredentials": {
    "backend": "coinbase",
    "walletSecretArn": "arn:aws:secretsmanager:us-east-1:123:secret:user-wallet"
  }
}
```

### Environment Credentials

For single-tenant deployments, configure via environment variables and omit `signerCredentials`.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RPC_URL` | Ethereum HTTP RPC | `http://localhost:8545` |
| `CHAIN_ID` | Ethereum chain ID | **required** (no default; never assumes mainnet) |
| `SIGNER_BACKEND` | Default signing backend (`nitro`, `secrets_manager`, `coinbase`) | `nitro` |
| `SECRETS_NAME` | Secrets Manager secret name (for `secrets_manager` backend) | `eth-private-keys` |
| `NITRO_ENDPOINT` | Nitro Enclave NLB URL (for `nitro` backend) | - |
| `NITRO_AUTH_ROLE_ARN` | ARN of the Nitro stack's zero-permission signing-client role to assume for SigV4 identity proofs. When unset, the Lambda's own execution-role credentials are used. | - |
| `NITRO_SECRET_ID` | Secret ID the signing service was deployed with; a log label only (see below) | - |
| `NITRO_CA_CERT_PATH` | PEM CA cert path for Nitro TLS validation | - |
| `NITRO_SKIP_TLS_VERIFY` | Skip Nitro TLS verification (dev/test only) | `false` |
| `DYNAMODB_TABLE` | Transaction tracking table | **required** |
| `TTL_DAYS` | DynamoDB record TTL | `7` |
| `DEFAULT_GAS_LIMIT` | Fallback gas limit | `21000` |
| `GAS_BUFFER_PERCENTAGE` | Buffer added to gas estimates | `20` |

`NITRO_SECRET_ID` does not select a wallet. It is never sent to the signing service, which
signs with the single wallet in its own deploy-time configuration; the value here only
labels logs and `SignerInfo`. Run one signing deployment per wallet. Requests to the service
are authenticated against an IAM allowlist — see
[Authentication](../docs/nitro-enclave-deployment.md#authentication).

When `NITRO_AUTH_ROLE_ARN` is set, the Lambda assumes that role
(`aws_config::sts::AssumeRoleProvider`, session name `tx-manager-nitro-auth`) and signs its
identity proofs as the assumed role, which is the ARN the allowlist pins. This is what lets
per-chain Lambdas authenticate without being individually allowlisted. When it is unset, the
Lambda uses its own execution-role credentials — the mode the Nitro stack's invoke Lambda
and the tests rely on. The selected identity mode is logged; role credentials never are.

## Error Codes

| Code | Description | Retryable |
|------|-------------|-----------|
| `INVALID_REQUEST` | Request rejected at the boundary (chain mismatch, missing/blank idempotency key, malformed fees) | No |
| `SIMULATION_FAILED` | eth_call reverted | No |
| `GAS_ESTIMATION_FAILED` | eth_estimateGas failed for a contract call | Yes |
| `NODE_REJECTED` | The node definitively refused the signed transaction at `eth_sendRawTransaction` (insufficient funds for gas, fee below base fee, intrinsic gas too low, exceeds block gas limit, encoding/signature/chain errors). The reservation is retired and the nonce recycled; nothing was broadcast. | No |
| `NONCE_EXHAUSTED` | Max pending transactions reached | Yes (after confirmations) |
| `HASH_MISMATCH` | Node acked a hash that disagrees with the signed bytes; SIGNED row retained for recovery | No |
| `DUPLICATE_IN_PROGRESS` | Same idempotency key is still in flight | Yes |
| `IDEMPOTENCY_CONFLICT` | Idempotency key reused with a different request body | No |
| `SIGNER_ERROR` | Could not sign transaction | No |

## Send-Error Classification

After the exact signed bytes are durably recorded (`SIGNED`), the outcome of
`eth_sendRawTransaction` is classified by the shared `nonce_manager::classify_send_error`
table so the Lambda and the watcher never disagree about what a node message means:

- **AlreadyKnown** (`already known`, `known transaction`) — the node holds the bytes;
  treated as an ack and marked broadcast.
- **NonceTooLow** — the nonce is consumed on-chain, by our bytes or someone else's. Left
  `SIGNED`; the watcher checks for a receipt of the exact stored hash before advancing.
- **Definitive** (funds, fees, gas, encoding) — never entered a mempool. Only on the
  *first* send: the reservation is retired, the nonce recycled, and `NODE_REJECTED` is
  returned. The watcher never recycles on this outcome for a rebroadcast.
- **Ambiguous** (timeouts, transport errors, `txpool is full`, `nonce too high`,
  `replacement transaction underpriced`, anything unrecognised) — accepted; the row stays
  `SIGNED` and the watcher rebroadcasts the identical bytes.
- **Transient**: `timeout`, `connection`, `rate limit`, `503` → can retry same nonce

## Building

```bash
# Build for Lambda (ARM64)
cargo build --release --target aarch64-unknown-linux-gnu

# Or use Docker
docker build -t tx-broadcast-lambda .
```

## Modules

| Module | Description |
|--------|-------------|
| `handler` | Unified request handler: nonce → simulate → sign → broadcast |
| `config` | Environment configuration |
| `signing/` | Modular signer backends (`TransactionSigner` trait) |
| `tx` | EIP-1559 transaction building, signing hash computation, encoding |
| `store` | DynamoDB: persists the exact signed bytes + hash before the send, then marks the transaction broadcast |
| `types` | Request/response types |
| `error` | Error types and codes |
