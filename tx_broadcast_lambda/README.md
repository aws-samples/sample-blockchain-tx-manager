# tx_broadcast_lambda

> [!NOTE]
> This is sample code from a source-only reference architecture, provided as-is under MIT-0 without warranty or support. It is not a production-ready deployment. See [Known Limitations and Customer Responsibilities](../docs/known-limitations.md).

AWS Lambda function for Ethereum transaction broadcasting with atomic nonce management.

## Overview

This Lambda handles the "hot path" of transaction submission: receiving a request, claiming its idempotency key, reserving a nonce (atomically in DynamoDB via conditional `TransactWriteItems`, durable before the handler returns), simulating, signing, persisting the exact signed bytes and tx hash to DynamoDB, and broadcasting the raw transaction to the mempool. It returns immediately after broadcast acceptance. Confirmation tracking is handled by the separate `tx_watcher` service.

Because the signed bytes are persisted before the send, an ambiguous broadcast failure is recovered by re-sending the identical stored raw transaction rather than re-signing under a new nonce. Scope is EVM chains and EIP-1559 transactions.

The same binary also serves two other roles: a stateless sign-hash path for direct invocations (see [Sign Hash](#sign-hash)), and, when deployed with `FUNCTION_MODE=replacement`, the separately permissioned replacement worker that the watcher drives through an internal SQS queue (see [Dynamic Fee Replacement Design](../docs/fee-bump-replacement-design.md)).

## Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Broadcast Execution Flow                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Receive unsigned transaction request (direct invoke or SQS) │
│     • Boundary validation; a violation returns INVALID_REQUEST  │
│                        │                                        │
│                        ▼                                        │
│  2. Claim the idempotency key in DynamoDB                       │
│     • Conditional PutItem before any nonce work                 │
│     • Duplicate short-circuits: original result, or             │
│       DUPLICATE_IN_PROGRESS while the first attempt is in flight│
│                        │                                        │
│                        ▼                                        │
│  3. Resolve signer via SignerProvider                           │
│     • Nitro, Secrets Manager, or Coinbase                       │
│     • Gas limit and fees are resolved here too (estimated if    │
│       not supplied, checked against HARD_MAX_* caps) so a gas   │
│       failure never strands a reservation                       │
│                        │                                        │
│                        ▼                                        │
│  4. Reserve nonce atomically in DynamoDB                        │
│     • Conditional TransactWriteItems; durable before return     │
│     • Gap pool first, then sequential increment                 │
│                        │                                        │
│                        ▼                                        │
│  5. Simulate transaction via eth_call                           │
│     • If it reverts: release nonce, return SIMULATION_FAILED    │
│                        │                                        │
│                        ▼                                        │
│  6. Build unsigned EIP-1559 tx, compute signing hash            │
│                        │                                        │
│                        ▼                                        │
│  7. Sign hash via the resolved TransactionSigner backend        │
│     • Signature verified (low-s, recovers to `from`)            │
│     • If signing fails: release nonce, return error             │
│                        │                                        │
│                        ▼                                        │
│  8. Persist exact signed bytes + tx hash (SIGNED), then         │
│     broadcast the identical bytes via eth_sendRawTransaction    │
│     • From here on the request never releases or re-signs       │
│     • Send outcome classified (see below)                       │
│                        │                                        │
│                        ▼                                        │
│  9. Mark broadcast (PENDING) and complete the idempotency claim │
│                        │                                        │
│                        ▼                                        │
│ 10. Return { success, txHash, nonce }                           │
│     • Does NOT wait for confirmation; tx_watcher takes over     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

Any failure before step 8 succeeds releases the reservation (guarded: only a still-`RESERVED`
reservation is recycled) and releases the idempotency claim, so a redelivery can retry
cleanly. After step 8 the claim is retained and the `SIGNED` row is durable; recovery is the
watcher's job.

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
  "feeSpeed": "standard",
  "idempotencyKey": "client-supplied-unique-id",
  "signerCredentials": {
    "backend": "coinbase",
    "walletSecretArn": "arn:aws:secretsmanager:..."
  }
}
```

`from` and `to` are always required and must not be the zero address. Gas parameters are
estimated if not provided; `feeSpeed` (`slow`, `standard`, `fast`; default `standard`)
selects the live fee tier when fees are estimated. An optional `replacementPolicy` object
configures same-nonce fee replacement; see
[Dynamic Fee Replacement Design](../docs/fee-bump-replacement-design.md). `gasPrice` is
accepted but ignored (EIP-1559 only).

Request-boundary rules enforced before any DynamoDB/nonce work (a violation returns a
non-retryable `INVALID_REQUEST` response, never a Lambda panic):

- **`idempotencyKey` is required for direct broadcasts.** A direct `lambda:InvokeFunction`
  broadcast must supply a non-empty (trimmed) `idempotencyKey`; a missing or blank key is
  rejected with `INVALID_REQUEST`. For SQS delivery the key is optional: the queue
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
- **Size and gas bounds.** `data` may be at most 120 KiB. `gasLimit`, when supplied, must be
  greater than zero and at most 100,000,000.
- **Deployment hard caps.** An explicit `maxFeePerGas` above `HARD_MAX_FEE_PER_GAS_WEI`, or
  `gasLimit × maxFeePerGas` above `HARD_MAX_TOTAL_FEE_WEI`, is rejected with
  `INVALID_REQUEST`. The same breach from a live fee quote returns a retryable
  `GAS_ESTIMATION_FAILED`, because the market may fall back under the cap.

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

On the SQS path a retryable failure returns an error to the Lambda runtime so SQS redelivers
the message (and routes it to the DLQ after `maxReceiveCount`); a non-retryable failure is
acknowledged and discarded.

## Sign Hash

A direct invocation whose payload has no `to` field and carries `hash`, or
`domainSeparator` + `structHash`, or `typedData`, is routed to the sign-hash path instead of
broadcast. It resolves the signer for `from`, signs the 32-byte digest, and returns
`{ r, s, v, signature }`. No nonce, reservation, or DynamoDB write is involved. SQS events
always route to broadcast. Request formats for all three modes are documented in the
[root README](../README.md#sign-hash).

Sign-hash can be disabled with `SIGN_HASH_ENABLED=false`. While it is on, every principal
that can invoke the Lambda can obtain a signature over any digest, including the signing
hash of a transaction built offline, which bypasses nonce management, simulation, and the
fee caps. Deployments that only broadcast should turn it off; a disabled path refuses with
`INVALID_REQUEST` before resolving a signer. See
[Ingress and signing authority](../docs/security-model.md#ingress-and-signing-authority).

## Signing Backends

All backends use a unified raw transaction flow: build unsigned tx → compute signing hash → `sign_hash()` via the `TransactionSigner` trait → verify signature → encode signed tx → `send_raw_transaction()`. The `SignerProvider` routes to the correct backend based on `SIGNER_BACKEND`, an optional `SIGNER_MAPPINGS` address table, or per-request `signerCredentials`.

| Backend | Cargo feature | Config | Description |
|---------|---------------|--------|-------------|
| `nitro` (default) | `nitro` (on by default) | `NITRO_ENDPOINT`, `NITRO_SECRET_ID` | AWS Nitro Enclave isolated signing over HTTPS |
| `secrets_manager` | always compiled | `SECRETS_NAME` | Private keys in Secrets Manager (JSON: `{"0xAddr": "key"}`); development only |
| `coinbase` | `coinbase` (opt-in) | `CDP_*` env vars plus `walletSecretArn` in request | Coinbase Developer Platform API |

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

`backend: "nitro"` is accepted but carries nothing to override: the signing service picks
the wallet from its own configuration. Per-request `secrets_manager` credentials are not
supported and return a signer error. Requests that carry `signerCredentials` cannot use
`replacementPolicy`.

### Environment Credentials

For single-tenant deployments, configure via environment variables and omit `signerCredentials`.

## Environment Variables

Defaults below are the values compiled into `src/config.rs`, `src/signing/config.rs`,
`src/signing/nitro.rs`, and `src/signing/provider.rs`. The CDK stack sets most of them
explicitly; see the root README for the deployment-level view.

**Core**

| Variable | Description | Default |
|----------|-------------|---------|
| `CHAIN_ID` | Ethereum chain ID; must be a non-zero integer | **required** (no default; never assumes mainnet) |
| `DYNAMODB_TABLE` | Transaction tracking table (CDK names it `{resourcePrefix}-tracker`) | **required** |
| `RPC_SECRET_ARN` | Secrets Manager secret `{"rpcUrl": ..., "wsRpcUrl": ...}` holding the provider endpoint (and API key). When set, overrides the plaintext URL variables below | - |
| `ETH_RPC_URL` or `RPC_URL` | Ethereum HTTP RPC (`ETH_RPC_URL` takes precedence); non-prod only | `http://localhost:8545` |
| `TTL_DAYS` | TTL applied to terminal and idempotency rows | `7` |
| `FUNCTION_MODE` | `replacement` makes this binary act as the replacement worker (SQS-driven, separately permissioned). Any other value, or unset, is the broadcast/sign-hash function | unset |
| `SIGN_HASH_ENABLED` | Allow direct invocations to use the sign-hash path. Only the literal `true` (case-insensitive) enables it; see [Sign Hash](#sign-hash) | `true` |

**Gas and fees**

| Variable | Description | Default |
|----------|-------------|---------|
| `DEFAULT_GAS_LIMIT` | Gas limit used when `eth_estimateGas` fails for a plain transfer (empty `data`). Contract calls return `GAS_ESTIMATION_FAILED` instead | `21000` |
| `GAS_BUFFER_PERCENTAGE` | Buffer added to gas estimates | `20` |
| `FEE_TIP_FLOOR_WEI` | Minimum priority fee used by the live fee estimate | `100000000` (0.1 gwei) |
| `DEFAULT_MAX_FEE_PER_GAS_WEI` | Default per-gas ceiling for a replacement policy that omits `maxFeePerGasWei` | `150000000000` (150 gwei) |
| `HARD_MAX_FEE_PER_GAS_WEI` | Non-bypassable per-gas cap on every signature this Lambda produces | `500000000000` (500 gwei) |
| `DEFAULT_MAX_TOTAL_FEE_WEI` | Default `gasLimit × maxFeePerGas` budget for a replacement policy that omits `maxTotalFeeWei` | `20000000000000000` (0.02 ETH) |
| `HARD_MAX_TOTAL_FEE_WEI` | Non-bypassable `gasLimit × maxFeePerGas` cap on every signature | `100000000000000000` (0.1 ETH) |
| `REPLACEMENT_ENABLED` | Enable family-backed same-nonce replacement for live fee-tier requests. Only the literal `true` (case-insensitive) enables it | `true` |
| `MAX_REPLACEMENT_ATTEMPTS` | Deployment maximum replacement generations; a request's `maxBumps` may not exceed it | `3` |

Configuration fails at startup if a `DEFAULT_MAX_*` value exceeds its `HARD_MAX_*` value.
`MAX_RETRIES` (default `3`) and `RPC_TIMEOUT_SECS` (default `30`) are read into the config
but not used anywhere; broadcast does no in-invocation retry by design.

**Signer selection**

| Variable | Description | Default |
|----------|-------------|---------|
| `SIGNER_BACKEND` | Default backend: `nitro` (or `nitro_enclave`), `secrets_manager` (or `secretsmanager`), `coinbase`. Unrecognised values fall back to the default | `nitro` when built with the `nitro` feature (the default), otherwise `secrets_manager` |
| `SIGNER_MAPPINGS` | JSON array of `{"address": "0x...", "backend": "...", "config": {}}` entries routing specific addresses to a backend | `[]` |
| `SECRETS_NAME` | Secrets Manager secret name for the `secrets_manager` backend; only loaded when that backend is the default | - |

**Nitro backend**

| Variable | Description | Default |
|----------|-------------|---------|
| `NITRO_ENDPOINT` | Nitro Enclave NLB URL. Both this and `NITRO_SECRET_ID` must be set for Nitro to be configured | - |
| `NITRO_SECRET_ID` | Secret ID the signing service was deployed with; a log label only (see below) | - |
| `NITRO_AUTH_MODE` | `sigv4` or `mtls` | `sigv4` |
| `NITRO_AUTH_ROLE_ARN` | ARN of the Nitro stack's zero-permission signing-client role to assume for SigV4 identity proofs. When unset or blank, the Lambda's own execution-role credentials are used | - |
| `NITRO_CLIENT_IDENTITY_PATH` | PEM holding the client certificate and private key; required when `NITRO_AUTH_MODE=mtls` | - |
| `NITRO_CA_CERT_PATH` | Path to a PEM CA certificate for Nitro TLS validation | - |
| `NITRO_CA_CERT_PEM` | Inline PEM CA certificate for Nitro TLS validation (blank is treated as unset) | - |
| `NITRO_SKIP_TLS_VERIFY` | Skip Nitro TLS verification; `true` or `1` enables it (dev/test only) | unset |

In SigV4 mode the signing region is taken from `AWS_REGION` (set automatically in Lambda),
falling back to `us-east-1`.

`NITRO_SECRET_ID` does not select a wallet. It is never sent to the signing service, which
signs with the single wallet in its own deploy-time configuration; the value here only
labels logs and `SignerInfo`. Run one signing deployment per wallet. Requests to the service
are authenticated against an IAM allowlist; see
[Authentication](../docs/nitro-enclave-deployment.md#authentication).

When `NITRO_AUTH_ROLE_ARN` is set, the Lambda assumes that role
(`aws_config::sts::AssumeRoleProvider`, session name `tx-manager-nitro-auth`) and signs its
identity proofs as the assumed role, which is the ARN the allowlist pins. This is what lets
per-chain Lambdas authenticate without being individually allowlisted. When it is unset, the
Lambda uses its own execution-role credentials, the mode the Nitro stack's invoke Lambda
and the tests rely on. The selected identity mode is logged; role credentials never are.

**Coinbase backend** (requires the `coinbase` Cargo feature; all four of the first group
must be set for Coinbase to be configured)

| Variable | Description | Default |
|----------|-------------|---------|
| `CDP_API_KEY_NAME` | CDP API key name (JWT `kid`) | - |
| `CDP_API_KEY_SECRET_ARN` | Secrets Manager ARN holding the CDP API private key (PEM) | - |
| `CDP_WALLET_SECRET_NAME` | CDP wallet secret name (JWT `kid` for wallet operations) | - |
| `CDP_WALLET_SECRET_ARN` | Secrets Manager ARN holding the wallet secret (PEM) | - |
| `CDP_API_KEY_SECRET` | Raw PEM fallback for `CDP_API_KEY_SECRET_ARN`. **Debug builds only** (`#[cfg(debug_assertions)]`); not read in release builds | - |
| `CDP_WALLET_SECRET` | Raw PEM fallback for `CDP_WALLET_SECRET_ARN`. **Debug builds only**; not read in release builds | - |

## Error Codes

| Code | Description | Retryable |
|------|-------------|-----------|
| `INVALID_REQUEST` | Request rejected at the boundary: zero `from`/`to`, chain mismatch, missing/blank idempotency key, malformed fees, `data` over 120 KiB, `gasLimit` of zero or over 100,000,000, an invalid `replacementPolicy`, or an explicit `maxFeePerGas` or `gasLimit × maxFeePerGas` above the deployment hard caps (`HARD_MAX_*`) | No |
| `SIMULATION_FAILED` | `eth_call` reverted; reservation released | No |
| `GAS_ESTIMATION_FAILED` | `eth_estimateGas` failed for a contract call, or a live fee quote exceeded the deployment hard caps | Yes |
| `NONCE_EXHAUSTED` | Nonce reservation failed, typically because the wallet's maximum pending transactions is reached | Yes (after confirmations) |
| `NODE_REJECTED` | The node definitively refused the signed transaction at `eth_sendRawTransaction` (insufficient funds for gas, fee below base fee, intrinsic gas too low, exceeds block gas limit, encoding/signature/chain errors). The reservation is retired and the nonce recycled; nothing was broadcast | No |
| `HASH_MISMATCH` | Node acked a hash that disagrees with the signed bytes; `SIGNED` row retained for recovery | No |
| `DUPLICATE_IN_PROGRESS` | Same idempotency key is still in flight | Yes |
| `IDEMPOTENCY_CONFLICT` | Idempotency key reused with a different request body | No |
| `DUPLICATE_COMPLETED` | Idempotency key already completed but the stored result could not be read back | No |
| `SIGNER_ERROR` | Signer resolution or signing failed (broadcast path, before the durable handoff; or the sign-hash path) | Yes (broadcast) |
| `RPC_ERROR` | Node RPC transport failure before the durable handoff | Yes |
| `STATE_STORE_ERROR` | DynamoDB / nonce-authority failure before the durable handoff | Yes |
| `INFRASTRUCTURE_ERROR` | Configuration load or other AWS API failure (for example the RPC secret could not be read) | Yes |

Every `Err` the broadcast pipeline returns precedes the durable signed handoff, the nonce
reservation has been released, and the idempotency claim is released, so retrying is safe.
Infrastructure failures are therefore retryable: on SQS they are redelivered and reach the
dead-letter queue after `maxReceiveCount`, instead of being acknowledged and lost.

## Send-Error Classification

After the exact signed bytes are durably recorded (`SIGNED`), the outcome of
`eth_sendRawTransaction` is classified by the shared `nonce_manager::classify_send_error`
table so the Lambda and the watcher never disagree about what a node message means. There
are exactly four classes:

- **AlreadyKnown** (`already known`, `already imported`, `known transaction`): the node
  holds the bytes; treated as an ack and marked broadcast.
- **NonceTooLow**: the nonce is consumed on-chain, by our bytes or someone else's. Left
  `SIGNED`; the watcher checks for a receipt of the exact stored hash before advancing.
- **Definitive** (funds, fees, gas, encoding): never entered a mempool. Only on the
  *first* send: the reservation is retired, the nonce recycled, and `NODE_REJECTED` is
  returned. The watcher never recycles on this outcome for a rebroadcast.
- **Ambiguous** (timeouts, transport errors, `txpool is full`, `nonce too high`,
  `replacement transaction underpriced`, anything unrecognised): accepted; the row stays
  `SIGNED` and the watcher rebroadcasts the identical bytes.

## Building

```bash
# Native build (defaults to the nitro feature)
cargo build --release

# Include the Coinbase backend
cargo build --release --features coinbase

# Container image: run from the repository root, because the Dockerfile also copies
# ../nonce_manager. The image runs `cargo lambda build --release --arm64` internally.
finch build --platform linux/arm64 -f tx_broadcast_lambda/Dockerfile -t tx-broadcast-lambda .
```

`docker build` accepts the same arguments.

## Modules

| Module | Description |
|--------|-------------|
| `main` | Lambda entry point: routes SQS vs direct invocations, broadcast vs sign-hash, and `FUNCTION_MODE=replacement` |
| `handler` | Broadcast pipeline (validate → claim → gas → reserve → simulate → sign → record → send → mark) and sign-hash handler |
| `config` | `LambdaConfig` from environment, including RPC secret resolution and fee caps |
| `idempotency` | Claim-first idempotency records in the tracker table (`idem#<key>` rows) |
| `fees` | Live EIP-1559 fee estimation and replacement fee math |
| `replacement` | Replacement-worker path: reloads family policy from DynamoDB, re-clamps against hard caps, signs and activates the next candidate |
| `eip712` | EIP-712 typed data encoding and hashing for sign-hash mode 3 |
| `tx` | EIP-1559 transaction building, signing hash computation, encoding, local hash |
| `types` | Request/response types |
| `error` | `LambdaError` and `Result` |
| `signing/` | Signer backends behind the `TransactionSigner` trait: `traits`, `provider` (routing), `config`, `error`, `nitro`, `nitro_auth` (SigV4/mTLS identity proofs), `secrets_manager`, `coinbase` |
