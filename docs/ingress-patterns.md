# Ingress and Multi-EVM-Chain Routing Patterns

This sample/reference architecture documents two ingress patterns for EVM chain stacks. Both route to the same isolated
per-chain stacks and share only the chain-agnostic Nitro signing infrastructure. Neither
pattern introduces shared nonce or transaction state.

1. **Private API ingress**: a private API Gateway and stateless router provide one
   governed endpoint for multiple chains.
2. **Direct internal AWS ingress**: trusted AWS workloads invoke a per-chain Lambda or
   send directly to its SQS queue with the AWS SDK.

The repository currently provisions the direct internal resources: per-chain Lambda ARNs
and SQS queue URLs. The private API is an optional ingress layer that can be deployed in a
separate stack when a centralized front door is useful.

## Choosing a pattern

| Requirement | Private API ingress | Direct internal AWS ingress |
|---|---|---|
| One endpoint for many chains | Yes | Caller maintains a chain-to-resource map |
| Central request validation and routing | Yes | Implemented by each caller |
| Central caller-to-chain/wallet policy | Yes | IAM grants and caller-side policy |
| Asynchronous broadcast | API returns `202`; router sends to SQS | Caller sends to SQS |
| Synchronous broadcast or sign-hash | Router invokes the per-chain Lambda | Caller invokes the per-chain Lambda |
| Network boundary | Private REST API through an API Gateway VPC endpoint | AWS service APIs through IAM |
| Additional shared runtime | API Gateway plus one stateless router Lambda | None |
| Effect of ingress outage | New API requests stop; queued work continues | Only the affected caller stops |
| Best fit | Multiple teams, accounts, or centrally governed clients | Trusted services in a controlled AWS environment |

Use the private API when centralized governance and ease of integration outweigh the
additional shared ingress dependency. Use direct access when callers are trusted AWS
services and minimum infrastructure, latency, and cost are more important.

## Pattern 1: Private API ingress

```text
Private clients
      │
      │ HTTPS through execute-api VPC endpoint
      ▼
Private API Gateway REST API
IAM authorization + resource policy + validation + throttling
      │
      ▼
Stateless chain router Lambda
      │
      ├── chain 1 --------▶ Ethereum queue ------▶ Ethereum broadcast Lambda
      ├── chain 42161 ----▶ Arbitrum queue ------▶ Arbitrum broadcast Lambda
      ├── chain 8453 -----▶ Base queue ----------▶ Base broadcast Lambda
      └── chain 10 -------▶ Optimism queue ------▶ Optimism broadcast Lambda
                                  │
                                  ▼
                         Per-chain DynamoDB table
                    nonce + transaction lifecycle authority
```

The API Gateway, router Lambda, and optional access-log resources form a shared ingress
layer. The router is stateless: it does not reserve nonces, sign transactions, store
transaction lifecycle state, or inspect Nitro key material. If it is unavailable, no new
API submissions are accepted, but messages already in per-chain queues and all watcher
processing continue independently.

### Recommended API contract

Put the chain in the resource path rather than accepting an untrusted routing decision
only from the body:

```http
POST /v1/chains/11155111/transactions
Idempotency-Key: payout-2026-09-08-00042
Content-Type: application/json

{
  "from": "0x...",
  "to": "0x...",
  "value": "1000000000000000",
  "data": "0x..."
}
```

The router must reject a body `chainId` that differs from the path. It should inject the
validated path value into the SQS payload so the per-chain Lambda receives an explicit,
consistent chain ID.

The asynchronous response acknowledges durable queue acceptance, not mempool admission:

```http
HTTP/1.1 202 Accepted

{
  "requestId": "payout-2026-09-08-00042",
  "chainId": 11155111,
  "status": "ACCEPTED"
}
```

A useful endpoint set is:

```text
POST /v1/chains/{chainId}/transactions          asynchronous broadcast, returns 202
GET  /v1/chains/{chainId}/transactions/{hash}   transaction status
POST /v1/chains/{chainId}/signatures            synchronous sign-hash
```

Sign-hash cannot use SQS because the caller needs the signature in the response. Route it
synchronously to the chain Lambda and apply a stricter authorization policy: permission
to request an arbitrary hash signature is equivalent to signing authority for the wallet.

### Router responsibilities

The router should do only boundary work:

1. Authenticate the caller with IAM/SigV4. Do not treat an API key as authentication.
2. Enforce a caller-to-operation-to-chain-to-wallet policy.
3. Validate the path, payload shape, addresses, size, and required idempotency key.
4. Resolve the chain from a reviewed static deployment manifest.
5. Send asynchronous broadcasts to the exact per-chain queue ARN.
6. Invoke the exact per-chain Lambda ARN only for approved synchronous operations.
7. Return a correlation ID without logging transaction calldata or signature material.

Example deployment manifest:

```json
{
  "11155111": {
    "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/sepolia-prod-queue",
    "broadcastFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:sepolia-prod-broadcast",
    "permittedWallets": ["0x..."]
  },
  "42161": {
    "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/arbitrum-prod-queue",
    "broadcastFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:arbitrum-prod-broadcast",
    "permittedWallets": ["0x..."]
  }
}
```

Generate the router role from this manifest with exact `sqs:SendMessage` and, where
needed, `lambda:InvokeFunction` resource ARNs. Avoid account-wide or suffix-wildcard
permissions and avoid runtime CloudFormation discovery.

### Private API controls

For a private REST API:

- Restrict the API resource policy to approved VPC endpoint IDs and AWS principals.
- Require IAM authorization on every operation.
- Disable the public execute-api endpoint.
- Apply request schemas, body-size limits, throttles, access logging, and execution logs
  that omit sensitive payload fields.
- Give the router no DynamoDB or Nitro permissions; it needs only exact queue/function
  permissions.
- Require `Idempotency-Key` for transaction submission.

An API Gateway request ID and an SQS message ID are not substitutes for client
idempotency. A client retry receives new IDs and could otherwise represent a second
business operation. The stable client key becomes the request's `idempotencyKey`, which
the per-chain DynamoDB claim binds to a digest of the transaction intent.

### API Gateway versus a load balancer

API Gateway is the default front door because this workload benefits from IAM request
authorization, schemas, throttling, and AWS service integration. An ALB still needs a
Lambda or ECS router before SQS and provides fewer API-governance controls. An NLB cannot
route by HTTP path or chain ID. Consider an ALB only when a persistent HTTP routing
service, request duration, or measured sustained-volume cost requires it.

## Pattern 2: Direct internal AWS ingress

```text
Trusted internal AWS service
      │
      ├── sqs:SendMessage ──────▶ per-chain queue ──▶ broadcast Lambda
      │                              asynchronous
      │
      └── lambda:InvokeFunction ─▶ per-chain broadcast Lambda
                                     synchronous broadcast or sign-hash
```

This is the pattern deployed by the repository. Each chain stack outputs:

- `QueueUrl` for asynchronous broadcast.
- `BroadcastFunctionArn` for synchronous broadcast and sign-hash.
- `TxTrackerTableName` for operational status access by approved tooling.

The caller owns the chain-to-resource mapping. It can use static deployment
configuration or read CloudFormation outputs during deployment and pass the resolved
values to the application. Do not query CloudFormation on every transaction.

### Asynchronous direct submission

Use SQS for fire-and-forget work, batch distributions, and workflows that can poll or
receive status separately:

```python
sqs.send_message(
    QueueUrl=CHAIN_QUEUES[chain_id],
    MessageBody=json.dumps({
        "from": wallet,
        "to": recipient,
        "value": value_wei,
        "chainId": chain_id,
        "idempotencyKey": business_operation_id,
    }),
)
```

Grant the caller `sqs:SendMessage` only on the queues for chains it may use. Always send a
stable business idempotency key. The SQS `messageId` fallback protects a single message
from redelivery but cannot collapse two producer sends caused by a caller retry.

### Synchronous direct invocation

Use Lambda invocation when the caller requires an immediate transaction hash or
signature:

```python
response = lambda_client.invoke(
    FunctionName=CHAIN_FUNCTIONS[chain_id],
    Payload=json.dumps(request),
)
result = json.loads(response["Payload"].read())
```

Grant `lambda:InvokeFunction` only on exact per-chain function ARNs. A caller with direct
invoke permission is inside the transaction manager's trust boundary and must be trusted
for the configured wallet and operation. Sign-hash permission deserves a narrower caller
set than ordinary queued broadcast.

Synchronous invocation includes RPC simulation, Nitro signing, durable signed-byte
persistence, and a mempool send attempt. Callers must not respond to a timeout by creating
a new idempotency key: retry with the original key so the existing DynamoDB claim returns
the original transaction result.

### Internal routing example

```python
CHAIN_FUNCTIONS = {
    1: "ethereum-prod-broadcast",
    42161: "arbitrum-prod-broadcast",
    8453: "base-prod-broadcast",
}

CHAIN_QUEUES = {
    1: "https://sqs.us-east-1.amazonaws.com/123456789012/ethereum-prod-queue",
    42161: "https://sqs.us-east-1.amazonaws.com/123456789012/arbitrum-prod-queue",
    8453: "https://sqs.us-east-1.amazonaws.com/123456789012/base-prod-queue",
}
```

Validate the requested chain against these maps before constructing the transaction. A
per-chain Lambda must never be used with a different chain's ID or RPC endpoint.

## Invariants shared by both patterns

Regardless of ingress:

- The per-chain DynamoDB table is the sole nonce and lifecycle authority.
- A transaction must carry a stable client idempotency key for safe producer retries.
- Chain ID, caller identity, wallet, and operation are authorization inputs, not trusted
  routing hints.
- A queued response means accepted for processing, not broadcast or confirmed.
- Once signed bytes are durable, recovery rebroadcasts only those identical bytes.
- The Nitro signer remains the only infrastructure shared by chain stacks and signs one
  configured wallet's 32-byte hashes.
- Adding or removing an ingress layer does not change per-chain failure isolation.
