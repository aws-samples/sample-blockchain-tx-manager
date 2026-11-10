# Security Model and Threat Boundaries

> **Sample/reference architecture, not a production-ready custody system.** This document
> describes the security properties and limits of the repository's tested reference path.
> It does not replace an adopter's threat model, transaction authorization, custody,
> availability, compliance, or incident-response review. Start with
> [Known Limitations and Customer Responsibilities](known-limitations.md).

## Scope and security objectives

The reference path manages EIP-1559 transactions for one EVM chain per transaction-manager
stack. It aims to:

- prevent two accepted requests from receiving the same nonce for the same wallet and chain;
- retain exact signed transaction bytes before attempting network broadcast, so an ambiguous
  send is recovered without signing a second transaction;
- keep an encrypted wallet key outside the application process and restrict KMS decryption
  to an enclave whose measurement matches the deployment policy;
- authenticate the transaction-manager Lambda to the Nitro signing service and restrict the
  network path to the internal signer; and
- keep automated same-nonce replacement constrained by the original immutable intent and
  configured hard fee limits.

It does **not** decide whether a requested recipient, contract call, value, signature, or
cancellation is business-authorized. A party allowed to request an arbitrary hash signature
has signing authority for that wallet. An adopter must put caller, operation, wallet,
destination, value, calldata, and rate/approval policy at its ingress boundary.

## Assets and security-relevant data

| Asset | Primary location | Intended protection | Residual concern |
|---|---|---|---|
| Wallet private key | Plaintext exists only while used by the attested enclave; encrypted ciphertext is stored in Secrets Manager | KMS attestation policy and enclave isolation | Wallet replacement changes the EVM address; it is not ordinary secret rotation. |
| KMS-encrypted wallet ciphertext | `nitro-wallet/` Secrets Manager secret | Secrets Manager access control and KMS key policy | Deleting or disabling the key makes the wallet unrecoverable. |
| Deployment TLS CA private key | `nitro-tls-ca/` Secrets Manager secret, read by Nitro parents at boot | IAM restriction, CA rotation, and operator audit | A party that can read this secret can issue certificates trusted by clients that pin the CA. |
| RPC credentials | Per-chain Secrets Manager secret | Per-role secret access; production deployment rejects plaintext RPC configuration | RPC URLs often contain provider credentials and must not enter logs, templates, or application configuration. |
| Signed transaction bytes and transaction hash | Per-chain DynamoDB tracker table | Atomic durable handoff, table encryption, backup and deletion controls | Signed bytes and calldata may be sensitive operational data; terminal TTL is not a legal-retention policy. |
| Nonce, idempotency, and replacement-family state | The same per-chain DynamoDB tracker table | Conditional `TransactWriteItems` state transitions | Data loss, an unsafe restore, or a compromised table writer can affect broadcast correctness. |
| Build, image, EIF, and PCR evidence | Customer-controlled release evidence store | Pinned inputs, repeated measurement, checksums, and review | A parent-reported PCR is not independent evidence; the builder and source review are trust prerequisites. |

## Principals and trust boundaries

| Principal or boundary | Authority in the reference path | What it must not be assumed to provide |
|---|---|---|
| Caller | Directly invokes the per-chain Lambda or sends to its queue. It supplies transaction intent and a stable idempotency key. | Business authorization is not inferred from Lambda/SQS IAM permission alone. |
| Optional private API/router | Performs customer-provided IAM authorization, validation, throttling, and chain/wallet routing before the per-chain resources. | It is documented, not provisioned by this repository; it must not hold nonce state or signer permissions. |
| Broadcast Lambda | Validates a request, claims idempotency, reserves a nonce, simulates, signs, stores exact bytes, and attempts broadcast. | It is not a destination allowlist, approval workflow, or custody policy engine. |
| Replacement Lambda | Recreates only a policy-authorized replacement. Fees are re-clamped against deployment hard caps; speed-up intent is decoded from the active candidate's wallet-signed bytes and must match the family row, so a tampered row is refused rather than signed. | It cannot authorize unlimited fees, a different intent, or a per-request signer override. |
| Watcher | Tracks blocks, receipts, reorgs, stale transactions, and enqueues identity-only replacement work. | It has no Nitro signing identity and must not sign a new transaction. It can write tracker rows, so its compromise can disrupt lifecycle state (availability), but it cannot steer a replacement signature. |
| DynamoDB | Sole per-chain nonce and transaction-lifecycle authority. | It is not a cross-region consensus system or substitute for backup/restore testing. |
| Nitro parent instance | Hosts the enclave, NLB endpoint, ciphertext, and deployment-CA retrieval path. | It is untrusted for plaintext wallet-key custody and may affect availability or the network path. |
| Nitro enclave | Generates/decrypts the wallet key and signs hashes after KMS attestation succeeds. | Attestation does not authorize the business action represented by a hash. |
| KMS and Secrets Manager | Protect encrypted key material, deployment CA material, and RPC credentials using AWS policy. | They do not protect against an authorized but malicious deployment operator or caller. |
| RPC provider and EVM network | Supply simulation, fees, nonce observations, block headers, receipts, and mempool admission. | They are external trust and availability dependencies, not a source of business truth. |
| Deployment operator | Builds/measures images and EIFs, configures PCR0, CA, IAM, network, alarms, and stacks. | The sample does not constrain operator privilege or replace change management. |

A shared Nitro deployment may serve multiple per-chain stacks because it signs 32-byte
hashes. Chain isolation comes from each chain stack's separate DynamoDB table, queue,
Lambda, watcher, RPC secret, and configuration. A shared signer therefore remains a custody
boundary that adopters should separate further when wallets or policy domains require it.

## Ingress and signing authority

The deployed direct-ingress pattern exposes a per-chain Lambda and SQS queue. Callers need
only the exact `lambda:InvokeFunction` and/or `sqs:SendMessage` resources for their approved
chains. These grants are necessary but not sufficient transaction controls: direct callers
are trusted to submit only approved transaction intent. The optional private API/router
pattern is the recommended place to enforce caller-to-chain-to-wallet-to-operation policy,
request limits, and destination/value/calldata rules.

For broadcasts, a direct Lambda caller must send a stable request-unique `idempotencyKey`.
SQS falls back to the message ID only for one message's redelivery, so it cannot collapse a
producer retry that creates a second message. The claim binds the key to a request digest:
reuse with different intent returns an idempotency conflict rather than silently accepting
new intent.

`sign-hash` is intentionally stateless: it creates no DynamoDB row and reserves no nonce.
Its authorization should be narrower than broadcast authorization because it authorizes a
signature over a caller-selected hash, including a valid EIP-712 hash.

## Per-chain nonce and transaction-state authority

DynamoDB is the sole nonce and lifecycle authority for one chain stack. The broadcast path
claims idempotency before nonce allocation. It then conditionally reserves a nonce and
creates the associated state in DynamoDB. Multi-key state changes use DynamoDB
`TransactWriteItems`; there is no Redis or second lifecycle store to reconcile.

Before the first raw-transaction send, the broadcast Lambda computes the hash of the exact
EIP-2718 bytes and atomically records those bytes and the `SIGNED` tracker state. This is
the durable handoff. Failures before it release only a still-`RESERVED` nonce. After it,
ambiguous transport failures fail closed: the transaction is not re-signed or reallocated;
the watcher checks and rebroadcasts only the stored bytes after verifying that their hash
matches the stored transaction hash.

The watcher records cursors, processes reorgs, and finalizes nonces only after its receipt
and chain-nonce checks. When another transaction has consumed a nonce, the reference path
marks the local transaction `DROPPED` and treats the nonce as consumed rather than reusing
it. These controls reduce duplicate sends and nonce reuse, but their correctness depends on
DynamoDB availability and the EVM/RPC observations described below.

The table uses encryption at rest in every mode. Outside explicit disposable deployments it
has point-in-time recovery and deletion protection. Adopters choosing an existing or
stack-created CMK must keep that CMK, its policy, and restore permissions available for the
life of the table and its backups.

## Nitro, KMS attestation, and parent-compromise model

The Nitro stack creates a KMS key for encrypted wallet material and a key policy with two
load-bearing rules:

1. an explicit `Deny` applies to `kms:Decrypt` and `kms:GenerateDataKey` when the request
   lacks the expected `kms:RecipientAttestation:ImageSha384` value or presents a different
   value; and
2. after an independently measured PCR0 is supplied, an `Allow` permits those actions to
   the parent role only when the recipient attestation matches that exact PCR0.

The explicit deny is required because an allow condition alone cannot subtract the account
root's KMS delegation. Before PCR0 is deployed, the deny is unconditional and no wallet
key can be generated or decrypted. `verify-kms-attestation.sh` checks the deployed policy,
but an adopter must measure the EIF twice on a trusted pinned builder, record source and
input digests, and compare the independently measured PCR0 before deployment.

The EC2 parent has ciphertext and AWS credentials used to proxy enclave KMS requests, but
it must be denied direct decrypt without enclave recipient attestation. This boundary is
not a claim that a compromised parent is harmless. A compromised parent can deny service,
interfere with traffic, expose ciphertext or operational data available to it, and read the
deployment CA secret used to mint replacement-instance certificates. It must not be used as
independent PCR evidence or trusted with wallet-key plaintext.

The signer is internal behind an NLB. The per-chain Lambda security group is the intended
signing-service client network source. The broadcast and replacement Lambdas assume the
Nitro stack's exact zero-permission signing-client role solely to obtain an allowlisted
SigV4 identity; the role does not grant AWS API permissions. The signer validates its
allowlisted caller identity. Adopters must review all allowed principals and avoid granting
`sts:AssumeRole` on that role outside the intended signing clients.

## TLS and deployment-CA lifecycle

The deployment path can create a CA secret and use it to issue a server certificate for
each parent whose SAN is the internal NLB DNS name. The broadcast and replacement Lambdas
receive the public CA certificate and validate the signer hostname. Production-style
configuration rejects TLS verification bypass and requires a pinned deployment CA when a
Nitro endpoint is configured.

CA protection is part of the signing boundary. Restrict and audit read access to the
`nitro-tls-ca/` secret, preserve it while live parents depend on it, and define rotation and
recovery before deployment. Rotating the CA requires a controlled parent roll and client
public-CA update. Do not treat a self-signed development certificate or
`NITRO_SKIP_TLS_VERIFY` as suitable for a non-development deployment.

## Replacement authority and fee bounds

The watcher has DynamoDB lifecycle access, RPC access, and send-only access to the internal
replacement queue. It has no Nitro signing-client role and cannot invoke a signer. For a
due replacement family it submits only wallet, nonce, expected generation, and action.

The replacement Lambda reloads the DynamoDB family and rejects stale generations,
non-active families, wrong chains, and unsupported actions. Immediately before signing it
rechecks the active receipt, chain nonce, and block cadence. It rebuilds either the immutable
original intent or the explicit zero-value self-cancel and clamps every quote against both
the immutable family ceilings and deployment hard per-gas/total-fee limits. Activation of a
new candidate is conditional and atomic. A duplicate queue message therefore cannot create
a second generation.

These controls do not make cancellation guaranteed: an earlier candidate may mine first,
and a policy ceiling may prevent a further replacement. Exhaustion defaults to holding the
existing transaction and alarming. Per-request signer overrides cannot use replacement
families because the worker cannot safely reproduce caller-specific signer routing.

## RPC provider, mempool, and EVM-chain assumptions

The sample trusts configured RPC endpoints for `eth_call`, fee data, chain nonce, headers,
and receipts. Provider outages, stale views, WebSocket stalls, rate limits, inconsistent
load-balanced nodes, censorship, or incorrect responses can delay or prevent processing.
The watcher reconnects, persists a cursor, detects tracked reorgs, rechecks a receipt before
marking a transaction dropped, and rebroadcasts exact bytes; these are recovery measures,
not Byzantine-provider protection or finality guarantees.

A node acknowledgement does not prove confirmation. The watcher waits for configured
confirmations and can reset orphaned mined/confirmed records to `PENDING` after a detected
reorganization. Required confirmations, fee policy, RPC redundancy, provider quotas, and
acceptable chain/finality risk are customer-owned decisions for each supported EVM chain.

## Availability, backup, and regional failure

The reference topology is regional. Its state table, queues, Lambda functions, watcher,
NLB, and signer instances do not provide active-active multi-region operation. The default
VPC also has a single NAT gateway. Customers must define recovery objectives, test
DynamoDB restores with the selected encryption key, validate wallet recovery procedures,
and design multi-AZ/multi-region/provider strategies appropriate to their risk.

Alarms and the watcher heartbeat can surface a failed or stalled component, but the sample
does not supply dashboards, paging integration, staffed operations, or an incident-response
organization. Configure a durable alarm subscriber, protect log access, and ensure logs,
tickets, and evidence do not contain RPC URLs, CA private keys, wallet ciphertext, or signed
raw transactions from funded wallets.

## Residual risks and explicit non-goals

The following remain outside the guarantees of this sample:

- business authorization, approval quorums, sanctions screening, destination governance,
  spending limits, MPC/HSM policy workflows, and custody compliance;
- arbitrary blockchains, account abstraction, blob transactions, access-list API support,
  and a separate immediate operator-cancel API;
- measured high-volume scaling, sharded status-index design, provider-specific receipt
  batching, and guaranteed provider capacity;
- cross-region disaster recovery, active-active nonce coordination, customer account
  isolation, organizational guardrails, and operator compromise; and
- any claim of service support, uptime, production certification, or a customer launch
  decision.

The security review for an adopter should use this document with the exact release commit,
source/image/EIF evidence, synthesized IAM policies, deployed configuration, and its own
funded non-production canary. A source change affecting signing, IAM, networking, KMS,
Docker inputs, or the state machine requires a renewed review and canary before relying on
an adaptation.
