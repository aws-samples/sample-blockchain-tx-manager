# Known Limitations and Customer Responsibilities

## Project status

This repository is an **AWS sample and reference architecture**. It demonstrates a vetted
pattern for EVM transaction submission, nonce coordination, Nitro Enclave signing, recovery,
and monitoring. It is not an AWS service, supported product, turnkey custody system, or
statement that a deployment is ready for a customer's production workload.

Customers are responsible for reviewing, adapting, testing, securing, and operating their
own deployment. Testnet canary evidence in this repository validates the sample's tested
paths; it does not certify a customer environment or satisfy a customer's security,
compliance, availability, or financial-risk requirements.

## Functional scope

- **EVM only.** The transaction path builds EIP-1559 type-2 transactions. It does not
  implement Solana, Bitcoin, arbitrary non-EVM chains, blob transactions, account
  abstraction/user operations, or legacy gas-price transactions.
- **Empty access lists.** The public request does not currently accept EIP-2930 access-list
  entries.
- **One Nitro wallet per signer deployment.** The Nitro service selects its configured
  secret; callers cannot choose another Nitro wallet per request. Deploy separate signer
  boundaries where distinct key custody or policy domains are required.
- **Per-request signer overrides are not replacement-managed.** Requests using
  `signerCredentials` may broadcast, but cannot opt into automated same-nonce replacement
  because the internal worker cannot safely reproduce caller-specific signer routing.
- **Cancellation is an attempt.** `onExhaust=cancel` submits a higher-fee zero-value
  self-transfer at the same nonce. An earlier candidate may still win, and a configured fee
  ceiling can make cancellation inadmissible. There is no separate immediate operator-cancel
  API in this sample.
- **Ingress choice is not provisioned centrally.** The stack exposes IAM-authorized Lambda
  and SQS resources. The optional private API Gateway/router pattern is documented but not
  deployed by this repository.

## Scale and availability boundaries

- The status GSI uses transaction status as its partition key. This is simple and appropriate
  for moderate per-chain active sets, but customers expecting sustained high write rates to
  one status value must load-test and may need sharded status keys.
- Receipt checks are per candidate with bounded concurrency. At large active-set sizes,
  customers should evaluate provider rate limits and `eth_getBlockReceipts` support before
  increasing concurrency or replacing the portable per-hash path.
- The default design is regional, not active-active multi-region. DynamoDB state, ECS watcher,
  Lambda functions, queues, NLB, and signer instances are deployed in one region.
- The sample Nitro VPC uses one NAT gateway and two signer instances by default. Customers
  must evaluate AZ failure modes, egress dependencies, quotas, capacity, and recovery
  objectives for their workload.
- Confirmation counts, fee percentiles, concurrency, timeout, and replacement defaults are
  illustrative policy values, not universal values for every EVM network.
- The watcher emits progress/replacement metrics and the stack creates alarms, but no
  dashboard, tracing system, paging integration, or operational staffing is provided.

## Key custody and cryptographic trust

- Customers must build and measure the EIF on a trusted, pinned builder, review the source
  and image inputs, and deploy the expected PCR0. Reading PCRs from an untrusted parent is
  not independent attestation evidence.
- The deployment CA secret contains its private key so replacement instances can issue
  per-instance certificates. Restrict that secret, audit access, and define a CA rotation
  and incident-response process appropriate to the customer's trust model.
- Blockchain wallet keys cannot be transparently rotated like API credentials. Replacing a
  wallet key changes the address; customers must plan authorization updates and transfer
  funds deliberately.
- The sample does not provide transaction approval quorums, HSM/MPC policy workflows,
  sanctions screening, address governance, or a custody compliance program.

## Data protection

- DynamoDB is always encrypted at rest. The default uses an AWS-owned key. Customers may
  import an existing CMK or ask the stack to create a rotating CMK when key-policy control,
  independent disablement, or compliance evidence is required.
- Disabling or deleting a DynamoDB CMK makes tracker/nonce data unavailable. Key lifecycle
  must outlive retained tables and backups.
- Point-in-time recovery and deletion protection are enabled outside explicit
  `destroyOnRemoval` deployments. Customers own backup retention, restore testing,
  cross-region recovery, and legal retention requirements.
- RPC URLs commonly embed provider credentials. Production-style deployments require the
  Secrets Manager RPC path, but customers own credential issuance, rotation, provider
  restrictions, and rate limits.

## Customer-owned controls

Customers must provide and operate at least:

1. IAM authorization for every caller and deployment operator.
2. Network/ingress design, AWS account boundaries, SCPs, and service quotas.
3. RPC providers and Secrets Manager values for every chain.
4. Alarm destinations, paging rules, dashboards, and on-call response.
5. Wallet generation ceremony, funding policy, transaction limits, and recovery procedures.
6. Chain-specific confirmation, fee, replacement, and cancellation policy.
7. CMKs/key policies where customer-managed encryption is required.
8. Load, failure, disaster-recovery, security, and compliance testing in the customer's
   environment.
9. Dependency updates, release review, change management, rollback, and incident response.

Any organization considering an adaptation is responsible for defining and validating its
own architecture, security, operational, compliance, and launch criteria.
