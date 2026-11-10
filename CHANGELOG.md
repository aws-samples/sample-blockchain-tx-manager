# Changelog

This project follows [Semantic Versioning](https://semver.org/). Version numbers identify
reviewed source revisions of this sample; they are not claims of production readiness or
AWS service support.

## [0.1.2] - 2026-11-10

Pre-announcement review pass. Still a source-only sample provided as-is under MIT-0,
without warranty or support, and not intended for production use as-is. Package version
fields (`Cargo.toml`, `infra/package.json`) now carry the release version.

### Security

- Deployment hard fee caps (`HARD_MAX_FEE_PER_GAS_WEI`, `HARD_MAX_TOTAL_FEE_WEI`) now bound
  every broadcast, including requests with explicit fees and no replacement policy. They
  were previously consulted only while resolving a replacement policy.
- The replacement Lambda takes speed-up intent from the active candidate's wallet-signed
  bytes (decoded, hashed, signer-recovered) and refuses when the family row disagrees, so a
  writer of the DynamoDB table cannot steer a replacement signature.
- The Nitro stack refuses the debug-mode PCR0 (96 zeros) outside `deployment=dev`, warns
  when dev enforces it, and `verify-kms-attestation.sh` flags it. The dev deployment docs
  now state what a debug enclave can and cannot attest.
- `SIGN_HASH_ENABLED` / CDK `signHashEnabled` lets a broadcast-only deployment refuse the
  sign-hash path, which otherwise grants every invoker a signature over any digest.
- The watcher waits 90 seconds before first rebroadcasting a SIGNED row, leaving the
  broadcast Lambda's send and definitive-refusal handling exclusive.
- Nitro invoke Lambda loses an unused `secretsmanager:UpdateSecret` grant. Parent watchdog
  restarts an enclave that is present but not `Running`. vsock-proxy FIPS endpoint fixed.
- Security model documents that parent-instance compromise yields signing authority, that
  the signing-client role trusts the account root, the private-subnet reach of the signer
  port, idempotency-claim liveness after a crash, and the reorg window on fast chains.

### Fixed

- CDK did not pass `TTL_DAYS` to the watcher, so the `ttlDays` context had no effect on
  transaction-row TTL.
- Infrastructure failures before the durable signed handoff (signer, RPC, DynamoDB,
  configuration) are reported as retryable with specific codes instead of a non-retryable
  `UNKNOWN_ERROR`, so SQS redelivers them and dead-letters after `maxReceiveCount` instead
  of discarding the message.
- Coinbase `CDP_*_SECRET_ARN` values are resolved from Secrets Manager; release builds
  previously used the ARN string as the PEM.
- Watcher reads `gas_price` as the Number the nonce manager writes.
- Python signing server rejects a non-string `hash` with 400.

### Dependencies

- `rustls` 0.23.46, `rustls-webpki` 0.103.16, `webpki-roots`/`webpki-root-certs` 1.0.11,
  `ctutils` 0.4.8, `tokio` 1.54.1, yanked `yoke-derive` 0.8.3 replaced. CI ignores only
  RUSTSEC-2026-0387 (`crypto-bigint` 0.5, no fix reachable while alloy pins k256 0.13).
- `aws-cdk-lib` 2.275.0 and `aws-cdk` 2.1148.0. The npm audit allowlist accepts only the
  bundled `minimatch` advisory (GHSA-g3hv-75wg-m249) in place of the former
  `brace-expansion` set.

### Documentation

- Component READMEs rebuilt from the code (backends, flow order, env vars, error codes,
  states, modules). Root README env, CDK context, and DynamoDB attribute tables completed.
  Reorg reset documented as SIGNED when exact bytes are stored.
- Sample-code disclaimer on every user-facing document; aws-samples Security footer;
  licence wording corrected to MIT-0 throughout; repository URL in the clone step;
  FIPS 140-3 Level 3 for KMS HSMs; dead citations removed; architecture image reduced
  from 1.9 MB to 184 KB.
- `THIRD-PARTY-LICENSES` records the one git dependency (`esrauch/paste` fork).
- Docs and signature tests use a throwaway test-vector address
  (`0xD764672D0bF0Cf30d2D3D665Bb5edd919Aa86384`, key derived from a public string) instead
  of a wallet generated during development.

## [0.1.1] - 2026-10-13

First publication of this source under `aws-samples`. Like 0.1.0, it is a source-only
sample provided as-is under MIT-0, without warranty or support, and is not intended for
production use as-is.

### Fixed

- Nitro signer: a fresh stack could boot its instances before the ECR/S3 VPC endpoints were
  serving, leaving both parents permanently without a signer. The ASG now depends on those
  endpoints, user_data retries the ECR login and image pulls, and the ASG replaces
  instances the NLB `/health` check marks unhealthy (20-minute grace).
- Broadcast Lambda image build retries its pinned zig/uv downloads on transient errors.
- `verify-kms-attestation.sh` no longer warns about CDK's default account-root key
  administration statement.

### Documentation

- Deployment instructions corrected where following them literally failed: the Nitro
  `secretId` and generated key name must match, direct invokes require `idempotencyKey`,
  per-crate test commands, and `.nitro-config` overriding exported values.
- The README hosts its architecture diagram in the repository.
- Strict-profile (`environment=prod`) and multi-wallet examples use testnets and neutral
  wallet names, and are labeled illustrative. Known Limitations and the Security Model
  state the as-is, non-production status more directly.

## [0.1.0] - 2026-10-01

Initial source-only release of the Ethereum Transaction Manager AWS sample/reference
architecture. This version predates the public repository history and carries no tag;
0.1.1 was the first revision published. It distributes no prebuilt image, EIF, PCR value,
deployed endpoint, wallet, or credential; customers build and validate those artifacts in
their own environment.

### Scope

- Atomic per-wallet EVM nonce reservation and lifecycle tracking in DynamoDB.
- EIP-1559 type-2 transaction simulation, signing, broadcast, idempotency, receipt tracking,
  reorganization recovery, and bounded dynamic same-nonce fee replacement.
- Nitro Enclaves sample signer with KMS attestation, encrypted wallet material, authenticated
  TLS ingress, reproducible EIF inputs, and fail-closed no-PCR bootstrap.
- Per-chain AWS CDK infrastructure for Lambda, SQS, ECS/Fargate, DynamoDB, Secrets Manager,
  KMS, CloudWatch, and alarm delivery.
- Development-only Secrets Manager and Coinbase signer adapters.

### Validated paths

- Complete local Rust, Python, TypeScript/CDK, cdk-nag, shell, secret, and DynamoDB Local
  gates.
- Clean-room first deployment into newly named resources and a new VPC.
- Repeated EIF build with identical PCR measurements, measured KMS redeploy, two-parent
  signer isolation, CA/SAN verification, and healthy load-balancer targets.
- Bounded funded Sepolia lifecycle through nonce 6, including idempotency, exact-byte crash
  recovery, concurrency, dynamic replacement, duplicate delivery, watcher replacement,
  alarms, and final nonce reconciliation.
- AWS-owned DynamoDB encryption in the clean-room run; existing-CMK, multi-Region-key, and
  stack-created rotating-CMK paths were validated separately.
- Revalidation of the final source on the same clean-room resources: all four images
  rebuilt and scanned, EIF rebuilt twice with identical PCR0/1/2, deployment TLS CA rotated,
  parents rolled onto the new measurement, two-parent isolation, deterministic raw-hash and
  EIP-712 signing (raw, pre-computed, and full typed data), boundary rejection with zero
  writes, an idempotent funded transaction, final nonce reconciliation, and alarm delivery.

### Changes since the 2026-09-15 candidate

- Refreshed pinned base images and applied vendor security errata; parent signing server
  moved to Python 3.14; unused `boto3` removed from the enclave.
- Patched Rust dependencies (`rustls` 0.23.45 at the time; optional Coinbase `jsonwebtoken` 10.4.0).
- Parent bootstrap no longer traces CA key material in user-data logs.
- `deploy-nitro-stack.sh` resolves the exact Nitro instance security group instead of
  possibly selecting a VPC-endpoint group.
- Runbook parent-isolation check no longer fails spuriously under `pipefail`.
- README documents EIP-191 `personal_sign` via raw-hash mode and its blind-signing risk.
- CI accepts only the `aws-cdk-lib`-bundled `brace-expansion` advisories (no upstream fix;
  synth-time only) and still fails on any other moderate-or-higher npm advisory.

### Known residual findings

- Container scans report no fixable High or Critical findings. Remaining findings are
  distribution packages without an available fix, CPython issues fixed only in pre-release
  3.15, and the AWS Lambda base image's local emulator binary. Customers must apply their own
  vulnerability policy and rebuild cadence.

### Compatibility and non-goals

- This release supports EVM-compatible chains and EIP-1559 type-2 transactions. It does
  not provide arbitrary blockchain, account-abstraction, blob-transaction, or access-list
  transaction support.
- It is not an AWS service, supported product, turnkey custody system, customer production
  certification, or production-ready deployment.
- No stable public API or backward-compatibility commitment exists before the first stable
  release. Customers must review and adapt IAM ingress, business authorization, custody,
  availability, observability, RPC-provider, backup, incident-response, and deployment
  controls.
- Throughput and scale recommendations remain measurement-gated; this release makes no
  production throughput claim.

See [Known Limitations and Customer Responsibilities](docs/known-limitations.md) for the
sample's scope, boundaries, and customer-owned responsibilities.
