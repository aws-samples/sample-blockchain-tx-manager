# Changelog

This project follows [Semantic Versioning](https://semver.org/). Version numbers identify
reviewed source revisions of this sample; they are not claims of production readiness or
AWS service support.

## [Unreleased]

### Fixed

- Nitro signer: a fresh stack could boot its instances before the ECR/S3 VPC endpoints were
  serving, leaving both parents permanently without a signer. The ASG now depends on those
  endpoints, user_data retries the ECR login and image pulls, and the ASG replaces
  instances the NLB `/health` check marks unhealthy (20-minute grace).
- Broadcast Lambda image build retries its pinned zig/uv downloads on transient errors.
- `verify-kms-attestation.sh` no longer warns about CDK's default account-root key
  administration statement.

## [0.1.0] — 2026-10-01

Initial source-only release of the Ethereum Transaction Manager AWS
sample/reference architecture. It distributes no prebuilt image, EIF, PCR value, deployed
endpoint, wallet, or credential; customers build and validate those artifacts in their own
environment.

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
- Patched Rust dependencies (`rustls` 0.23.45; optional Coinbase `jsonwebtoken` 10.4.0).
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
