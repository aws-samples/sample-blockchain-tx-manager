# Security Policy

## Project status

This repository is an AWS sample/reference architecture provided under its license without
warranty, operational support, or a response-time SLA. Customers adopting it own their
security review, dependency updates, deployment controls, monitoring, and incident response.

## Reporting a vulnerability

Do not include vulnerability details, credentials, wallet material, signed transactions, or
provider URLs in a public issue.

- Report a repository vulnerability through
  [AWS Vulnerability Reporting](https://aws.amazon.com/security/vulnerability-reporting/).
  Do **not** create a public GitHub issue.
- For a vulnerability in an upstream dependency, also notify the upstream maintainer using
  its private disclosure process.

Include the affected revision/component, impact, reproduction conditions, and a suggested
mitigation when available. Never use funded customer wallets or production systems for a
proof of concept.

## Scope

Reports relevant to this repository include:

- Rust components (`nonce_manager`, `tx_broadcast_lambda`, `tx_watcher`).
- CDK infrastructure (`infra/`).
- Nitro Enclave application and integration changes carried in this repository.
- Deployment/build scripts and CI configuration.
- Documentation that would cause customers to deploy an unsafe configuration.

Underlying AWS service vulnerabilities and defects unchanged from third-party/upstream
projects should be reported to their respective owners. A vulnerability caused by this
repository's integration or modification remains relevant here even when the original code
was derived from an upstream sample.

## Handling sensitive test data

Use isolated testnet stacks and test wallets. Redact AWS account IDs where appropriate, RPC
credentials, secret values, CA private keys, wallet ciphertext, transaction payloads, and
signed raw transactions. Follow `docs/finch-and-canary-runbook.md` for the sample's guarded
canary procedure.
