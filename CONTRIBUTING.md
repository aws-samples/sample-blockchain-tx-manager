# Contributing

Thanks for your interest in contributing. This project handles private keys and
on-chain signing, so changes go through careful review.

## Getting set up

Prerequisites (see the main README for version details):

- Rust 1.94.1 (pinned by `rust-toolchain.toml`)
- Node.js 22 LTS and npm
- Python 3.11
- AWS CDK CLI
- Docker (or Finch; the Lambda container build installs `cargo-lambda` inside
  `tx_broadcast_lambda/Dockerfile`, so it is not needed on your machine)

```bash
# CDK dependencies (lockfile-exact)
npm --prefix infra ci

# Python test environment (all requirement files are exact-pinned)
python3 -m venv nitro_enclave_signer/.venv
nitro_enclave_signer/.venv/bin/pip install \
  -r nitro_enclave_signer/requirements.txt \
  -r nitro_enclave_signer/requirements-dev.txt \
  -r nitro_enclave_signer/application/eth1/enclave/requirements.txt \
  -r nitro_enclave_signer/application/eth1/lambda/requirements.txt \
  -r nitro_enclave_signer/application/eth1/server/requirements.txt

# Full local gate (Java 17 + DynamoDB Local required for integration tests)
./scripts/run-tests.sh all

# Credential-free CDK synthesis and security assertions
(cd infra && npx cdk synth --all --context synthMode=true)
npm --prefix infra test
```

## Filing an issue

Before filing, search existing issues to avoid duplicates. For new issues, include:

- Which component (`nonce_manager`, `tx_broadcast_lambda`, `tx_watcher`,
  `nitro_enclave_signer`, `infra`, or cross-cutting)
- Reproduction steps or a minimal example
- Expected vs. actual behavior
- Environment (chain, deployment target, relevant env vars; **redact secrets**)

## Submitting a pull request

1. Open an issue first for non-trivial changes so the design can be discussed.
2. Keep PRs focused: one logical change per PR.
3. Write or update tests for behavior you change.
4. Run the checks above locally before pushing.
5. For changes that touch signing, IAM, networking, or KMS, include a short
   threat-model note in the PR description.

## Security-sensitive changes

Anything touching the following needs explicit review:

- Key material handling (signing, encryption, Secrets Manager)
- IAM policies and role assumption
- Network exposure (security groups, load balancers, TLS)
- Nitro Enclave attestation and PCR handling

If a change has security implications, prefer a private disclosure first
(see [SECURITY.md](SECURITY.md)).

## Security issue notifications

Do not create a public issue for a potential security vulnerability. Report it through the
[AWS Vulnerability Reporting](https://aws.amazon.com/security/vulnerability-reporting/)
process and follow [SECURITY.md](SECURITY.md).

## Licensing and code of conduct

See [LICENSE](LICENSE) for the project's MIT No Attribution (MIT-0) license and preserve
notices for any derived or third-party material. We will ask you to confirm the licensing of
your contribution. By contributing, you agree that your contribution is licensed under the
same MIT-0 license.

This project follows the [Amazon Open Source Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you agree to uphold it.
