# Nitro Enclave Signer Deployment Guide

This guide walks through the Nitro Enclave signer used by this sample/reference architecture.
It is not a custody certification or universal production design; adopters must review the
trust model, independently reproduce EIF/PCR evidence, and own key operations.

## Security Model

### Why Nitro Enclaves?

Nitro Enclaves provide an isolated compute environment where:
- The parent EC2 instance cannot access enclave memory
- Only attested code can decrypt secrets via KMS
- Private keys exist in plaintext only inside the enclave

### Why Not KMS Asymmetric Keys?

KMS supports `ECC_SECG_P256K1` (secp256k1) and may be a simpler signer for some
customer requirements. This sample uses Nitro to demonstrate attested custom signing logic
and enclave-only plaintext handling. Customers must compare KMS request/key pricing,
Nitro-capable EC2/NLB/NAT cost, operational complexity, throughput, and policy requirements;
the sample configures one wallet secret per signer deployment, not unlimited caller-selected
wallets.

### Secure Key Generation

Private keys are generated inside the enclave using KMS `GenerateDataKey`:

1. **Randomness from KMS** - 32-byte private key comes from KMS's FIPS 140-2 validated HSMs
2. **Plaintext only in enclave** - KMS returns plaintext only to the attested enclave
3. **Ciphertext for storage** - KMS returns the same bytes encrypted under your KMS key
4. **No local key material** - Parent instance never sees plaintext

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Key Generation Flow                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   POST /generate_key ──▶ http_server ──vsock──▶ Enclave                     │
│                                                      │                       │
│                                                      ▼                       │
│                                          KMS GenerateDataKey                 │
│                                          (with attestation)                  │
│                                                      │                       │
│                                                      ▼                       │
│                                          ┌───────────────────┐              │
│                                          │ Returns:          │              │
│                                          │ • plaintext (32B) │──▶ enclave   │
│                                          │ • ciphertext      │──▶ storage   │
│                                          └───────────────────┘              │
│                                                      │                       │
│                                                      ▼                       │
│                                          Derive ETH address                  │
│                                          Delete plaintext                    │
│                                          Return { address, encrypted_key }   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Nitro Enclave Stack                                  │
│  ┌─────────────┐     ┌─────────────────────────────────────────────────┐   │
│  │  NLB        │────▶│              EC2 Parent Instance                 │   │
│  │ (internal)  │     │  ┌─────────────────────────────────────────┐    │   │
│  └─────────────┘     │  │           http_server (Docker)           │    │   │
│                      │  │  POST /generate_key                      │    │   │
│                      │  │  POST /sign_hash                         │    │   │
│                      │  │  GET  /health                            │    │   │
│                      │  └──────────────────┬──────────────────────┘    │   │
│                      │                     │ vsock                      │   │
│                      │  ┌──────────────────▼──────────────────────┐    │   │
│                      │  │         signing_server (Enclave)         │    │   │
│                      │  │  • generate_key: KMS GenerateDataKey     │    │   │
│                      │  │  • sign_*: KMS Decrypt + sign            │    │   │
│                      │  └─────────────────────────────────────────┘    │   │
│                      └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- AWS CLI configured with appropriate permissions
- Python 3.11 with pip
- A running container runtime for the image builds. CDK shells out to whatever `CDK_DOCKER`
  names, defaulting to `docker`; for [Finch](https://runfinch.com), set `CDK_DOCKER=finch`
  after `finch vm start`. Aliasing or symlinking `docker` is not supported by CDK — set the
  variable.
- Node.js 22 LTS and npm (for CDK)
- jq (for parsing outputs)

## Quick Start

Use the deployment script for automated setup:

```bash
./scripts/deploy-nitro-stack.sh dev us-east-1
```

`NITRO_STACK_PREFIX` separates the CloudFormation stack, default wallet namespace, and
TLS CA name from the deployment mode. This is required when two staging-mode signers share
an account/region:

```bash
NITRO_STACK_PREFIX=cleanroom- ./scripts/deploy-nitro-stack.sh staging us-east-1
```

This will:
1. Build the kmstool_enclave_cli
2. Deploy the CDK stack
3. Output the KMS policy template
4. Save configuration to `.nitro-config`

## Manual Deployment

### Step 1: Build KMS Tool

The enclave needs the KMS tool binary for cryptographic attestation:

```bash
cd nitro_enclave_signer
./scripts/build_kmstool_enclave_cli.sh
```

This builds the AWS Nitro Enclaves SDK KMS tool inside a Docker container.

### Step 2: Deploy CDK Stack

```bash
cd nitro_enclave_signer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export CDK_DEFAULT_REGION=us-east-1
export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
# app.py reads CDK_DEPLOY_* for the stack environment
export CDK_DEPLOY_REGION="$CDK_DEFAULT_REGION"
export CDK_DEPLOY_ACCOUNT="$CDK_DEFAULT_ACCOUNT"

# secretId = the one wallet the signer uses; generate the key under this name
npx cdk deploy devNitroWalletEth --context deployment=dev \
  --context secretId=nitro-wallet/dev
```

Note the outputs:
- `NLBDNS` - Network Load Balancer DNS name
- `EC2InstanceRoleARN` - For KMS key policy
- `KMSKeyID` - For key generation

### Step 3: Wait for Instance Initialization

The EC2 instances take 5-10 minutes to initialize:
- Pull Docker images from ECR
- Build the enclave EIF file
- Start the enclave and HTTP server

**Important**: The NLB is internal (deployed in private subnets). You cannot reach it from your local machine. Use SSM Session Manager to access EC2 instances for testing.

### Step 4: Get PCR0 Value

Connect to an EC2 instance via SSM:

```bash
# Get instance ID
INSTANCE_ID=$(aws autoscaling describe-auto-scaling-groups \
  --query "AutoScalingGroups[?contains(AutoScalingGroupName, 'devNit')].Instances[?LifecycleState=='InService'].InstanceId" \
  --output text | head -1)

# Connect via SSM
aws ssm start-session --target $INSTANCE_ID
```

Inside the instance:

```bash
nitro-cli describe-enclaves | jq -r '.[0].Measurements.PCR0'
```

### Step 5: Redeploy With the PCR0 Measurement

The KMS key policy is owned by CDK, so the measurement is a **deploy-time input** rather
than something applied out of band. Redeploy with the value from Step 4:

```bash
npx cdk deploy devNitroWalletEth --context deployment=dev --context pcr0=<PCR0_VALUE>
```

This makes CDK write two statements onto the key policy:

| Statement | Effect | Purpose |
|---|---|---|
| `DenyDecryptWithoutMatchingEnclaveAttestation` | `Deny` | Denies `kms:Decrypt`/`kms:GenerateDataKey` to **every** principal unless the request carries a matching attestation document |
| `AllowEnclaveAttestedDecrypt` | `Allow` | Permits those actions for the instance role **only** with an exactly matching `PCR0` |

The `Deny` is the control that matters. An `Allow` can only add authorization, never
subtract it, so a conditioned `Allow` on its own would sit alongside the default key-policy
delegation to the account root and enforce nothing. Do not apply the statement by hand with
`aws kms put-key-policy`: the next `cdk deploy` overwrites the policy, so a manual edit
silently reverts while appearing to have worked.

Until you supply `pcr0`, the `Deny` is unconditional and **no principal can decrypt**, so
signing and key generation fail closed. That is deliberate — an unmeasured deployment must
not be able to reach key material.

Then verify what is actually enforced:

```bash
./scripts/verify-kms-attestation.sh              # report the enforced measurement
./scripts/verify-kms-attestation.sh <PCR0_VALUE> # assert it matches a known value
```

This script only reads state; it exits non-zero if the `Deny` is missing or enforces a
different measurement. Settle it directly from the parent instance — this must fail:

```bash
aws kms decrypt --key-id <KMSKeyID> --ciphertext-blob fileb://<(printf 'x') 2>&1 | head -1
```

`AccessDenied` citing the explicit deny is the passing result. An
`InvalidCiphertextException` means the call was **authorized** and only the payload was
rejected — the parent can decrypt outside the enclave, and the boundary is not enforced.

> **Trust note:** `nitro-cli describe-enclaves` in Step 4 asks the *parent instance* — the
> component this architecture treats as untrusted — what it is running. Use it to notice a
> stale policy after a rebuild, not to establish trust. Derive the authoritative value from
> the EIF you built yourself: `nitro-cli describe-eif --eif-path <path>`.

**Important**: PCR0 changes when enclave code changes. If you modify files in
`nitro_enclave_signer/application/eth1/enclave/`, you must:
1. Rebuild and redeploy the stack (or trigger an ASG instance refresh)
2. Get the new PCR0 value
3. Redeploy with `--context pcr0=<new value>` — signing fails closed until you do

Note that `--context deployment=dev` enables `--debug-mode`, which **zeroes PCR0**. A
debug enclave therefore cannot satisfy an attestation condition; use `staging`/`prod` for
any deployment where the enclave boundary must hold.

### Step 6: Generate Signing Keys

Generate a new Ethereum key pair inside the enclave:

```bash
./scripts/generate-nitro-key.sh my-wallet-key
```

Or invoke the Lambda directly:

```bash
aws lambda invoke --function-name <NitroInvokeLambda> \
  --payload '{"operation":"generate_key","secret_name":"nitro-wallet/my-wallet-key"}' \
  --cli-binary-format raw-in-base64-out /dev/stdout
```

Response:
```json
{
  "address": "0xB58c0055bDAdFBBd20787360EF94ecdacFBEFc26",
  "secret_name": "nitro-wallet/my-wallet-key"
}
```

The Lambda stores the ciphertext in Secrets Manager itself, so there is no separate
`create-secret` step. It creates and never updates: if the name is taken, the call fails
rather than overwriting what may be a funded wallet's only encrypted key.

`secret_name` must sit under the `nitro-wallet/` prefix — that is the only namespace the
instance role can read.

> **`curl` will not work.** The signing service authenticates every request and has no
> unauthenticated mode. A caller must present a signed `sts:GetCallerIdentity` request,
> which the service replays to STS, and must appear in the deployed allowlist. Hand-rolling
> that proof with `curl` is not practical; the Lambda builds it (see
> `application/eth1/lambda/nitro_client_auth.py`). This is deliberate: anything that can
> reach port 443 and authenticate can obtain a signature over any hash it submits.

### Step 7: Fund the Wallet

Send ETH to the generated address for gas fees:

```bash
# Check balance
curl -s -X POST "https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0xYOUR_ADDRESS","latest"],"id":1}'
```

## Deploying TX Manager with Nitro

After the Nitro stack is deployed, deploy TX Manager stacks. The `deploy-chain.sh` script auto-sources `.nitro-config` for VPC ID, Nitro endpoint, and security group, and deploys only the per-chain stack (each chain owns its own DynamoDB nonce authority):

```bash
cd infra && npm install && cd ..

export SEPOLIA_RPC_URL="https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY"
export SEPOLIA_WS_URL="wss://eth-sepolia.g.alchemy.com/v2/YOUR_KEY"
export NITRO_SECRET_ID="my-wallet-key"

./scripts/deploy-chain.sh sepolia dev
```

**Critical**: The TX Manager Lambda must be in the same VPC as the Nitro NLB to reach it. This is automatic when using `deploy-chain.sh` with `.nitro-config`.

## VPC Configuration

The Nitro stack creates its own VPC by default. The `deploy-nitro-stack.sh` script saves the VPC ID to `.nitro-config` as `NITRO_VPC_ID`, and `deploy-chain.sh` auto-sources it — no manual VPC lookup needed.

**If `.nitro-config` is missing** (manual Nitro deployment):
```bash
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=*NitroWallet*" --query 'Vpcs[0].VpcId' --output text)
export VPC_ID
./scripts/deploy-chain.sh sepolia dev
```

**VPC Peering** (alternative): If TX Manager is in a different VPC, set up VPC peering and route tables.

## API Endpoints

Every endpoint below except `/health` requires authentication. Callers send an identity
proof alongside the request body, and the service rejects anything it cannot attribute to a
principal in its allowlist. See [Authentication](#authentication).

### POST /generate_key

Generate a new Ethereum key pair inside the enclave.

**Request:**
```json
{"key_id": "<KMS_KEY_ID>"}
```

**Response:**
```json
{
  "address": "0x...",
  "encrypted_key": "<base64-ciphertext>"
}
```

### POST /sign_hash

Sign a 32-byte hash. This is the **enclave's internal** endpoint, used by the Lambda only.

> **Note:** The Lambda also exposes a sign-hash operation via direct invocation (`lambda:InvokeFunction`). That operation supports three modes: raw hash, pre-computed EIP-712 hashes, and full EIP-712 typed data (types/primaryType/domain/message). The Lambda computes the final 32-byte hash and delegates to this enclave endpoint.

**Request:**
```json
{
  "hash": "0x...",
  "secret_id": "<secrets-manager-id>"
}
```

**Response:**
```json
{
  "signature": {
    "r": "0x...",
    "s": "0x...",
    "v": 27
  }
}
```

The `v` value is 27 or 28 (legacy format). TX Manager converts this to parity (0 or 1) for EIP-1559 transactions.

### GET /health

Health check endpoint. This is the only unauthenticated endpoint — the NLB has to reach it
to decide whether an instance is in service, and it reveals nothing but liveness.

**Response:**
```json
{"status": "healthy"}
```

## Authentication

The signing service returns a signature over whatever 32-byte hash a caller submits. Network
position alone is therefore not an acceptable control: anything that can open a connection
could otherwise sign arbitrary transactions. The service refuses to start without an
authentication mode and a non-empty allowlist.

Two modes are available, selected at deploy time with `--context authMode=`.

### SigV4 / IAM (default)

The caller signs an `sts:GetCallerIdentity` request and sends it as proof; the service
replays that request to STS, and STS returns the caller's identity. No AWS API can validate
a SigV4 signature on a third party's behalf, so this replay is what makes IAM identity
verifiable inside the service.

The proof is bound to the request body: the client signs a SHA-256 digest of the body as a
covered header, so a captured proof cannot be replayed against a different payload.

| Header | Contents |
|---|---|
| `X-Nitro-Auth-Authorization` | SigV4 `Authorization` header from the signed STS request |
| `X-Nitro-Auth-Date` | `X-Amz-Date` from that request |
| `X-Nitro-Auth-Token` | Session token, when the caller uses temporary credentials |
| `X-Nitro-Request-Digest` | SHA-256 hex digest of the request body |

The client half is `application/eth1/lambda/nitro_client_auth.py`; the verifying half is
`application/eth1/server/sigv4_auth.py`.

The invoking Lambda's execution role is added to the allowlist automatically. Use
`allowedPrincipals` for anything else that must sign — a break-glass role, a second service:

```bash
NITRO_ALLOWED_PRINCIPALS=arn:aws:iam::111122223333:role/BreakGlass \
  ./scripts/deploy-nitro-stack.sh prod us-east-1
```

#### The signing-client role (how TX Manager Lambdas authenticate)

TX Manager broadcast Lambdas are **not** added to the allowlist individually, and adding
them would be a two-pass deploy: you would deploy a chain, read its generated Lambda role
ARN, add it to `allowedPrincipals`, and redeploy the Nitro stack — repeated for every
chain, every time a role is replaced.

Instead the Nitro stack creates one stable, zero-permission role,
`NitroSigningClientRole`, and puts **its** ARN on the allowlist permanently. Each broadcast
Lambda is granted `sts:AssumeRole` on exactly that ARN and assumes it to obtain the
identity the service recognizes. The role holds no permission policies, so assuming it
grants only an allowlisted identity, never any AWS access; its trust is delegated to the
account root, so IAM (the per-Lambda grant), not the role, decides who may assume it.

The wiring is automatic: `deploy-nitro-stack.sh` writes the role ARN to `.nitro-config` as
`NITRO_AUTH_ROLE_ARN` (from the `SigningClientRoleArn` stack output), and `deploy-chain.sh`
passes it to the TX Manager stack, which sets it as the Lambda's `NITRO_AUTH_ROLE_ARN`
environment variable and adds the `sts:AssumeRole` grant. Onboarding a new chain never
requires touching the deployed signing service. If `NITRO_AUTH_ROLE_ARN` is absent, the
Lambda falls back to its own execution-role credentials — which is how the Nitro stack's
own invoke Lambda (key generation) and the local tests authenticate.

The stack adds an STS interface endpoint so this verification stays inside the VPC. Without
it, every signing request would depend on NAT egress, and a NAT failure would fail
authentication closed for all of them.

### mTLS

Most organizations deploying this already run a CA, and pinning client certificates avoids
the STS round trip entirely. This path is scaffolded: the service implements it
(`application/eth1/server/mtls_auth.py`), and the deploy plumbing accepts the CA bundle path
and client allowlist, but the CA bundle itself is operator-supplied.

```bash
NITRO_AUTH_MODE=mtls \
NITRO_ALLOWED_CLIENTS=tx-broadcast.internal,ops-breakglass.internal \
NITRO_CLIENT_CA_PATH=/etc/pki/tls/certs/client-ca.pem \
  ./scripts/deploy-nitro-stack.sh prod us-east-1
```

Place the bundle under `/etc/pki/tls/certs`, which the container already mounts. Allowlist
entries match the client certificate's CN or a DNS SAN. Both values are required in this
mode; the service will not start with only one.

A valid certificate from that CA is necessary but not sufficient — the CN or a DNS SAN must
also be in `allowedClients`, so issuing a cert does not by itself grant signing rights.

Revocation is off unless you ask for it. Add `NITRO_CLIENT_CRL_PATH` to enable CRL checking
across the chain:

```bash
NITRO_CLIENT_CRL_PATH=/etc/pki/tls/certs/client-ca.crl \
  ./scripts/deploy-nitro-stack.sh prod us-east-1
```

This fails closed by design: once enabled, a CRL that is missing or past its `nextUpdate`
rejects every client handshake. Keep it refreshed, or leave it unset and rely on removing
entries from `allowedClients` to revoke access.

### Which wallet gets used

`secretId` names the single wallet the service may sign with, and it is deliberately not
caller-supplied. The instance role can read every secret under `nitro-wallet/`, so a
caller-chosen id would let any authorized client sign with any other wallet in that
namespace.

## Multi-Chain Support

The Nitro signer is chain-agnostic—it signs 32-byte hashes. The chain ID is embedded in the transaction hash by the TX Manager. One Nitro stack serves all EVM chains; each chain owns its own DynamoDB nonce authority:

```
              Nitro Stack (signing)
                       │
         ┌─────────────┼─────────────┐
         │             │             │
    TX Manager    TX Manager    TX Manager
    Ethereum      Arbitrum      Base
    chainId=1     chainId=42161 chainId=8453
```

All chains use the same `NITRO_ENDPOINT`. Nonce state is isolated per chain because each chain has its own DynamoDB tracker table. Same Ethereum address/key works across all EVM chains.

## Managing Multiple Wallets

Each deployment of the signing service signs with exactly one wallet, named by `secretId` at
deploy time. Callers cannot select a wallet per request, and this is deliberate: the instance
role can read every secret under `nitro-wallet/`, so honouring a caller-supplied id would let
any authorized caller sign with any other wallet in that namespace. Separation between
wallets is a deployment boundary, not a request parameter.

To run more than one wallet, deploy the stack more than once:

```bash
./scripts/generate-nitro-key.sh treasury
./scripts/generate-nitro-key.sh operations

NITRO_SECRET_ID=nitro-wallet/treasury ./scripts/deploy-nitro-stack.sh treasury us-east-1
NITRO_SECRET_ID=nitro-wallet/operations ./scripts/deploy-nitro-stack.sh operations us-east-1
```

Each gets its own instances, NLB, allowlist, and KMS key, so a caller authorized for one
cannot reach the other. Point each TX Manager stack at the corresponding `nitroEndpoint`.

## Security Considerations

1. **PCR0 Validation**: An explicit `Deny` on the key policy blocks `kms:Decrypt` for every principal that cannot present an attestation document matching the deployed measurement — including the parent instance role. Redeploy with `--context pcr0=<new value>` whenever enclave code changes; signing fails closed until you do.

2. **Caller Authentication**: Every endpoint but `/health` requires an authenticated,
   allowlisted principal, and the service refuses to start without a mode and a non-empty
   allowlist — see [Authentication](#authentication). Network position is not a control here:
   the service signs whatever hash it is given, so anything that can both reach port 443 and
   authenticate can sign any transaction. Keep the allowlist to the callers that need it.

3. **VPC Isolation**: The NLB is internal (private subnets). Never expose it publicly.

4. **TLS and deployment CA**: `deploy-nitro-stack.sh` creates a deployment CA in
   Secrets Manager. Each replacement instance issues a leaf certificate with the internal
   NLB DNS name in its SAN, shreds the locally fetched CA key, and serves as a non-root
   process. `deploy-chain.sh` carries the public CA as base64 context and the chain stack injects
   the complete PEM into its Lambdas for hostname verification. The Nitro stack also injects
   that public PEM into its key-generation invoke Lambda; it is never granted the CA secret,
   which contains the private key. `NITRO_SKIP_TLS_VERIFY` is
   dev-only and rejected by prod-tagged chain deployments. Customers own CA-secret access,
   audit, rotation, and incident response.

5. **Secrets Manager Permissions**: EC2 instances need `secretsmanager:GetSecretValue` permission for the secrets they access.

6. **Wallet key replacement**: This is not transparent rotation. A new key creates a
   new on-chain address. Plan destination authorization changes and move funds deliberately;
   deploy/update the signer with the new fixed secret ID and repeat attestation/canary
   evidence before directing traffic to it.

## Troubleshooting

### KMS GenerateDataKey/Decrypt fails

- Check which measurement is enforced: `./scripts/verify-kms-attestation.sh`. If it reports
  no `Deny`, the boundary is not enforced at all; if it reports a different measurement than
  the enclave's, redeploy with `--context pcr0=<value>`
- An `AccessDenied` from *outside* the enclave is correct behavior, not a misconfiguration —
  the parent instance role holds no unconditional decrypt permission by design
- Debug mode (`--context deployment=dev`) zeroes PCR0, so a debug enclave can never satisfy
  the attestation condition

### Health check fails

```bash
# SSH to instance via SSM
aws ssm start-session --target <instance-id>

# Check http_server logs. The instance runs Docker regardless of the runtime you built
# the images with locally; user_data starts the container as `http_server`.
docker logs http_server

# Check enclave status
nitro-cli describe-enclaves
```

### Enclave console

```bash
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

### Lambda can't reach Nitro endpoint

- Verify Lambda is in the same VPC as Nitro NLB
- Check security groups allow traffic on port 443
- Verify NLB target group health checks are passing

### Secrets Manager AccessDeniedException

The EC2 instance role needs permission to read secrets:

```bash
# Check current permissions
aws iam get-role-policy --role-name <role-name> --policy-name SecretsManagerAccess

# Add permission if missing (via CDK or console)
```

### Nonce issues (transactions not appearing on-chain)

If transactions are accepted by RPC but don't appear on-chain:
- Check the nonce being used matches on-chain nonce
- The nonce manager auto-syncs if cached nonce is ahead of chain
- Force sync by redeploying Lambda (clears cached state)

### Instance refresh after code changes

If you change enclave code:

```bash
# Trigger instance refresh
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name <asg-name> \
  --preferences '{"MinHealthyPercentage": 50}'

# Monitor progress
aws autoscaling describe-instance-refreshes \
  --auto-scaling-group-name <asg-name>
```

## Teardown

`cdk destroy` removes the VPC, NLB, ASG, and Lambda, but **deliberately retains two
resources**: the KMS encryption key and the Secrets Manager secret CDK creates for the
stack. Both carry `RemovalPolicy.RETAIN`, which sets `DeletionPolicy` *and*
`UpdateReplacePolicy`, so neither a destroy nor a replacement-triggering update can delete
them.

That is not conservatism about cost — it is the only thing standing between a mistaken
`cdk destroy` and permanent loss of funds:

- A signing key exists in exactly two forms: plaintext inside a running enclave, and
  ciphertext in Secrets Manager. Nothing else holds it.
- The KMS key id is embedded in the ciphertext metadata, so there is no re-wrap or
  re-import path. Delete the KMS key and every ciphertext becomes permanently undecryptable.
- An undecryptable ciphertext means the wallet can never sign again, so any ETH or tokens
  at that address are unrecoverable. No AWS support path restores a deleted KMS key past
  its waiting period.

```bash
cd nitro_enclave_signer
npx cdk destroy devNitroWalletEth --context deployment=dev
```

After the stack is gone, the key and secret remain in the account, unmanaged. Leaving them
is the safe default and costs $1/month for the key.

### Deliberately deleting the retained resources

Only do this once you are certain no wallet encrypted under this key holds anything you
care about. **Drain the wallets first** — that is the step that is irreversible if skipped.

```bash
# 1. List every secret that may hold a wallet ciphertext for this key.
aws secretsmanager list-secrets \
  --query 'SecretList[?starts_with(Name, `nitro-wallet/`)].[Name,ARN]' --output table

# 2. For each wallet address, confirm on-chain balance is zero before going further.
#    (Addresses were printed by generate-nitro-key.sh; recover them from your records.)

# 3. Schedule the KMS key for deletion. 30 days is the maximum waiting period —
#    use it, not the 7-day minimum, so a mistake stays recoverable for as long as possible.
aws kms schedule-key-deletion --key-id <KMS_KEY_ID> --pending-window-in-days 30

# 4. Delete the secrets, also with the maximum recovery window.
aws secretsmanager delete-secret --secret-id <SECRET_ARN> --recovery-window-in-days 30
```

Cancel a mistake with `aws kms cancel-key-deletion --key-id <KMS_KEY_ID>` and
`aws secretsmanager restore-secret --secret-id <SECRET_ARN>`, but only within the waiting
window. After it elapses, the key material is destroyed and the wallets are gone.

## Environment Variables Reference

### TX Manager Lambda

| Variable | Description | Required |
|----------|-------------|----------|
| `NITRO_ENDPOINT` | NLB URL (https://...) | Yes |
| `NITRO_SECRET_ID` | Default Secrets Manager secret ID | Yes |
| `SIGNER_BACKEND` | Set to `nitro` | Yes |
| `CHAIN_ID` | EVM chain ID | Yes |
| `RPC_URL` or `ETH_RPC_URL` | Ethereum HTTP RPC (`ETH_RPC_URL` takes precedence) | Yes |
| `DYNAMODB_TABLE` | Transaction tracking table (per-chain nonce + lifecycle authority) | Yes |

### Nitro EC2 Instances

All of these are set by CDK from deploy-time context; the table is for reading a running
instance, not for editing by hand. Restarting the container with different values is reverted
by the next instance refresh.

| Variable | Description | Default |
|----------|-------------|---------|
| `REGION` | AWS region | us-east-1 |
| `SECRET_ID` | The one wallet this service may sign with. Not caller-supplied. | — (required) |
| `NITRO_AUTH_MODE` | `sigv4` or `mtls`. No unauthenticated mode exists. | sigv4 |
| `NITRO_ALLOWED_PRINCIPALS` | sigv4: permitted IAM ARNs, comma-separated or a JSON array | — (required in sigv4) |
| `NITRO_ALLOWED_CLIENTS` | mtls: permitted client cert CN / DNS SAN values | — (required in mtls) |
| `NITRO_CLIENT_CA_PATH` | mtls: CA bundle that may issue client certs | — (required in mtls) |
| `NITRO_CLIENT_CRL_PATH` | mtls: CRL. Set only if you keep it refreshed — see [mTLS](#mtls). | unset (no revocation checking) |
| `NITRO_SERVER_CERT_PATH` | Server cert+key, in `make-dummy-cert` combined form | /etc/pki/tls/certs/localhost.crt |

### Nitro Invoke Lambda

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_LEVEL` | Logging verbosity. `DEBUG` on `dev` deployments, `INFO` otherwise. | WARNING |
| `NITRO_INSTANCE_PRIVATE_DNS` | NLB DNS name | Set by CDK |
| `SECRET_ARN` | Secret holding the encrypted key | Set by CDK |
| `KEY_ARN` | KMS key used to encrypt it | Set by CDK |
