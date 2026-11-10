# Sample Deployment Guide

> [!IMPORTANT]
> This guide deploys an AWS sample/reference architecture for evaluation and adaptation.
> Completing it does not make a workload production-ready or transfer operational,
> security, custody, or compliance responsibility to AWS. Review
> [Known Limitations](known-limitations.md) before deciding whether to adapt this sample.

This guide walks through a testnet deployment of the EVM transaction-manager pattern. It
produces a working system that signs and broadcasts EIP-1559 transactions through Nitro
Enclaves; customers must adapt the topology and policy to their environment.

## What You're Building

The system consists of two layers:

1. **Nitro Enclave Stack** - Secure signing infrastructure where private keys never exist in plaintext outside an isolated enclave
2. **Per-chain TX Manager Stack(s)** - Transaction broadcasting infrastructure (Lambda, DynamoDB, ECS watcher, SQS). Each chain's DynamoDB table is the sole nonce and lifecycle authority for that chain.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Your Application                                │
│                         │                       │                            │
│            lambda:InvokeFunction          sqs:SendMessage                    │
│              (sync broadcast              (async broadcast,                  │
│               or sign-hash)                fire-and-forget)                  │
│                         │                       │                            │
│  ┌──────────────────────┼───────────────────────┼─────────────────────────┐│
│  │                      │  TX Manager Stack     │                         ││
│  │                      ▼                       ▼                         ││
│  │              ┌──────────────────┐    ┌──────────────┐                  ││
│  │              │ Lambda           │◀───│ SQS Queue    │                  ││
│  │              │ (broadcast +     │    │ + DLQ        │                  ││
│  │              │  sign-hash)      │    └──────────────┘                  ││
│  │              └────────┬─────────┘───────────▶ Ethereum RPC            ││
│  │                       │                                                ││
│  │          ┌────────────────────────┐    ┌──────────┐                  ││
│  │          │ DynamoDB              │    │ Nitro    │                  ││
│  │          │ (nonce + TX lifecycle)│    │ Endpoint │                  ││
│  │          └────────────────────────┘    └────┬─────┘                  ││
│  │                                    │                                   ││
│  └────────────────────────────────────┼───────────────────────────────────┘│
│                                       │                                     │
│  ┌────────────────────────────────────┼───────────────────────────────────┐│
│  │                  Nitro Enclave Stack                                    ││
│  │                                    ▼                                   ││
│  │    ┌─────────────┐    ┌──────────────────────────────┐                 ││
│  │    │     NLB     │───▶│ EC2 + Nitro Enclave          │                 ││
│  │    │ (internal)  │    │ (signs hashes, keys in HSM)  │                 ││
│  │    └─────────────┘    └──────────────────────────────┘                 ││
│  │                                                                         ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

This diagram uses the **direct internal AWS ingress** pattern. The repository deploys the
per-chain Lambda and SQS resources but does not create an API Gateway. For a centralized,
private multi-chain endpoint, add the optional private API Gateway and stateless router
described in [Ingress and Multi-Chain Routing Patterns](ingress-patterns.md). Both patterns
use the same per-chain stacks and isolation boundaries.

## Prerequisites

Before starting, ensure you have:

### Required Software

```bash
# Check Node.js (22 LTS required)
node --version  # Should show v22.x.x (see .nvmrc)

# Check npm
npm --version

# Check Python (3.11 required)
python3 --version

# Check AWS CLI
aws --version

# Check the container runtime (must be running)
docker info

# Check jq (JSON processor)
jq --version
```

If any are missing:

```bash
# macOS with Homebrew
brew install node python3 awscli docker jq

# Start Docker Desktop if not running
open -a Docker
```

CDK shells out to whatever `CDK_DOCKER` names, defaulting to `docker`, so any drop-in
replacement works. For [Finch](https://runfinch.com):

```bash
brew install finch   # asks for an admin password; it installs a .pkg
finch vm init        # first time only
finch vm start
export CDK_DOCKER=finch
```

Set the variable; CDK does not support aliasing or symlinking `docker`, and
`deploy-nitro-stack.sh` checks for the runtime `CDK_DOCKER` names.

### Cross-Architecture Build Support

The container images target `linux/arm64` (Graviton/ARM64 Lambda and ECS tasks). If you are building on an `x86_64` host, register QEMU emulation for `arm64` once per machine:

```bash
docker run --privileged --rm tonistiigi/binfmt --install arm64
```

(Substitute your runtime for `docker` here and in the commands below, e.g. `finch run`.)

This is not needed on native `arm64` build hosts (e.g., Apple Silicon, Graviton).

### AWS Configuration

```bash
# Configure AWS credentials
aws configure

# Verify you're authenticated
aws sts get-caller-identity
```

You should see output like:
```json
{
    "UserId": "AIDAEXAMPLEUSERID",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/your-username"
}
```

### Required AWS Permissions

Your IAM user/role needs permissions for:
- CloudFormation (create/update/delete stacks)
- EC2 (VPCs, security groups, instances)
- Lambda (create functions)
- DynamoDB (create tables)
- ECS (create clusters, services)
- KMS (create keys, manage policies)
- Secrets Manager (create/read secrets)
- IAM (create roles, policies)
- ECR (push images)
- SSM (session manager access)

Use a dedicated sandbox/deployment role and derive least-privilege permissions from the
reviewed CloudFormation change set. Do not attach `AdministratorAccess` to an application or
long-lived human role merely to follow this sample. Organization policies, permission
boundaries, and deployment-role design are customer responsibilities.

### Ethereum RPC Endpoints

You need HTTP and WebSocket RPC endpoints from any Sepolia RPC provider, for example:
- [Alchemy](https://www.alchemy.com/) (used in the examples below)
- [Infura](https://infura.io/)
- [QuickNode](https://www.quicknode.com/)

For this guide, we'll use Sepolia testnet. With Alchemy, after signing up:
1. Create a new app for "Ethereum" → "Sepolia"
2. Copy the HTTPS and WSS URLs

Example URLs (yours will be different):
```
HTTPS: https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY
WSS:   wss://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY
```

## Step 1: Clone and Setup Repository

```bash
# Clone the repository
git clone https://github.com/aws-samples/sample-blockchain-tx-manager.git
cd sample-blockchain-tx-manager

# Verify structure
ls -la
# Should show: infra/, nitro_enclave_signer/, nonce_manager/, tx_broadcast_lambda/, tx_watcher/, scripts/
```

## Step 2: Deploy Nitro Enclave Stack

The Nitro stack provides secure signing. Private keys are generated inside an isolated enclave and never exist in plaintext on the EC2 instance.

### 2.1 Deploy Using the Helper Script (Recommended)

The easiest way to deploy is using the provided script:

```bash
# From repository root. NITRO_SECRET_ID is the only wallet this signer uses (default
# nitro-wallet/<env>); §2.5 must generate the key under this same name.
NITRO_SECRET_ID=nitro-wallet/sepolia_treasury_key ./scripts/deploy-nitro-stack.sh dev us-east-1
```

To create another independently named signer while retaining an attested security mode,
set a unique prefix. For example, this creates `customerA-NitroWalletEth` in staging mode
instead of updating `stagingNitroWalletEth`:

```bash
NITRO_STACK_PREFIX=customerA- ./scripts/deploy-nitro-stack.sh staging us-east-1
```

The prefix also namespaces the default wallet secret and deployment CA. Use explicit
`NITRO_SECRET_ID` / `NITRO_TLS_CA_SECRET_NAME` when customer naming policy requires them.

The defaults deploy SigV4/IAM authentication with the stack's own Lambda as the only
allowlisted caller, signing with `nitro-wallet/<environment>`. Override with
`NITRO_SECRET_ID`, `NITRO_ALLOWED_PRINCIPALS`, or `NITRO_AUTH_MODE=mtls`; see
[Authentication](nitro-enclave-deployment.md#authentication) and the variable table in
[Quick Reference](#environment-variables).

Outside `dev`, this script and `deploy-chain.sh` prompt before IAM/security-group
widening, which needs a terminal; in CI, review `cdk diff` and set `CDK_REQUIRE_APPROVAL=never`.

**What this does:**
1. Builds the `kmstool_enclave_cli` if not present
2. Sets up Python virtual environment
3. Bootstraps CDK if needed
4. Deploys the Nitro CDK stack
5. Extracts and displays all outputs
6. Saves configuration to `.nitro-config`

**Expected output:**
```
==========================================
Nitro Enclave Stack Deployment
==========================================
Environment: dev
Region:      us-east-1
Auth mode:   sigv4
Wallet:      nitro-wallet/dev
Runtime:     docker
AWS Account: 123456789012

Step 1: Building kmstool_enclave_cli...
✓ KMS tool built

Step 2: Deploying Nitro CDK stack...
✓ CDK stack deployed

Step 3: Extracting stack outputs...
NLB Endpoint:  https://devNit-Nitro-xxx.elb.us-east-1.amazonaws.com
KMS Key ID:    12345678-1234-1234-1234-1234567890ab
EC2 Role ARN:  arn:aws:iam::123456789012:role/devNitroWalletEth-InstanceSSM...

...

Configuration saved to .nitro-config
```

### 2.2 Manual Deployment (Alternative)

If you prefer to deploy manually:

#### Build the KMS Tool

```bash
cd nitro_enclave_signer
./scripts/build_kmstool_enclave_cli.sh
```

**What this does:** Builds the AWS Nitro Enclaves SDK KMS tool inside a Docker container. This tool allows the enclave to make attested KMS calls.

**Expected output:** After ~5 minutes (~30 on Apple Silicon, which emulates amd64), you
should see the binary at:
```
application/eth1/enclave/kms/kmstool_enclave_cli
```

#### Setup Python Environment

```bash
# Still in nitro_enclave_signer/
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### Bootstrap CDK (First Time Only)

The Nitro CDK app reads `CDK_DEPLOY_ACCOUNT` / `CDK_DEPLOY_REGION` (see
`nitro_enclave_signer/app.py`), so set both pairs: the `CDK_DEFAULT_*` pair
for `cdk bootstrap` and the `CDK_DEPLOY_*` pair for subsequent `cdk deploy`:

```bash
export CDK_DEFAULT_REGION=us-east-1
export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
export CDK_DEPLOY_REGION="$CDK_DEFAULT_REGION"
export CDK_DEPLOY_ACCOUNT="$CDK_DEFAULT_ACCOUNT"
npx cdk bootstrap "aws://$CDK_DEFAULT_ACCOUNT/$CDK_DEFAULT_REGION"
```

#### Deploy the Stack

```bash
npx cdk deploy devNitroWalletEth \
  --context deployment=dev \
  --context authMode=sigv4 \
  --context secretId=nitro-wallet/sepolia_treasury_key
```

`secretId` names the one wallet this deployment may sign with. `authMode` defaults to
`sigv4`; there is no unauthenticated mode, and the app refuses to synthesize any other value.
Add `--context allowedPrincipals=<arn>[,<arn>]` for callers beyond the stack's own Lambda,
whose role is allowlisted automatically. TX Manager broadcast Lambdas do **not** go here:
they authenticate by assuming the stack's stable `SigningClientRoleArn` role (wired
automatically via `.nitro-config` → `NITRO_AUTH_ROLE_ARN`), so onboarding a chain needs no
Nitro-stack redeploy. Reserve `allowedPrincipals` for break-glass or non-Lambda callers.
For mTLS, see
[Authentication](nitro-enclave-deployment.md#authentication).

#### Server TLS (verified, no external CA)

The broadcast Lambda connects to the Nitro NLB over TLS and, in production, verifies it.
The NLB is TCP passthrough (it cannot hold an ACM cert) and instances are cattle behind an
ASG, so there is no single certificate to attach. Instead `deploy-nitro-stack.sh` creates a
small **deployment CA** once and stores it in Secrets Manager (`nitro-tls-ca/<env>`); each
instance, at boot, fetches the CA and issues its own server certificate whose SAN is the
NLB DNS name, then discards the CA private key. The CA *certificate* (public) is written to
`.nitro-config` as `NITRO_CA_CERT_B64`, and `deploy-chain.sh` passes it to the Lambda as
`NITRO_CA_CERT_PEM`. The Lambda trusts exactly that CA and validates the NLB hostname
against the SAN: real verification with no public CA and no per-host work.

This is automatic through the scripts. A **production** chain deploy against a Nitro
endpoint therefore fails closed unless it has the CA (or the forbidden-for-prod
`nitroSkipTlsVerify`): deploy the Nitro stack first so `.nitro-config` carries the CA.
`NITRO_SKIP_TLS_VERIFY=true` remains only for a dev signer still using the legacy
self-signed `CN=localhost` cert.

#### Create `.nitro-config`

The helper script (2.1) creates this file automatically. If you deployed manually, create it at the repository root so that `generate-nitro-key.sh` and `deploy-chain.sh` work. Populate it with values from your CloudFormation stack outputs and the NLB/VPC resources:

```
NITRO_ENDPOINT=https://<NLB DNS name>
NITRO_KMS_KEY_ID=<KMSKeyID stack output>
NITRO_EC2_ROLE_ARN=<EC2InstanceRoleARN stack output>
NITRO_AUTH_ROLE_ARN=<SigningClientRoleArn stack output>
NITRO_TLS_CA_SECRET_NAME=nitro-tls-ca/<env>
NITRO_CA_CERT_B64=<base64 of the CA cert PEM; deploy-nitro-stack.sh emits this>
NITRO_VPC_ID=<VPC ID of the NLB>
NITRO_SECURITY_GROUP_ID=<Nitro EC2 instance security group ID>
REGION=<region you deployed to>
STACK_NAME=<stack you deployed, e.g. devNitroWalletEth>
```

`NITRO_AUTH_ROLE_ARN` is the `SigningClientRoleArn` stack output, the stable
zero-permission role each broadcast Lambda assumes to authenticate. `deploy-chain.sh`
treats it as required whenever `NITRO_ENDPOINT` is set.

`generate-nitro-key.sh` reads `STACK_NAME` to find the signing Lambda; it defaults to
`devNitroWalletEth`, so set it explicitly for any other environment.

### 2.3 Wait for Instances to Initialize

The EC2 instances need 5-10 minutes to:
- Pull Docker images
- Build the enclave image
- Start the enclave and HTTP server

Check instance status:

```bash
# Get instance IDs (use the region from .nitro-config)
source .nitro-config
ASG_NAME=$(aws cloudformation describe-stacks --stack-name devNitroWalletEth \
  --region "$REGION" \
  --query 'Stacks[0].Outputs[?OutputKey==`ASGGroupName`].OutputValue' --output text)

aws autoscaling describe-auto-scaling-groups \
  --region "$REGION" \
  --auto-scaling-group-names "$ASG_NAME" \
  --query 'AutoScalingGroups[0].Instances[*].[InstanceId,LifecycleState]' \
  --output table
```

Wait until both instances show `InService`, then confirm the NLB targets are `healthy`:

```bash
TG_ARN=$(aws elbv2 describe-target-groups --region "$REGION" \
  --query "TargetGroups[?VpcId=='$NITRO_VPC_ID'].TargetGroupArn | [0]" --output text)
aws elbv2 describe-target-health --region "$REGION" --target-group-arn "$TG_ARN" \
  --query 'TargetHealthDescriptions[].[Target.Id,TargetHealth.State]' --output text
```

### 2.4 Enforce Enclave Attestation on the KMS Key

PCR0 is a cryptographic hash of the enclave image. Only a genuine enclave whose measurement
matches can produce an attestation document carrying it, which is what restricts decryption
of signing keys to the enclave rather than the parent instance.

The key policy is **owned by CDK**, so the measurement is a deploy-time input:

```bash
cd nitro_enclave_signer
npx cdk deploy devNitroWalletEth --context deployment=dev --context pcr0=<PCR0_VALUE>
```

For `deployment=dev` the only value the debug-mode enclave can attest is 96 zeros; see the
note at the end of this section. The EIF measurement below is what `staging` and `prod`
enforce.

Obtain the value from an EIF built from the enclave image CDK pushed. That is the authoritative
source, because it does not depend on trusting the instance (see
[runbook §1.5](finch-and-canary-runbook.md#15-measure-the-enclave-eif-and-pcr0)):

```bash
nitro-cli describe-eif --eif-path <path-to-eif> | jq -r '.Measurements.PCR0'
```

**What the deploy writes:**

1. `DenyDecryptWithoutMatchingEnclaveAttestation`: denies `kms:Decrypt` and
   `kms:GenerateDataKey` to **every** principal whose request does not carry a matching
   attestation document.
2. `AllowEnclaveAttestedDecrypt`: allows those actions for the EC2 instance role, but only
   with an exactly matching measurement.

Both are required, and **the `Deny` is the one that enforces anything.** KMS authorizes on
the union of identity and key policies, so an `Allow` can only add authorization, never
remove it: a conditioned `Allow` by itself would sit next to the default key-policy
delegation to the account root and change nothing. Correspondingly, the parent instance role
is granted **no** unconditional `kms:Decrypt`; the enclave premise depends on the parent
being unable to decrypt.

> Do **not** apply these statements with `aws kms put-key-policy`. CDK rewrites the policy on
> every deploy, so a manual edit reverts silently while appearing to have succeeded.

Omitting `--context pcr0` (as on the very first deploy, before an EIF exists) leaves the
`Deny` unconditional, so **nothing can decrypt** and signing and key generation fail closed.
That is the intended default: an unmeasured deployment must not reach key material.

**Verify what is actually enforced:**

```bash
./scripts/verify-kms-attestation.sh              # report the enforced measurement
./scripts/verify-kms-attestation.sh <PCR0_VALUE> # assert it matches an expected value
```

The script is read-only and exits non-zero if the `Deny` is absent or enforces a different
measurement. The decisive check is a negative one, run from the parent instance:

```bash
aws kms decrypt --key-id <KMSKeyID> --ciphertext-blob fileb://<(printf 'x') 2>&1 | head -1
```

- `AccessDenied` with an explicit-deny reference → **correct**, the boundary holds.
- `InvalidCiphertextException` → **failure**: the call was authorized and only the payload
  was rejected, so the parent can decrypt outside the enclave.

`--context deployment=dev` enables `--debug-mode`. A debug-mode enclave attests PCR0 as
96 zeros whatever image it runs, so the measured EIF value can never match in dev. The only
value dev can enforce is the all-zero one (`--context pcr0=000…0`, 96 zeros); CDK accepts it
for dev alone and warns, because it admits any debug enclave the parent starts. Dev therefore
exercises the signing path without an enclave-boundary guarantee. Use `staging` or `prod`
wherever the boundary must actually hold.

If you rebuild anything under `application/eth1/enclave/`, PCR0 changes and signing fails
closed until you redeploy with the new value.

### 2.5 Generate a Signing Key

Generate an Ethereum key pair using the helper script.

**Secret Naming Convention (recommended):**

Use a descriptive pattern like `{chain}_{purpose}_key` or `{chain}_{userid}_key_{last4}`:
- `sepolia_treasury_key`
- `sepolia_ops_key_6384`
- `base_sepolia_rewards_key`

The script prepends the `nitro-wallet/` prefix if you leave it off; the instance role only
grants `secretsmanager:GetSecretValue` under that prefix, so a secret stored outside it is
unreadable by the enclave. Beyond the prefix, the name is stored exactly as given; no
address suffix is appended. Append the address's last 4 characters yourself if you want it.

```bash
# From repository root. Must match the NITRO_SECRET_ID the Nitro stack was deployed with (§2.1).
./scripts/generate-nitro-key.sh sepolia_treasury_key
```

**What this does:**
1. Loads configuration from `.nitro-config` (created by deploy script)
2. Refuses to continue if the secret name is already taken, since it may hold the only copy of a
   funded wallet's key, and there is no rotate-in-place path
3. Invokes the signing service's Lambda, which authenticates to the enclave and calls
   `/generate_key`. The Lambda is the entry point because the service rejects unauthenticated
   callers; see [Authentication](nitro-enclave-deployment.md#authentication)
4. The enclave generates the key internally and returns it encrypted under the KMS key; the
   plaintext key never exists outside the enclave
5. The Lambda writes the ciphertext to Secrets Manager, so it never transits your machine

**Expected output:**
```
Generating key in Nitro Enclave...
Secret name: nitro-wallet/sepolia_treasury_key

Resolving the signing Lambda...
Invoking devNitroWalletEth-NitroInvokeLambda-abc123...

==========================================
Key Generated Successfully
==========================================

Address:     0xD764672D0bF0Cf30d2D3D665Bb5edd919Aa86384
Secret Name: nitro-wallet/sepolia_treasury_key
```

**Save the address!** You'll need to fund it with ETH, and nothing stores the mapping from
secret name to address; it cannot be recovered from the ciphertext outside the enclave.

### 2.6 Fund the Wallet

The generated address needs ETH for gas fees. For Sepolia testnet:

1. Go to a Sepolia faucet of your choice (most RPC providers run one, for example
   https://www.alchemy.com/faucets/ethereum-sepolia)
2. Enter your address (from step 2.5)
3. Request test ETH

Verify the balance:
```bash
curl -s -X POST "https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0xYOUR_ADDRESS","latest"],"id":1}' | jq -r '.result'
```

The result is in wei (hex). `0x2386f26fc10000` = 0.01 ETH.

### 2.7 Verify Configuration

The deploy script saves configuration to `.nitro-config`. Verify it exists:

```bash
cat .nitro-config
```

Should show (values are placeholders):
```
NITRO_ENDPOINT=https://devNit-Nitro-xxx.elb.us-east-1.amazonaws.com
NITRO_KMS_KEY_ID=12345678-1234-1234-1234-1234567890ab
NITRO_EC2_ROLE_ARN=arn:aws:iam::123456789012:role/devNitroWalletEth-InstanceSSM...
NITRO_AUTH_ROLE_ARN=arn:aws:iam::123456789012:role/devNitroWalletEth-NitroSigningClientRole...
NITRO_SECRET_ID=nitro-wallet/sepolia_treasury_key
NITRO_SKIP_TLS_VERIFY=false
NITRO_TLS_CA_SECRET_NAME=nitro-tls-ca/dev
NITRO_CA_CERT_B64=LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t...
NITRO_VPC_ID=vpc-0abc123def456
NITRO_SECURITY_GROUP_ID=sg-0abc123def456
REGION=us-east-1
STACK_NAME=devNitroWalletEth
```

## Step 3: Deploy TX Manager Stack

The TX Manager handles transaction broadcasting, nonce management, and confirmation tracking.

### 3.1 Understanding VPC Requirements (Critical)

**The TX Manager MUST be deployed in the same VPC as the Nitro stack.** This is because:

1. The Nitro NLB is **internal** (not internet-facing) - it only has private IP addresses
2. Lambda functions need VPC access to reach the NLB endpoint
3. The ECS watcher service also needs VPC access

If you deploy to a different VPC, Lambda will fail with connection timeouts when trying to reach the Nitro endpoint.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Same VPC (Required)                       │
│                                                                  │
│  ┌──────────────┐         ┌──────────────┐                      │
│  │ TX Manager   │         │ Nitro Stack  │                      │
│  │              │         │              │                      │
│  │ • Lambda     │────────▶│ • NLB        │                      │
│  │ • ECS        │ Private │   (internal) │                      │
│  │ • DynamoDB   │   IPs   │ • EC2+Enclave│                      │
│  └──────────────┘         └──────────────┘                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 VPC ID (Automatic)

The `deploy-chain.sh` script auto-sources `.nitro-config` which contains `NITRO_VPC_ID`. No manual lookup is needed. Verify it's set:

```bash
source .nitro-config
echo "VPC ID: $NITRO_VPC_ID"
```

If `.nitro-config` is missing (manual Nitro deployment), find the VPC manually:

```bash
VPC_ID=$(aws ec2 describe-vpcs \
  --region "$REGION" \
  --filters "Name=tag:aws:cloudformation:stack-name,Values=devNitroWalletEth" \
  --query 'Vpcs[0].VpcId' --output text)
export VPC_ID
```

### 3.3 Set Environment Variables

```bash
# Set RPC URLs (replace with your Alchemy URLs)
export SEPOLIA_RPC_URL="https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY"
export SEPOLIA_WS_URL="wss://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY"

# For dev environments, enable cleanup on stack deletion
export DESTROY_ON_REMOVAL=true
```

The `deploy-chain.sh` script automatically sources `.nitro-config` for `NITRO_ENDPOINT`,
`NITRO_VPC_ID`, `NITRO_SECURITY_GROUP_ID`, `NITRO_AUTH_ROLE_ARN`, `NITRO_CA_CERT_B64`, and
`NITRO_SECRET_ID`; these override exported values, so no need to export them.

#### Optional DynamoDB customer-managed encryption

DynamoDB is encrypted at rest by default with an AWS-owned key. If customer policy requires
control of the KMS key, choose one of these mutually exclusive modes:

```bash
# Existing customer CMK (customer owns key policy and lifecycle)
export DYNAMODB_KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789012:key/KEY_ID

# OR create a rotating CMK in this stack
export CREATE_DYNAMODB_KMS_KEY=true
```

With neither variable set, the table uses AWS-owned encryption. A customer CMK must remain
enabled and retained as long as the table/backups are needed. Test encryption-mode changes
on a disposable/testnet stack first.

### 3.4 Install Node Dependencies

```bash
cd infra
npm install
```

### 3.5 Deploy TX Manager

```bash
# Back to repository root
cd ..

# Deploy (takes 10-15 minutes)
./scripts/deploy-chain.sh sepolia dev
```

**What this does:**
- Auto-sources `.nitro-config` (VPC ID, Nitro endpoint, security group)
- Creates a per-chain DynamoDB table (sole nonce authority + transaction state tracking),
  using AWS-owned encryption by default or the selected customer CMK
- Creates Lambda function (for transaction broadcasting and hash signing)
- Creates ECS Fargate service (for confirmation watching)
- Creates SQS queues with DLQ (for async submission)

**Expected output:**
```
Outputs:
TxManager-Sepolia-Dev.BroadcastFunctionArn = arn:aws:lambda:us-east-1:123456789012:function:sepolia-dev-broadcast
TxManager-Sepolia-Dev.QueueUrl = https://sqs.us-east-1.amazonaws.com/123456789012/sepolia-dev-queue
...
```

### 3.6 Verify Deployment

```bash
# Get Lambda ARN and SQS Queue URL
LAMBDA_ARN=$(aws cloudformation describe-stacks --stack-name TxManager-Sepolia-Dev \
  --query 'Stacks[0].Outputs[?OutputKey==`BroadcastFunctionArn`].OutputValue' --output text)
QUEUE_URL=$(aws cloudformation describe-stacks --stack-name TxManager-Sepolia-Dev \
  --query 'Stacks[0].Outputs[?OutputKey==`QueueUrl`].OutputValue' --output text)

echo "Lambda ARN (sync): $LAMBDA_ARN"
echo "SQS Queue (async): $QUEUE_URL"
```

### 3.7 Choose the ingress pattern

The outputs above support the direct internal pattern immediately:

- trusted services call `sqs:SendMessage` for asynchronous broadcast;
- trusted services call `lambda:InvokeFunction` for synchronous broadcast or sign-hash.

If clients need one private endpoint across chains, deploy a separate private API Gateway
and stateless router with exact permissions to these queue and function outputs. Do not put
nonce, transaction, or wallet-key state in the router. See
[Ingress and Multi-Chain Routing Patterns](ingress-patterns.md) for the route contract,
IAM boundary, idempotency rules, and selection guidance.

## Step 4: Test the System

The commands below test the direct internal AWS pattern provisioned by the chain stack.

### 4.1 Send a Test Transaction

```bash
# Replace with your generated address
FROM_ADDRESS="0xD764672D0bF0Cf30d2D3D665Bb5edd919Aa86384"

# Sync broadcast via direct Lambda invocation. Direct invokes require a unique
# idempotencyKey; a request without one is rejected with INVALID_REQUEST.
aws lambda invoke \
  --function-name sepolia-dev-broadcast \
  --cli-binary-format raw-in-base64-out \
  --payload "{
    \"from\": \"$FROM_ADDRESS\",
    \"to\": \"$FROM_ADDRESS\",
    \"value\": \"1000000000000000\",
    \"chainId\": 11155111,
    \"idempotencyKey\": \"guide-test-$(date +%s)\"
  }" /dev/stdout | jq .
```

**Expected response:**
```json
{
  "success": true,
  "txHash": "0xabc123...",
  "nonce": 0,
  "retryable": false
}
```

**Async broadcast via SQS** (fire-and-forget, no response; `idempotencyKey` is optional
here and falls back to the SQS `messageId`):
```bash
aws sqs send-message \
  --queue-url "$QUEUE_URL" \
  --message-body "{
    \"from\": \"$FROM_ADDRESS\",
    \"to\": \"$FROM_ADDRESS\",
    \"value\": \"1000000000000000\"
  }"
```

### 4.2 Test EIP-712 Signing

Test sign-hash with EIP-712 typed data via direct Lambda invocation:

```bash
FROM_ADDRESS="0xD764672D0bF0Cf30d2D3D665Bb5edd919Aa86384"  # Replace with your address

aws lambda invoke \
  --function-name sepolia-dev-broadcast \
  --cli-binary-format raw-in-base64-out \
  --payload "{
    \"from\": \"$FROM_ADDRESS\",
    \"typedData\": {
      \"types\": {
        \"EIP712Domain\": [
          {\"name\": \"name\", \"type\": \"string\"},
          {\"name\": \"version\", \"type\": \"string\"},
          {\"name\": \"chainId\", \"type\": \"uint256\"},
          {\"name\": \"verifyingContract\", \"type\": \"address\"}
        ],
        \"Permit\": [
          {\"name\": \"owner\", \"type\": \"address\"},
          {\"name\": \"spender\", \"type\": \"address\"},
          {\"name\": \"value\", \"type\": \"uint256\"},
          {\"name\": \"nonce\", \"type\": \"uint256\"},
          {\"name\": \"deadline\", \"type\": \"uint256\"}
        ]
      },
      \"primaryType\": \"Permit\",
      \"domain\": {
        \"name\": \"TestToken\",
        \"version\": \"1\",
        \"chainId\": 11155111,
        \"verifyingContract\": \"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC\"
      },
      \"message\": {
        \"owner\": \"$FROM_ADDRESS\",
        \"spender\": \"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB\",
        \"value\": \"1000000000000000000\",
        \"nonce\": 0,
        \"deadline\": 1893456000
      }
    }
  }" \
  /dev/stdout
```

**Expected response:**
```json
{
  "success": true,
  "r": "0x...",
  "s": "0x...",
  "v": 27,
  "signature": "0x..."
}
```

This is a stateless operation: no nonce, reservation, or DynamoDB involved.

### 4.3 Verify Transaction On-Chain

Wait 15-30 seconds for the transaction to be mined, then:

```bash
TX_HASH="0xabc123..."  # From previous response

curl -s -X POST "$SEPOLIA_RPC_URL" \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$TX_HASH\"],\"id\":1}" | jq .
```

If `result` is not `null`, your transaction is on-chain!

### 4.4 Check Lambda Logs

```bash
aws logs tail /aws/lambda/sepolia-dev-broadcast --since 5m --format short
```

### 4.5 Check Watcher Logs

```bash
aws logs tail /ecs/sepolia-dev-watcher --since 5m --format short
```

## Step 5: Strict Profile and Multi-Stack Topologies (Illustrative)

> [!IMPORTANT]
> This step shows how the sample's strictest configuration profile and multi-chain,
> multi-wallet topologies work. It is illustrative, not an endorsement for production or
> mainnet use as-is. The sample is provided without warranty or support; see
> [Known Limitations](known-limitations.md) for the controls it does not provide.

### 5.1 Strict Configuration Profile (`environment=prod`)

The `prod` profile differs from dev in two enforced ways: the RPC endpoints (which embed
your provider API key) must come from Secrets Manager, and an alarm subscriber is
required. `deploy-chain.sh` and the CDK stack both refuse a `prod`-profile deploy without
them. The examples use testnets.

```bash
# One secret per chain. The services read it at startup; the URLs never enter the
# CloudFormation template or the Lambda/ECS environment.
aws secretsmanager create-secret \
  --name tx-manager/sepolia/rpc \
  --secret-string '{"rpcUrl":"https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY","wsRpcUrl":"wss://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY"}'

export RPC_SECRET_ARN="arn:aws:secretsmanager:us-east-1:123456789012:secret:tx-manager/sepolia/rpc-AbCdEf"
export ALARM_EMAIL="alerts@example.com"   # or ALARM_TOPIC_ARN=<existing SNS topic>
./scripts/deploy-chain.sh sepolia prod
```

Rotating the provider key is a Secrets Manager update followed by a restart of the
watcher task and a new Lambda version (both read the secret once at startup).

### 5.2 Multiple Chains

Deploy additional chains sharing the same Nitro signer. Each chain owns its own DynamoDB tracker table, so nonce state is isolated per chain; there is no shared nonce store. Each `deploy-chain.sh` run deploys only that chain's stack:

```bash
# Arbitrum Sepolia
export RPC_SECRET_ARN="arn:aws:secretsmanager:...:secret:tx-manager/arbitrum-sepolia/rpc-..."
./scripts/deploy-chain.sh arbitrum-sepolia prod

# Base Sepolia
export RPC_SECRET_ARN="arn:aws:secretsmanager:...:secret:tx-manager/base-sepolia/rpc-..."
./scripts/deploy-chain.sh base-sepolia prod
```

All chains use the same `NITRO_ENDPOINT` and `NITRO_SECRET_ID` (same address on all EVM chains).

### 5.3 Multiple Wallets

Generate additional keys for different purposes:

```bash
./scripts/generate-nitro-key.sh example-wallet-a
./scripts/generate-nitro-key.sh example-wallet-b
./scripts/generate-nitro-key.sh example-wallet-c
```

A wallet is chosen at deploy time, not per request. Each signing-service deployment signs with
the one wallet named by its `secretId`, and it ignores any wallet the client asks for. The
instance role can read every secret under `nitro-wallet/`, so a caller-supplied id would let
any authorized caller sign with any other wallet in that namespace.

So one signing stack per wallet:

```bash
NITRO_SECRET_ID=nitro-wallet/example-wallet-a \
  ./scripts/deploy-nitro-stack.sh wallet-a us-east-1
NITRO_SECRET_ID=nitro-wallet/example-wallet-b \
  ./scripts/deploy-nitro-stack.sh wallet-b us-east-1
```

Then point each per-chain TX Manager stack at the matching `NITRO_ENDPOINT`. This also keeps
the allowlists separate, so a caller authorized for wallet A cannot sign with wallet B.

### 5.4 Monitoring

The per-chain stack already creates the alarms (Lambda errors/duration/throttles, DLQ
depth, queue age, ECS task count, watcher block progress, DynamoDB throttles and system
errors) and an ECS health check that replaces a watcher that stops processing blocks.
What it cannot do is decide who gets paged. For the `prod` profile the deploy **fails**
unless you provide a subscriber:

```bash
# Per-stack topic with an email subscription (confirm the subscription email afterwards)
export ALARM_EMAIL=alerts@example.com
./scripts/deploy-chain.sh sepolia prod

# Or route every chain into an existing org topic (PagerDuty / Chatbot / OpsGenie)
export ALARM_TOPIC_ARN=arn:aws:sns:us-east-1:123456789012:platform-alerts
./scripts/deploy-chain.sh sepolia prod
```

Tune `watcherStallSecs` (default 300) if you run a chain whose block interval is
unusually long; it bounds both the health-check staleness and the progress alarm period.
See the [Monitoring](../README.md#monitoring) table for each alarm's threshold and
missing-data policy.

### 5.5 Security Hardening

1. **Choose and enforce the ingress boundary** - For multiple centrally governed clients,
   use the private API pattern; for direct internal access, grant exact per-chain queue and
   function ARNs. See [Ingress and Multi-Chain Routing Patterns](ingress-patterns.md).
2. **Restrict Lambda invocation** - Grant `lambda:InvokeFunction` only to known caller IAM principals using resource-based policies
3. **Enable VPC Flow Logs** - For network auditing
4. **Enable CloudTrail** - For API auditing
5. **Rotate KMS keys** - The stack enables automatic rotation
6. **Review IAM policies** - Use least-privilege

## Troubleshooting

### "AccessDeniedException" from Secrets Manager

The EC2 instance role needs permission to read your secret:

```bash
# Check current permissions
aws iam list-role-policies --role-name devNitroWalletEth-InstanceSSM...

# The CDK stack grants secretsmanager:GetSecretValue only on secrets named nitro-wallet/*.
# A secret outside that prefix is unreadable; regenerate it with generate-nitro-key.sh,
# which adds the prefix automatically.
```

### "KMS Decrypt failed"

1. Check which measurement the policy enforces, and whether it matches the enclave:
   ```bash
   ./scripts/verify-kms-attestation.sh
   ```
2. If you changed enclave code, PCR0 changed. Redeploy with the new value; this is a
   `cdk deploy`, not a policy edit, since CDK owns the key policy (see §2.4):
   ```bash
   npx cdk deploy devNitroWalletEth --context deployment=dev --context pcr0=<NEW_PCR0>
   ```

### Transaction accepted but not on-chain

The nonce might be wrong. Check Lambda logs:
```bash
aws logs tail /aws/lambda/sepolia-dev-broadcast --since 5m | grep -i nonce
```

Nothing is cached: the DynamoDB `nonce-state` row is the nonce authority, and its watermarks
are never rewound. If the transaction's nonce is ahead of the chain's pending nonce, a lower
nonce was reserved but never broadcast; the watcher's stale-reservation recovery finalizes or
recycles it (as a `gap#` row the next reservation fills), after which the queued transaction
can mine. If the chain is ahead of DynamoDB, `force_sync()` and the watcher raise the
watermarks on the next chain read. See [Nonce Manager: Key Behaviors](../nonce_manager/README.md#key-behaviors).
Redeploying the Lambda does not change nonce state.

### Can't connect to Nitro endpoint

The NLB is internal (private subnets). Lambda must be in the same VPC.

**Verify Lambda is in the correct VPC:**
```bash
# Get Lambda VPC
LAMBDA_VPC=$(aws lambda get-function-configuration --function-name sepolia-dev-broadcast \
  --query 'VpcConfig.VpcId' --output text)

# Get Nitro NLB VPC
NLB_ARN=$(aws elbv2 describe-load-balancers \
  --query "LoadBalancers[?contains(LoadBalancerName, 'devNit')].LoadBalancerArn" \
  --output text)
NLB_VPC=$(aws elbv2 describe-load-balancers \
  --load-balancer-arns "$NLB_ARN" \
  --query 'LoadBalancers[0].VpcId' --output text)

echo "Lambda VPC: $LAMBDA_VPC"
echo "NLB VPC:    $NLB_VPC"
```

**If they don't match:** You need to redeploy the TX Manager with the correct `VPC_ID`:
```bash
export VPC_ID="$NLB_VPC"
./scripts/deploy-chain.sh sepolia dev
```

**If Lambda has no VPC:** The stack wasn't deployed with VPC configuration. Redeploy with `VPC_ID` set.

### Enclave not running

SSH to instance and check:
```bash
aws ssm start-session --target $INSTANCE_ID

# Inside instance. The instance runs Docker regardless of the runtime you build with
# locally; user_data starts the container as `http_server`.
nitro-cli describe-enclaves
docker ps
docker logs http_server
```

## Quick Reference

### Helper Scripts

| Script | Description |
|--------|-------------|
| `./scripts/deploy-nitro-stack.sh [env] [region]` | Deploy Nitro stack, build KMS tool, save config |
| `./scripts/verify-kms-attestation.sh [pcr0]` | Read-only: report which PCR0 the KMS key policy enforces (optionally assert it matches) |
| `./scripts/generate-nitro-key.sh <name>` | Generate new Ethereum key in enclave |
| `./scripts/deploy-chain.sh <chain> <env>` | Deploy the per-chain TX Manager stack |

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `RPC_SECRET_ARN` | Secrets Manager secret `{"rpcUrl","wsRpcUrl"}` with the chain's endpoints. **Required for prod**; replaces the URL variables below | `arn:aws:secretsmanager:...:secret:tx-manager/ethereum/rpc-...` |
| `ALARM_EMAIL` / `ALARM_TOPIC_ARN` | Alarm subscriber. **One is required for prod** | `oncall@example.com` |
| `SEPOLIA_RPC_URL` | HTTP RPC for Sepolia (non-prod plaintext path) | `https://eth-sepolia.g.alchemy.com/v2/xxx` |
| `SEPOLIA_WS_URL` | WebSocket RPC for Sepolia (non-prod plaintext path) | `wss://eth-sepolia.g.alchemy.com/v2/xxx` |
| `VPC_ID` | VPC to deploy into | `vpc-0abc123...` |
| `NITRO_ENDPOINT` | Nitro NLB URL | `https://devNit-xxx.elb.us-east-1.amazonaws.com` |
| `NITRO_SECRET_ID` | Wallet the signing service signs with. Not caller-selectable. | `nitro-wallet/sepolia-treasury` |
| `NITRO_AUTH_MODE` | `sigv4` (default) or `mtls`. No unauthenticated mode. | `sigv4` |
| `NITRO_ALLOWED_PRINCIPALS` | Extra IAM roles allowed to request a signature. The invoking Lambda's role is added automatically. | `arn:aws:iam::111122223333:role/BreakGlass` |
| `NITRO_ALLOWED_CLIENTS` | mTLS only: permitted client cert CN / DNS SAN values | `tx-broadcast.internal` |
| `NITRO_CLIENT_CA_PATH` | mTLS only: CA bundle that may issue client certs | `/etc/pki/tls/certs/client-ca.pem` |
| `NITRO_CLIENT_CRL_PATH` | mTLS, optional: CRL. Enabling it makes a stale CRL reject every client. | `/etc/pki/tls/certs/client-ca.crl` |
| `CDK_ENCLAVE_PCR0` | Enclave measurement the KMS key policy requires for `kms:Decrypt` | `abc...123` (96 hex chars) |
| `CDK_DOCKER` | Container runtime CDK shells out to, if not `docker` | `finch` |

See [Authentication](nitro-enclave-deployment.md#authentication) for how the modes work and
which one to pick.

### Key Commands

```bash
# Deploy Nitro stack (recommended - does everything)
./scripts/deploy-nitro-stack.sh dev us-east-1

# Enforce a PCR0 measurement on the KMS key (CDK owns the key policy)
npx cdk deploy devNitroWalletEth --context deployment=dev --context pcr0=<PCR0>

# Check what the deployed policy actually enforces
./scripts/verify-kms-attestation.sh

# Generate a new signing key
./scripts/generate-nitro-key.sh my-key-name

# Deploy TX Manager
./scripts/deploy-chain.sh sepolia dev

# Send transaction (sync, via direct Lambda invocation)
aws lambda invoke --function-name sepolia-dev-broadcast \
  --cli-binary-format raw-in-base64-out \
  --payload '{"from":"0x...","to":"0x...","value":"1000000000000000","idempotencyKey":"unique-id-1"}' /dev/stdout

# Check logs
aws logs tail /aws/lambda/sepolia-dev-broadcast --since 5m
```

### Stack Outputs

After deployment, get all outputs:
```bash
# Nitro stack
aws cloudformation describe-stacks --stack-name devNitroWalletEth \
  --query 'Stacks[0].Outputs' --output table

# TX Manager stack
aws cloudformation describe-stacks --stack-name TxManager-Sepolia-Dev \
  --query 'Stacks[0].Outputs' --output table
```
