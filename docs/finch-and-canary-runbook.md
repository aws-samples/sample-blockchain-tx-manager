# Finch Build and End-to-End Canary Runbook

This runbook records the repeatable local Finch workflow and the full Sepolia canary used
to validate the deployed transaction manager. It complements the
[deployment guide](deployment-guide.md): use that guide to deploy Nitro and chain stacks;
use this runbook to prove the built images and the deployed system.

Passing this runbook is evidence for a reviewed sample revision, not certification that any
adaptation is production-ready. Anyone independently adapting the sample must define and run
its own validation for its account, topology, and use case.

## Safety and scope

- Run the canary only in an isolated, non-production stack with a dedicated testnet wallet.
- The funded tests submit four real Sepolia transactions and consume test ETH for gas.
- The recovery test deliberately stops the watcher and conditionally rewrites two canary
  DynamoDB rows. Never run it against a shared, staging, or production wallet/table.
- The parent-isolation test invokes KMS and SSM but must prove that the EC2 parent is denied
  `kms:Decrypt`; an `InvalidCiphertextException` is not sufficient evidence.
- Prefer verified TLS for the canary: deploy the Nitro stack with a deployment CA (the
  default of `deploy-nitro-stack.sh`), which puts `NITRO_CA_CERT_B64` in `.nitro-config`,
  and `deploy-chain.sh` pins it so the Lambda validates the NLB certificate. This exercises
  the deployment-CA TLS path for non-development configurations. `NITRO_SKIP_TLS_VERIFY=true` is only for a legacy dev
  signer still using the sample self-signed cert; non-development configurations reject it.
- Do not enable shell tracing (`set -x`) or print RPC secret values. Store build evidence
  outside the repository, for example under `~/.finch-artifacts/`.
- Stack deletion is intentionally not automated here. Review retained KMS keys, wallet
  secrets, and funded addresses before removing any canary infrastructure.
- Run the snippets in bash, not zsh (the macOS default): zsh does not word-split
  unquoted variables, so loops like `for instance in $PARENTS` fail.

## Mandatory AWS credential safety

Every live AWS command in this runbook **must** use short-lived, account-scoped credentials.
Static access keys, long-lived credentials, and a default identity whose account/role has
not been verified are prohibited. Use the customer's approved federation, SSO, or
temporary-role mechanism and scope each session to the bounded phase.

### Credential acquisition

The operator must use the organization's approved temporary-role mechanism. Do not run
`aws configure` with static keys for this procedure. Obtain a short-lived session for the
specific canary account and role, make it available to the standard AWS credential chain,
and verify its expiration is long enough for the next bounded phase. Use separate sessions
when practical:

- **Read-only preflight/evidence:** STS identity; CloudFormation, EC2, ECS, DynamoDB, logs,
  IAM, KMS-policy, and SSM command-status reads.
- **Build/deploy:** only the CloudFormation, CDK bootstrap asset S3/ECR, IAM pass/create,
  Lambda, ECS, DynamoDB, networking, Secrets Manager, KMS, and related actions needed for
  the named non-production stacks.
- **Canary mutation:** invoke the named canary Lambda; stop/update the named canary ECS
  service; read and conditionally transact only against the named canary table; send/read
  SSM commands only on the canary parent instances; `kms:Encrypt` only on the canary KMS
  key for boundary evidence; and read the named RPC secret and canary logs.

The operator session does not need `kms:Decrypt` for the parent-denial test. The operator
creates a valid ciphertext with `kms:Encrypt`; the EC2 parent role attempts and must be
denied `kms:Decrypt`.

### Mandatory identity and target guard

Set the expected account and region explicitly, then run this guard after every credential
refresh and before each deploy or fault-injection phase:

```bash
export EXPECTED_AWS_ACCOUNT='123456789012' # replace with the isolated canary account
export REGION=us-east-1
export AWS_REGION="$REGION"
export AWS_DEFAULT_REGION="$REGION"
export CDK_DEFAULT_REGION="$REGION"

CALLER_JSON=$(aws sts get-caller-identity --output json)
ACTUAL_AWS_ACCOUNT=$(jq -r .Account <<<"$CALLER_JSON")
CALLER_ARN=$(jq -r .Arn <<<"$CALLER_JSON")

[ "$ACTUAL_AWS_ACCOUNT" = "$EXPECTED_AWS_ACCOUNT" ] || {
  printf 'Refusing AWS operations: expected account %s, got %s (%s)\n' \
    "$EXPECTED_AWS_ACCOUNT" "$ACTUAL_AWS_ACCOUNT" "$CALLER_ARN" >&2
  exit 1
}

case "$CALLER_ARN" in
  *ReadOnly*|*ViewOnly*) echo "Verified read-only caller: $CALLER_ARN" ;;
  *) echo "Verified write-capable caller for the bounded canary phase: $CALLER_ARN" ;;
esac
```

Before any mutation, also require all target names to be explicitly canary-scoped:

```bash
: "${CANARY_STACK_NAME:?set the isolated canary stack name}"
: "${TABLE_NAME:?discover the isolated canary table}"
: "${ECS_CLUSTER:?discover the isolated canary cluster}"
: "${ECS_SERVICE:?discover the isolated canary service}"

for target in "$CANARY_STACK_NAME" "$TABLE_NAME" "$ECS_CLUSTER" "$ECS_SERVICE"; do
  case "$target" in
    *canary*|*Canary*) ;;
    *) echo "Refusing mutation: target is not canary-scoped: $target" >&2; exit 1 ;;
  esac
done
```

Credential and identity output may be retained as evidence only after removing session
tokens, access-key material, and credential-file paths. Never copy the credentials file,
RPC secret value, temporary ECR login, or environment dump into the artifact directory.
If credentials expire while the watcher is scaled to zero, obtain a new scoped session and
restore desired count to one before continuing any other work.

## 1. Finch build, test, and run procedure

Run all commands from the repository root unless a step says otherwise.

### 1.1 Install and start Finch on macOS

```bash
brew install finch       # first installation may request an administrator password
finch vm init            # first time only
finch vm start
finch info
export CDK_DOCKER=finch
```

Set `CDK_DOCKER` in every shell that runs CDK. Aliasing or symlinking `docker` does not
work because CDK launches the executable by name.

Both application images target `linux/arm64`. Apple Silicon runs them natively. On an
`x86_64` host, register ARM emulation once after starting the VM:

```bash
finch run --privileged --rm tonistiigi/binfmt --install arm64
```

The enclave and signing-server images target `linux/amd64`; on Apple Silicon the Finch
VM executes them via Rosetta, which the default `finch vm init` enables.

#### 1.1.1 Recovering Finch on a restricted macOS host

Some managed development hosts restrict `sudo` or prevent subprocesses from reading the
macOS keychain. These optional fallbacks were validated during the sample canary:

- **`finch vm start` dies starting `socket_vmnet`** (`fork/exec /usr/bin/sudo: operation
  not permitted`): the injected `finch-shared` bridged network needs root. Back up
  `/Applications/Finch/lima/data/_config/default.yaml`, replace its
  `networks: [ - lima: finch-shared ]` block with `networks: []`, and start again.
  User-mode (vz NAT) networking provides outbound internet, which is all builds, pulls,
  and pushes need. Restore the backup when returning to an unrestricted host.
- **`finch vm status` can report `Nonexistent` for an instance that exists.** Check with
  `LIMA_HOME=/Applications/Finch/lima/data /Applications/Finch/lima/bin/limactl list`;
  a `Stopped` instance starts fine with `limactl start finch`. Do not `finch vm init`
  over it (it refuses) or remove it (you lose the BuildKit cache that keeps enclave
  builds reproducible).
- **`finch push` fails with `no basic auth credentials` even after a successful
  `finch login`**: the login lands in the macOS keychain, which the push (running inside
  the VM as root) can never read. Write the ECR token where the VM-side pusher looks,
  then push from inside the VM:

  ```bash
  TOKEN=$(aws ecr get-login-password --region "$REGION")
  AUTH=$(printf 'AWS:%s' "$TOKEN" | base64 | tr -d '\n')
  LIMA_HOME=/Applications/Finch/lima/data /Applications/Finch/lima/bin/limactl shell finch -- \
    /bin/sh -c "sudo mkdir -p /root/.docker && printf '%s' \
    '{\"auths\":{\"ACCOUNT.dkr.ecr.REGION.amazonaws.com\":{\"auth\":\"$AUTH\"}}}' \
    | sudo tee /root/.docker/config.json >/dev/null && sudo chmod 600 /root/.docker/config.json"
  ```

  For CDK asset publishing, point `CDK_DOCKER` at a wrapper that delegates only `push`
  to the VM (everything else passes through to `finch`):

  ```bash
  # ~/.local/bin/finch-cdk
  #!/usr/bin/env bash
  set -euo pipefail
  if [ "${1:-}" = "push" ]; then
    shift
    exec env LIMA_HOME=/Applications/Finch/lima/data \
      /Applications/Finch/lima/bin/limactl shell finch -- \
      sudo nerdctl --namespace finch push "$@"
  fi
  exec finch "$@"
  ```

  ```bash
  export CDK_DOCKER="$HOME/.local/bin/finch-cdk"
  ```

  The ECR token expires after 12 hours: rewrite `/root/.docker/config.json` at the start
  of every session. If a CDK deploy failed **after** building assets, the built images
  are already tagged with their content-addressed asset tags in the VM
  (`sudo nerdctl --namespace finch images`); pushing those tags manually and re-running
  the deploy avoids a rebuild, because CDK skips publishing tags that already exist.

### 1.2 Run source tests before building images

The repository test runner does not need Finch. It uses a Java 17 DynamoDB Local JAR for
the nonce-manager integration tests.

```bash
# One-time local dependencies on macOS
brew install openjdk@17
brew install --cask dynamodb-local

# Rust formatting, strict clippy, unit tests, DynamoDB Local integration tests,
# and Nitro Python tests
./scripts/run-tests.sh all

# TypeScript compile, CDK assertions, and cdk-nag checks
(
  cd infra
  npm ci
  npm run build
  npm test
)
```

If the Nitro virtual environment does not exist, create it exactly as the test runner
instructs:

```bash
cd nitro_enclave_signer
python3 -m venv .venv
.venv/bin/pip install \
  -r requirements.txt \
  -r requirements-dev.txt \
  -r application/eth1/enclave/requirements.txt \
  -r application/eth1/lambda/requirements.txt \
  -r application/eth1/server/requirements.txt
cd ..
```

Success means every command exits zero. `scripts/run-tests.sh` prints `All tests passed`;
`npm test` completes both `nitro-auth.assert.ts` and `nag-check.ts`.

### 1.3 Build both deployable ARM images

The Docker build context is the repository root because each image also copies the shared
`nonce_manager` crate.

```bash
ARTIFACT_DIR="$HOME/.finch-artifacts/btm-$(git rev-parse --short HEAD)"
mkdir -p "$ARTIFACT_DIR"

finch build --platform linux/arm64 \
  -f tx_broadcast_lambda/Dockerfile \
  -t btm-broadcast:canary . \
  2>&1 | tee "$ARTIFACT_DIR/broadcast-build.log"

finch build --platform linux/arm64 \
  -f tx_watcher/Dockerfile \
  -t btm-watcher:canary . \
  2>&1 | tee "$ARTIFACT_DIR/watcher-build.log"

finch image inspect btm-broadcast:canary \
  --format '{{.Architecture}} {{.Id}} {{json .RepoDigests}}'
finch image inspect btm-watcher:canary \
  --format '{{.Architecture}} {{.Id}} {{json .RepoDigests}}'
```

Both inspections must report `arm64`. A successful source build is useful but is not a
substitute for the CDK asset build during `cdk synth`/`deploy`: CDK hashes the complete
asset context and deploys that exact hash.

### 1.4 Smoke-run the built image contents

These checks run the final image stages without contacting AWS. They prove that the
expected executables are present and that the watcher does not run as root.

```bash
finch run --rm --platform linux/arm64 \
  --entrypoint /bin/sh btm-broadcast:canary \
  -c 'test -x "${LAMBDA_RUNTIME_DIR}/bootstrap"'

finch run --rm --platform linux/arm64 \
  --entrypoint /bin/sh btm-watcher:canary \
  -c 'test -x /app/tx_watcher && test "$(id -u)" -ne 0'
```

A successful local business-flow run requires DynamoDB, HTTP/WebSocket RPC endpoints,
AWS credentials, and a reachable signer. Do not recreate that environment ad hoc in
Finch; use the isolated deployed canary below.

### 1.5 Measure the enclave (EIF and PCR0)

Any change to the enclave image (`server.py`, `requirements.txt`, the Dockerfile, its
base-image digest, or the kmstool artifacts) produces a new PCR0, and the Nitro stack
must be redeployed with it **before** anything can sign. Measure locally, on the pinned
builder, before deploying:

```bash
COMMIT=$(git rev-parse --short HEAD)   # measure a clean, committed tree only
ART="$HOME/.finch-artifacts/btm-enclave-$COMMIT"; mkdir -p "$ART"

# 1. Build the enclave image (amd64) from its own directory and save it.
(cd nitro_enclave_signer/application/eth1/enclave &&
  finch build --platform linux/amd64 -t btm-signing-enclave:$COMMIT .     2>&1 | tee "$ART/enclave-build.log")
finch save btm-signing-enclave:$COMMIT -o "$ART/enclave-image.tar"

# 2. Build the pinned Nitro CLI toolchain from its tracked Dockerfile. Exporting it
#    records the exact builder used and its checksum with the release evidence.
NITRO_CLI_BUILDER_TAR="$ART/nitro-cli-builder.tar" \
  ./scripts/build-nitro-cli-builder.sh

# 3. Measure inside that builder.
finch run --rm --privileged --platform linux/amd64 -v "$ART":/out   --entrypoint /bin/sh btm-nitro-cli:1.4.4 -c '
set -e; export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
dockerd --iptables=false --bridge=none >/tmp/dockerd.log 2>&1 &
for i in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker load -i /out/enclave-image.tar
nitro-cli build-enclave --docker-uri btm-signing-enclave:'$COMMIT'   --output-file /out/signing_server.eif > /out/build-measurements.json
cat /out/build-measurements.json'

# 4. Repeat the build-enclave step into a second EIF and require identical PCR0/1/2.
#    File digests may differ (EIF metadata embeds build time); measurements must not.
```

**Measure the image CDK deploys.** Instances build their EIF from the enclave image CDK
pushed, and the Dockerfile's `dnf --releasever=latest upgrade` means a separate rebuild can
yield a different PCR0. After `cdk deploy`, save the enclave `cdkasset-<hash>:latest` image
(`finch images | grep cdkasset-`) and measure that in step 3; it must equal the
parent-reported `nitro-cli describe-enclaves` value.

Record the PCR0, the source/input/image digests, builder tar checksum, RPM versions, and
image config ID in
`$ART/BUILD-EVIDENCE.md`, then pass the measurement to the deploy:
`CDK_ENCLAVE_PCR0=<pcr0> ./scripts/deploy-nitro-stack.sh staging us-east-1`.

Two constraints proven on live runs:

- **Resolve Python pins against the pinned base image first.** The enclave base is
  AL2023 (python3.9); a pin that resolves on your workstation may not exist for 3.9 and
  the build fails only inside the image. Resolve inside the exact base digest:
  `finch run --rm --platform linux/amd64 <base-digest> sh -c 'dnf install -qy python3-pip
  && pip3 install <pkgs> && pip3 freeze'`.
- **Any user_data or image-URI change rolls the ASG.** Expect ~8 minutes of instance
  initialization (image pull, on-instance EIF build, enclave + server start) after
  `UPDATE_COMPLETE`, and always verify against the *newest* instances (sort
  `describe-instances` by `LaunchTime`); the outgoing pair keeps serving while draining.

### 1.6 Use Finch for CDK synthesis and deployment

The deployment scripts honor `CDK_DOCKER` and are the normal path:

```bash
export CDK_DOCKER=finch

# Shared signer; follow the deployment guide's first-deploy/PCR0/redeploy sequence.
./scripts/deploy-nitro-stack.sh staging us-east-1

# Per-chain stack; see section 2 for canary-specific environment variables.
./scripts/deploy-chain.sh sepolia canary
```

For a reviewable assembly, direct CDK output outside the repository and run `cdk diff`
before deployment. Pass every context used by `deploy-chain.sh`; omitting contexts can
produce a different asset hash or stack. Section 2.2 shows the complete canary inputs.
Preserve the resulting `cdk.out`, diff, and image build logs under an artifact directory.

Do not hand-edit `cdk.out`, asset directories, or generated asset hashes. Re-synthesize
after any source, lockfile, Dockerfile, or context change.

## 2. End-to-end Sepolia canary

### 2.1 Acceptance criteria

A complete canary proves all of the following:

1. Both ARM images build and the reviewed CDK diff contains only intended changes.
2. Raw-hash signing succeeds through Lambda → assumed-role SigV4 → parent → enclave.
3. The parent cannot decrypt a valid ciphertext and an unauthenticated signing request
   receives HTTP 401.
4. Invalid chain, missing idempotency key, and incomplete fee-pair requests are rejected
   before any DynamoDB write.
5. ECS replaces a stopped watcher task while desired count remains one.
6. A funded transaction confirms; replaying its idempotency key returns the identical
   hash and nonce without another transaction.
7. A deliberately recreated `SIGNED` handoff recovers the exact stored bytes. The watcher
   advances only after the exact stored hash has a receipt.
8. Two concurrent submissions receive distinct consecutive nonces and both confirm.
9. Final chain and DynamoDB state agree: `next_nonce == confirmed_nonce == chain nonce`
   and `pending_count == 0`.
10. TLS is verified end to end: the broadcast Lambda carries `NITRO_CA_CERT_PEM` (a
    complete PEM) and no `NITRO_SKIP_TLS_VERIFY`; each parent presents a CA-issued cert
    whose SAN is the NLB DNS name; and `/health` returns 200 with `"enclave": "ok"`.
11. Observability is live: the watcher emits `TxManager/Watcher` `BlocksProcessed` EMF
    documents, every stack alarm (including the block-progress alarm) is `OK`, and the
    watcher logs contain no HTTP/WS endpoint or provider token.
12. `feeSpeed=slow` uses live fee history, is immediately admissible, stays under both
    immutable ceilings, creates a family row atomically, and confirms normally.
13. A controlled unbroadcast family is replaced dynamically at the same nonce: watcher
    claim -> internal queue -> separately permissioned replacement Lambda -> Nitro sign ->
    atomic generation activation -> confirmation. Duplicate queue delivery is a no-op.
14. Default `hold` rejects a cancel attempt without changing generation. After the winner
    crosses the +20-block reorg window, the family is `CONFIRMED`, losing siblings are
    terminal, and chain/next/confirmed/pending invariants still agree.

### 2.2 Prepare an isolated canary

Prerequisites:

- Short-lived, account-scoped credentials have been vended through the mandatory process
  above; `aws sts get-caller-identity` matches `EXPECTED_AWS_ACCOUNT`, and the session has
  only the permissions required for the current canary phase.
- An attested non-production Nitro stack is deployed with its PCR0 enforced.
- `.nitro-config` contains the signer VPC, NLB, security group, signing-client role, KMS
  key, region, and stack name.
- A dedicated wallet secret exists under `nitro-wallet/` and its address is recorded.
- The wallet has enough Sepolia ETH for at least four 21,000-gas self-transfers.
- The RPC secret contains both `rpcUrl` and `wsRpcUrl`. No script creates it:

  ```bash
  aws secretsmanager create-secret --region "$REGION" --name tx-manager/sepolia/canary-rpc \
    --secret-string '{"rpcUrl":"https://...","wsRpcUrl":"wss://..."}' --query ARN --output text
  ```
- Your AWS identity can invoke the canary Lambda and read the canary table. The boundary
  and fault tests additionally require SSM command, ECS stop/update, DynamoDB transaction,
  KMS encrypt, and log-read permissions on these isolated resources.

Sessions expire mid-run: the Rust asset builds plus a stack update can outlive a vended
session. That is safe (CDK assets are content-addressed, so re-running a deploy after
re-vending is cheap), but always re-run the identity guard after every re-vend, and if
credentials expire while the watcher is scaled to zero, restore desired count to one
before anything else.

Create a new wallet once; the script refuses to overwrite an existing secret. The Nitro
signer must be deployed with this same secret ID (`NITRO_SECRET_ID=nitro-wallet/sepolia-canary`)
so its server selects the canary wallet. It is safe for the first signer deployment to name
the not-yet-created secret; generate the key after that deployment and before signing:

```bash
./scripts/generate-nitro-key.sh sepolia-canary
```

Record the returned address and fund it from a Sepolia faucet. Then deploy the per-chain
stack with Finch:

```bash
export CDK_DOCKER=finch
export REGION=us-east-1
export AWS_REGION="$REGION"
export AWS_DEFAULT_REGION="$REGION"
export CDK_DEFAULT_REGION="$REGION"
export CANARY_STACK_NAME=TxManager-Sepolia-Canary
export STACK_NAME="$CANARY_STACK_NAME" # deploy-chain.sh input
export NITRO_SECRET_ID=sepolia-canary
export RPC_SECRET_ARN='arn:aws:secretsmanager:REGION:ACCOUNT:secret:tx-manager/sepolia/canary-rpc-...'
export DESTROY_ON_REMOVAL=true

# TLS: with a CA-backed Nitro stack (the default), deploy-chain.sh sources NITRO_CA_CERT_B64
# from .nitro-config and pins it automatically; nothing to set here, and the canary then
# validates TLS exactly as production does. Only a legacy self-signed dev signer needs:
#   export NITRO_SKIP_TLS_VERIFY=true
```

Do not use plaintext RPC contexts for a reusable canary. They are copied into synthesized
templates and task/function environment variables; use `RPC_SECRET_ARN` instead.

Before deploying, synthesize and review the exact canary assembly. Loading `.nitro-config`
also loads the Nitro stack's `STACK_NAME`, so restore the chain stack name afterward:

```bash
source .nitro-config
NITRO_STACK_NAME=$STACK_NAME
STACK_NAME=$CANARY_STACK_NAME

ARTIFACT_DIR="$HOME/.finch-artifacts/btm-canary-$(git rev-parse --short HEAD)"
mkdir -p "$ARTIFACT_DIR"

# Prefer the pinned deployment CA (verified TLS); fall back to skip only for a legacy
# self-signed dev signer.
TLS_CONTEXT=()
if [ "${NITRO_SKIP_TLS_VERIFY:-false}" = true ]; then
  TLS_CONTEXT=(--context nitroSkipTlsVerify=true)
elif [ -n "${NITRO_CA_CERT_B64:-}" ]; then
  # Keep the CA base64: `cdk --context` drops everything after the first newline.
  TLS_CONTEXT=(--context "nitroCaCertB64=$NITRO_CA_CERT_B64")
fi

(
  cd infra
  CDK_DOCKER=finch npx cdk synth "$CANARY_STACK_NAME" \
    --context stackName="$CANARY_STACK_NAME" \
    --context resourcePrefix=sepolia-canary \
    --context chainId=11155111 \
    --context rpcSecretArn="$RPC_SECRET_ARN" \
    --context requiredConfirmations=3 \
    --context environment=canary \
    --context destroyOnRemoval=true \
    --context vpcId="$NITRO_VPC_ID" \
    --context nitroEndpoint="$NITRO_ENDPOINT" \
    --context nitroSecretId=nitro-wallet/sepolia-canary \
    --context nitroSecurityGroupId="$NITRO_SECURITY_GROUP_ID" \
    --context nitroAuthRoleArn="$NITRO_AUTH_ROLE_ARN" \
    "${TLS_CONTEXT[@]}" \
    --output "$ARTIFACT_DIR/cdk.out"

  CDK_DOCKER=finch npx cdk diff "$CANARY_STACK_NAME" \
    --app "$ARTIFACT_DIR/cdk.out" --no-change-set --fail false \
    | tee "$ARTIFACT_DIR/cdk.diff"
)
```

Review the diff before running `deploy-chain.sh`. For a new canary stack the diff should be
additive and contain only the expected per-chain resources: one DynamoDB table, the
broadcast and replacement Lambdas, queues and DLQs, the ECS watcher, alarms, and their
least-privilege roles/security groups. The deploy script re-synthesizes from the same exported inputs and asks for
approval according to its environment policy. Re-run the identity guard, and because the
resources do not exist yet, apply the canary-name guard to the stack before deployment:

```bash
[ "$(aws sts get-caller-identity --query Account --output text)" = \
  "$EXPECTED_AWS_ACCOUNT" ]
case "$CANARY_STACK_NAME" in
  *canary*|*Canary*) ;;
  *) echo "Refusing deploy: stack is not canary-scoped: $CANARY_STACK_NAME" >&2; exit 1 ;;
esac

./scripts/deploy-chain.sh sepolia canary
```

### 2.3 Discover outputs and establish a baseline

```bash
export CANARY_WALLET='0xREPLACE_WITH_CANARY_ADDRESS'

OUTPUTS=$(aws cloudformation describe-stacks \
  --stack-name "$CANARY_STACK_NAME" --region "$REGION" \
  --query 'Stacks[0].Outputs[].{key:OutputKey,value:OutputValue}' --output json | \
  jq 'map({(.key): .value}) | add')

export LAMBDA_FUNCTION=$(jq -r .BroadcastFunctionArn <<<"$OUTPUTS")
export TABLE_NAME=$(jq -r .TxTrackerTableName <<<"$OUTPUTS")
export ECS_CLUSTER=$(jq -r .EcsClusterName <<<"$OUTPUTS")
export ECS_SERVICE=$(jq -r .WatcherServiceName <<<"$OUTPUTS")
export WALLET_LOWER=$(tr '[:upper:]' '[:lower:]' <<<"$CANARY_WALLET")

# Complete the target guard now that CloudFormation outputs exist.
for target in "$CANARY_STACK_NAME" "$TABLE_NAME" "$ECS_CLUSTER" "$ECS_SERVICE"; do
  case "$target" in
    *canary*|*Canary*) ;;
    *) echo "Refusing canary: target is not canary-scoped: $target" >&2; exit 1 ;;
  esac
done

printf 'lambda=%s\ntable=%s\ncluster=%s\nservice=%s\n' \
  "$LAMBDA_FUNCTION" "$TABLE_NAME" "$ECS_CLUSTER" "$ECS_SERVICE"

aws ecs wait services-stable \
  --cluster "$ECS_CLUSTER" --services "$ECS_SERVICE" --region "$REGION"

# Load the HTTP endpoint without printing it. Do not use set -x.
RPC_HTTP_URL=$(aws secretsmanager get-secret-value \
  --secret-id "$RPC_SECRET_ARN" --region "$REGION" \
  --query SecretString --output text | jq -r .rpcUrl)

rpc() {
  curl -fsS -X POST "$RPC_HTTP_URL" -H 'Content-Type: application/json' --data "$1"
}

BALANCE_HEX=$(rpc "$(jq -nc --arg a "$CANARY_WALLET" \
  '{jsonrpc:"2.0",method:"eth_getBalance",params:[$a,"latest"],id:1}')" | jq -er .result)
BASE_NONCE_HEX=$(rpc "$(jq -nc --arg a "$CANARY_WALLET" \
  '{jsonrpc:"2.0",method:"eth_getTransactionCount",params:[$a,"latest"],id:1}')" | jq -er .result)
export BASE_NONCE=$((BASE_NONCE_HEX))

python3 - "$BALANCE_HEX" "$BASE_NONCE" <<'PY'
import sys
balance = int(sys.argv[1], 16)
nonce = int(sys.argv[2])
print(f"balance_wei={balance} baseline_nonce={nonce}")
assert balance >= 10**16, "fund the canary with at least 0.01 Sepolia ETH"
PY
```

### 2.4 Verify signing and request boundaries

First prove the TLS wiring the signing will ride on. This catches truncated or missing
CA delivery *before* it presents as an opaque `SIGNER_ERROR` (a mangled inline CA fails
inside the Lambda's HTTP client builder, so every request errors identically):

```bash
ENVV=$(aws lambda get-function-configuration --function-name "$LAMBDA_FUNCTION"   --region "$REGION" --query 'Environment.Variables' --output json)
jq -e '(.NITRO_CA_CERT_PEM // "" | test("BEGIN CERTIFICATE")) and
       (.NITRO_CA_CERT_PEM // "" | test("END CERTIFICATE")) and
       (has("NITRO_SKIP_TLS_VERIFY") | not) and
       (has("RPC_SECRET_ARN")) and (has("RPC_URL") | not)' <<<"$ENVV" >/dev/null   && echo "TLS + RPC wiring OK"
```

A legacy skip-verify canary instead asserts `NITRO_SKIP_TLS_VERIFY == "true"` and no CA.

Invoke raw-hash signing twice and require identical deterministic output:

```bash
ARTIFACT_DIR="$HOME/.finch-artifacts/btm-live-canary-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$ARTIFACT_DIR"

SIGN_PAYLOAD=$(jq -nc --arg from "$CANARY_WALLET" \
  '{from:$from,hash:("0x" + ("ab" * 32))}')

for n in 1 2; do
  aws lambda invoke --function-name "$LAMBDA_FUNCTION" --region "$REGION" \
    --cli-binary-format raw-in-base64-out --payload "$SIGN_PAYLOAD" \
    "$ARTIFACT_DIR/sign-$n.json" >/dev/null
  jq -e '.success == true and (.signature | length) == 132 and
         (.r | length) == 66 and (.s | length) == 66 and
         (.v == 27 or .v == 28)' "$ARTIFACT_DIR/sign-$n.json" >/dev/null
done
cmp "$ARTIFACT_DIR/sign-1.json" "$ARTIFACT_DIR/sign-2.json"
```

Then prove malformed broadcasts do not touch DynamoDB:

```bash
COUNT_BEFORE=$(aws dynamodb scan --table-name "$TABLE_NAME" --region "$REGION" \
  --select COUNT --query Count --output text)

assert_invalid() {
  local name=$1 payload=$2 out="$ARTIFACT_DIR/$1.json"
  aws lambda invoke --function-name "$LAMBDA_FUNCTION" --region "$REGION" \
    --cli-binary-format raw-in-base64-out --payload "$payload" "$out" >/dev/null
  jq -e '.success == false and .errorCode == "INVALID_REQUEST" and
         .retryable == false' "$out" >/dev/null
  echo "$name: INVALID_REQUEST"
}

assert_invalid chain-mismatch "$(jq -nc --arg a "$CANARY_WALLET" \
  '{from:$a,to:$a,value:"0",chainId:1,idempotencyKey:"canary-invalid-chain"}')"
assert_invalid missing-idempotency "$(jq -nc --arg a "$CANARY_WALLET" \
  '{from:$a,to:$a,value:"0",chainId:11155111}')"
assert_invalid incomplete-fees "$(jq -nc --arg a "$CANARY_WALLET" \
  '{from:$a,to:$a,value:"0",chainId:11155111,
    idempotencyKey:"canary-incomplete-fees",maxFeePerGas:"1000000000"}')"

COUNT_AFTER=$(aws dynamodb scan --table-name "$TABLE_NAME" --region "$REGION" \
  --select COUNT --query Count --output text)
[ "$COUNT_AFTER" = "$COUNT_BEFORE" ]
```

### 2.5 Verify attestation and parent isolation

First confirm the deployed KMS policy enforces the expected PCR0:

```bash
./scripts/verify-kms-attestation.sh "${CDK_ENCLAVE_PCR0:?set expected PCR0}"
```

Test every running Nitro parent, not just one. Create a valid ciphertext as the operator,
then require each parent to receive HTTP 401 without SigV4 and `AccessDeniedException`
when decrypting that valid ciphertext:

The synthesis step saved the Nitro stack name and loaded the Nitro KMS key ID from
`.nitro-config`. If this is a new shell, repeat that setup without losing the chain stack
name:

```bash
if [ -z "${NITRO_STACK_NAME:-}" ] || [ -z "${NITRO_KMS_KEY_ID:-}" ]; then
  CANARY_STACK_NAME=${CANARY_STACK_NAME:-TxManager-Sepolia-Canary}
  source .nitro-config
  NITRO_STACK_NAME=$STACK_NAME
  STACK_NAME=$CANARY_STACK_NAME
fi

PARENTS=$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:aws:cloudformation:stack-name,Values=$NITRO_STACK_NAME" \
            'Name=instance-state-name,Values=running' \
  --query 'Reservations[].Instances[].InstanceId' --output text)
[ -n "$PARENTS" ]

CIPHER_B64=$(printf '%s' 'canary-parent-boundary' | \
  aws kms encrypt --region "$REGION" --key-id "$NITRO_KMS_KEY_ID" \
    --plaintext fileb:///dev/stdin --query CiphertextBlob --output text)
# The SAN each parent's cert must carry (from .nitro-config's NITRO_ENDPOINT).
NLB_SAN=${NITRO_ENDPOINT#https://}
export CDK_ENCLAVE_PCR0 NLB_SAN

for instance in $PARENTS; do
  REMOTE=$(cat <<EOF
set -euo pipefail
HTTP=\$(curl -sk -o /tmp/unauth-body -w '%{http_code}' \
  -X POST https://127.0.0.1/sign_hash \
  -H 'Content-Type: application/json' \
  --data '{"hash":"0xabababababababababababababababababababababababababababababababab"}')
[ "\$HTTP" = 401 ]
printf '%s' '$CIPHER_B64' | base64 -d >/tmp/canary-ciphertext
set +e
OUT=\$(aws kms decrypt --region '$REGION' --key-id '$NITRO_KMS_KEY_ID' \
  --ciphertext-blob fileb:///tmp/canary-ciphertext 2>&1)
RC=\$?
set -e
[ \$RC -ne 0 ]
echo "\$OUT" | grep -q AccessDeniedException
! echo "\$OUT" | grep -q InvalidCiphertextException
nitro-cli describe-enclaves | jq -e \
  ".[0].State == \"RUNNING\" and .[0].Measurements.PCR0 == \"$CDK_ENCLAVE_PCR0\"" >/dev/null
H=\$(curl -sk -o /tmp/h.json -w '%{http_code}' --max-time 20 https://127.0.0.1/health)
[ "\$H" = 200 ] && grep -q '"enclave": "ok"' /tmp/h.json
# Capture the handshake before parsing: piping s_client straight into x509 races under
# pipefail (x509 exits after the certificate while s_client is still writing → SIGPIPE).
echo | openssl s_client -connect 127.0.0.1:443 >/tmp/server-handshake 2>/dev/null
openssl x509 -in /tmp/server-handshake -noout -ext subjectAltName | grep -q "$NLB_SAN"
echo PARENT_ISOLATION_OK
EOF
)
  PARAMS=$(jq -nc --arg command "$REMOTE" '{commands:[$command]}')
  COMMAND_ID=$(aws ssm send-command --region "$REGION" \
    --instance-ids "$instance" --document-name AWS-RunShellScript \
    --parameters "$PARAMS" --query 'Command.CommandId' --output text)
  aws ssm wait command-executed --region "$REGION" \
    --command-id "$COMMAND_ID" --instance-id "$instance"
  aws ssm get-command-invocation --region "$REGION" \
    --command-id "$COMMAND_ID" --instance-id "$instance" \
    --query '{Status:Status,Output:StandardOutputContent,Error:StandardErrorContent}' \
    --output json | tee "$ARTIFACT_DIR/parent-$instance.json"
done
```

Every invocation must be `Success` and contain `PARENT_ISOLATION_OK`.

### 2.6 Verify watcher self-healing

Stopping an individual task is safe only because the canary ECS service retains desired
count one. Do not change the desired count for this check.

```bash
OLD_TASK=$(aws ecs list-tasks --cluster "$ECS_CLUSTER" \
  --service-name "$ECS_SERVICE" --desired-status RUNNING --region "$REGION" \
  --query 'taskArns[0]' --output text)
[ -n "$OLD_TASK" ] && [ "$OLD_TASK" != None ]

aws ecs stop-task --cluster "$ECS_CLUSTER" --task "$OLD_TASK" \
  --reason 'Canary: verify watcher replacement' --region "$REGION" >/dev/null

NEW_TASK=''
for _ in $(seq 1 60); do
  for task in $(aws ecs list-tasks --cluster "$ECS_CLUSTER" \
    --service-name "$ECS_SERVICE" --desired-status RUNNING --region "$REGION" \
    --query taskArns --output text); do
    [ "$task" != "$OLD_TASK" ] && NEW_TASK=$task
  done
  [ -n "$NEW_TASK" ] && break
  sleep 10
done

[ -n "$NEW_TASK" ] && [ "$NEW_TASK" != "$OLD_TASK" ]
aws ecs wait services-stable --cluster "$ECS_CLUSTER" \
  --services "$ECS_SERVICE" --region "$REGION"
aws ecs describe-services --cluster "$ECS_CLUSTER" --services "$ECS_SERVICE" \
  --region "$REGION" --query 'services[0].[desiredCount,runningCount,pendingCount]'
```

The final counts must be `[1, 1, 0]`.

### 2.7 Submit and confirm an idempotent transaction

Use a unique key for each canary run. A zero-value self-transfer limits the cost to gas.

```bash
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
TX1_PAYLOAD=$(jq -nc --arg a "$CANARY_WALLET" --arg key "canary-$RUN_ID-tx1" \
  '{from:$a,to:$a,value:"0",chainId:11155111,gasLimit:21000,idempotencyKey:$key}')

aws lambda invoke --function-name "$LAMBDA_FUNCTION" --region "$REGION" \
  --cli-binary-format raw-in-base64-out --payload "$TX1_PAYLOAD" \
  "$ARTIFACT_DIR/tx1.json" >/dev/null
jq -e --argjson nonce "$BASE_NONCE" \
  '.success == true and .nonce == $nonce and (.txHash | length) == 66' \
  "$ARTIFACT_DIR/tx1.json" >/dev/null

aws lambda invoke --function-name "$LAMBDA_FUNCTION" --region "$REGION" \
  --cli-binary-format raw-in-base64-out --payload "$TX1_PAYLOAD" \
  "$ARTIFACT_DIR/tx1-duplicate.json" >/dev/null
cmp "$ARTIFACT_DIR/tx1.json" "$ARTIFACT_DIR/tx1-duplicate.json"

TX1_HASH=$(jq -r '.txHash | ascii_downcase' "$ARTIFACT_DIR/tx1.json")
for _ in $(seq 1 60); do
  TX1_STATUS=$(aws dynamodb get-item --table-name "$TABLE_NAME" --region "$REGION" \
    --consistent-read \
    --key "{\"wallet\":{\"S\":\"$WALLET_LOWER\"},\"tx_hash\":{\"S\":\"$TX1_HASH\"}}" \
    --query 'Item.status.S' --output text)
  [ "$TX1_STATUS" = CONFIRMED ] && break
  sleep 10
done
[ "$TX1_STATUS" = CONFIRMED ]
```

### 2.8 Fault-inject exact-byte `SIGNED` recovery

This is the destructive portion of the canary. It scales only the isolated watcher to
zero, submits one transaction, waits for the exact hash to mine, and conditionally changes
its tracker/reservation handoff from `PENDING/BROADCAST` back to `SIGNED/SIGNED`. Restarting
the watcher must rebroadcast the stored bytes, observe `nonce too low`, find a receipt for
the exact stored hash, and finalize it. The conditional transaction prevents overwriting
an unexpected state.

```bash
restore_watcher() {
  aws ecs update-service --cluster "$ECS_CLUSTER" --service "$ECS_SERVICE" \
    --desired-count 1 --region "$REGION" >/dev/null || true
}
trap restore_watcher EXIT INT TERM

aws ecs update-service --cluster "$ECS_CLUSTER" --service "$ECS_SERVICE" \
  --desired-count 0 --region "$REGION" >/dev/null
aws ecs wait services-stable --cluster "$ECS_CLUSTER" \
  --services "$ECS_SERVICE" --region "$REGION"

TX2_PAYLOAD=$(jq -nc --arg a "$CANARY_WALLET" --arg key "canary-$RUN_ID-recovery" \
  '{from:$a,to:$a,value:"0",chainId:11155111,gasLimit:21000,idempotencyKey:$key}')
aws lambda invoke --function-name "$LAMBDA_FUNCTION" --region "$REGION" \
  --cli-binary-format raw-in-base64-out --payload "$TX2_PAYLOAD" \
  "$ARTIFACT_DIR/tx2.json" >/dev/null

TX2_HASH=$(jq -er '.txHash | ascii_downcase' "$ARTIFACT_DIR/tx2.json")
TX2_NONCE=$(jq -er .nonce "$ARTIFACT_DIR/tx2.json")
[ "$TX2_NONCE" -eq $((BASE_NONCE + 1)) ]
RESERVATION_SK=$(printf 'reservation#%020d' "$TX2_NONCE")

aws dynamodb get-item --table-name "$TABLE_NAME" --region "$REGION" \
  --consistent-read \
  --key "{\"wallet\":{\"S\":\"$WALLET_LOWER\"},\"tx_hash\":{\"S\":\"$TX2_HASH\"}}" \
  > "$ARTIFACT_DIR/tx2-before.json"
RAW_BEFORE=$(jq -er '.Item.signed_raw_tx.S' "$ARTIFACT_DIR/tx2-before.json")
[ "$(jq -r '.Item.status.S' "$ARTIFACT_DIR/tx2-before.json")" = PENDING ]

# Wait until the exact hash has an on-chain receipt while the watcher is stopped.
for _ in $(seq 1 60); do
  RECEIPT=$(rpc "$(jq -nc --arg h "$TX2_HASH" \
    '{jsonrpc:"2.0",method:"eth_getTransactionReceipt",params:[$h],id:1}')")
  [ "$(jq -r '.result != null' <<<"$RECEIPT")" = true ] && break
  sleep 10
done
jq -e '.result != null and .result.status == "0x1"' <<<"$RECEIPT" >/dev/null

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -n --arg table "$TABLE_NAME" --arg wallet "$WALLET_LOWER" \
  --arg hash "$TX2_HASH" --arg reservation "$RESERVATION_SK" --arg now "$NOW" '
  [
    {Update:{TableName:$table,
      Key:{wallet:{S:$wallet},tx_hash:{S:$hash}},
      UpdateExpression:"SET #s = :signed, updated_at = :now",
      ConditionExpression:"#s = :pending",
      ExpressionAttributeNames:{"#s":"status"},
      ExpressionAttributeValues:{":signed":{S:"SIGNED"},":pending":{S:"PENDING"},":now":{S:$now}}}},
    {Update:{TableName:$table,
      Key:{wallet:{S:$wallet},tx_hash:{S:$reservation}},
      UpdateExpression:"SET #s = :signed, updated_at = :now",
      ConditionExpression:"#s = :broadcast",
      ExpressionAttributeNames:{"#s":"state"},
      ExpressionAttributeValues:{":signed":{S:"SIGNED"},":broadcast":{S:"BROADCAST"},":now":{S:$now}}}}
  ]' > "$ARTIFACT_DIR/recovery-injection.json"

aws dynamodb transact-write-items --region "$REGION" \
  --transact-items "file://$ARTIFACT_DIR/recovery-injection.json"

restore_watcher
trap - EXIT INT TERM
aws ecs wait services-stable --cluster "$ECS_CLUSTER" \
  --services "$ECS_SERVICE" --region "$REGION"

for _ in $(seq 1 60); do
  TX2_ITEM=$(aws dynamodb get-item --table-name "$TABLE_NAME" --region "$REGION" \
    --consistent-read \
    --key "{\"wallet\":{\"S\":\"$WALLET_LOWER\"},\"tx_hash\":{\"S\":\"$TX2_HASH\"}}")
  [ "$(jq -r '.Item.status.S // ""' <<<"$TX2_ITEM")" = CONFIRMED ] && break
  sleep 10
done

[ "$(jq -r '.Item.status.S' <<<"$TX2_ITEM")" = CONFIRMED ]
[ "$(jq -r '.Item.signed_raw_tx.S' <<<"$TX2_ITEM")" = "$RAW_BEFORE" ]
[ "$(jq -r '.Item.nonce.N' <<<"$TX2_ITEM")" -eq "$TX2_NONCE" ]
[ "$(jq -r '.Item.confirmations.N' <<<"$TX2_ITEM")" -ge 3 ]
jq -e '.Item.ttl.N != null' <<<"$TX2_ITEM" >/dev/null
```

Confirm the watcher logs contain the exact-hash recovery path and contain no RPC URL:

```bash
aws logs tail "/ecs/${ECS_SERVICE}" --since 15m --region "$REGION" \
  | tee "$ARTIFACT_DIR/watcher-recovery.log"
grep -E 'nonce already consumed by the expected transaction|marked PENDING' \
  "$ARTIFACT_DIR/watcher-recovery.log"
# Progress metrics must be flowing (one EMF document per processed block), and no
# endpoint or provider token may appear anywhere in the log.
grep -q '"BlocksProcessed":1' "$ARTIFACT_DIR/watcher-recovery.log"
! grep -E 'https?://|wss?://' "$ARTIFACT_DIR/watcher-recovery.log"
```

### 2.9 Submit two concurrent transactions

```bash
for n in 3 4; do
  jq -nc --arg a "$CANARY_WALLET" --arg key "canary-$RUN_ID-tx$n" \
    '{from:$a,to:$a,value:"0",chainId:11155111,gasLimit:21000,idempotencyKey:$key}' \
    > "$ARTIFACT_DIR/tx$n-payload.json"
done

aws lambda invoke --function-name "$LAMBDA_FUNCTION" --region "$REGION" \
  --cli-binary-format raw-in-base64-out \
  --payload "fileb://$ARTIFACT_DIR/tx3-payload.json" \
  "$ARTIFACT_DIR/tx3.json" >/dev/null & PID3=$!
aws lambda invoke --function-name "$LAMBDA_FUNCTION" --region "$REGION" \
  --cli-binary-format raw-in-base64-out \
  --payload "fileb://$ARTIFACT_DIR/tx4-payload.json" \
  "$ARTIFACT_DIR/tx4.json" >/dev/null & PID4=$!
wait "$PID3"
wait "$PID4"

python3 - "$ARTIFACT_DIR/tx3.json" "$ARTIFACT_DIR/tx4.json" \
  "$((BASE_NONCE + 2))" "$((BASE_NONCE + 3))" <<'PY'
import json, sys
a, b = (json.load(open(path)) for path in sys.argv[1:3])
expected = {int(sys.argv[3]), int(sys.argv[4])}
assert a.get("success") is True and b.get("success") is True, (a, b)
assert {a["nonce"], b["nonce"]} == expected, (a, b)
assert a["txHash"] != b["txHash"], (a, b)
print("CONCURRENT_NONCES_UNIQUE", a["nonce"], b["nonce"])
PY

for n in 3 4; do
  HASH=$(jq -r '.txHash | ascii_downcase' "$ARTIFACT_DIR/tx$n.json")
  for _ in $(seq 1 60); do
    ITEM=$(aws dynamodb get-item --table-name "$TABLE_NAME" --region "$REGION" \
      --consistent-read \
      --key "{\"wallet\":{\"S\":\"$WALLET_LOWER\"},\"tx_hash\":{\"S\":\"$HASH\"}}")
    [ "$(jq -r '.Item.status.S // ""' <<<"$ITEM")" = CONFIRMED ] && break
    sleep 10
  done
  [ "$(jq -r '.Item.status.S' <<<"$ITEM")" = CONFIRMED ]
  jq -e '.Item.signed_raw_tx.S != null and .Item.ttl.N != null' <<<"$ITEM" >/dev/null
done
```

### 2.10 Verify final invariants and preserve evidence

```bash
EXPECTED_FINAL_NONCE=$((BASE_NONCE + 4))
CHAIN_NONCE_HEX=$(rpc "$(jq -nc --arg a "$CANARY_WALLET" \
  '{jsonrpc:"2.0",method:"eth_getTransactionCount",params:[$a,"latest"],id:1}')" \
  | jq -er .result)
CHAIN_NONCE=$((CHAIN_NONCE_HEX))

STATE=$(aws dynamodb get-item --table-name "$TABLE_NAME" --region "$REGION" \
  --consistent-read \
  --key "{\"wallet\":{\"S\":\"$WALLET_LOWER\"},\"tx_hash\":{\"S\":\"nonce-state\"}}")

NEXT_NONCE=$(jq -r '.Item.next_nonce.N' <<<"$STATE")
CONFIRMED_NONCE=$(jq -r '.Item.confirmed_nonce.N' <<<"$STATE")
PENDING_COUNT=$(jq -r '.Item.pending_count.N' <<<"$STATE")

printf 'expected=%s chain=%s next=%s confirmed=%s pending=%s\n' \
  "$EXPECTED_FINAL_NONCE" "$CHAIN_NONCE" "$NEXT_NONCE" \
  "$CONFIRMED_NONCE" "$PENDING_COUNT"

[ "$CHAIN_NONCE" -eq "$EXPECTED_FINAL_NONCE" ]
[ "$NEXT_NONCE" -eq "$EXPECTED_FINAL_NONCE" ]
[ "$CONFIRMED_NONCE" -eq "$EXPECTED_FINAL_NONCE" ]
[ "$PENDING_COUNT" -eq 0 ]

# Alarm *state* is not alarm *delivery*: a topic-policy or KMS gap fails the publish
# silently while every alarm sits green (found live 2026-09-11; alarms had never been
# deliverable). Force one alarm through and require a successful action execution:
DLQ_ALARM=$(aws cloudwatch describe-alarms --alarm-name-prefix "$CANARY_STACK_NAME" \
  --region "$REGION" --query "MetricAlarms[?contains(AlarmName,'Dlq')].AlarmName|[0]" --output text)
aws cloudwatch set-alarm-state --alarm-name "$DLQ_ALARM" --region "$REGION" \
  --state-value ALARM --state-reason "canary: prove alarm->SNS delivery"
sleep 20
aws cloudwatch describe-alarm-history --alarm-name "$DLQ_ALARM" --region "$REGION" \
  --history-item-type Action --max-records 1 \
  --query 'AlarmHistoryItems[0].HistorySummary' --output text \
  | tee "$ARTIFACT_DIR/alarm-delivery.txt" | grep -q '^Successfully executed action'
aws cloudwatch set-alarm-state --alarm-name "$DLQ_ALARM" --region "$REGION" \
  --state-value OK --state-reason "canary: restore"

# Every alarm must be OK, including WatcherBlockProgress, which proves the EMF
# pipeline end to end (a dead metric stream shows here as ALARM, because the alarm
# treats missing data as breaching).
aws cloudwatch describe-alarms --alarm-name-prefix "$CANARY_STACK_NAME" --region "$REGION" \
  --query 'MetricAlarms[?StateValue!=`OK`].[AlarmName,StateValue]' --output text \
  | tee "$ARTIFACT_DIR/non-ok-alarms.txt"
[ ! -s "$ARTIFACT_DIR/non-ok-alarms.txt" ]

aws cloudformation describe-stacks --stack-name "$CANARY_STACK_NAME" --region "$REGION" \
  --query 'Stacks[0].{Status:StackStatus,Outputs:Outputs}' --output json \
  > "$ARTIFACT_DIR/final-stack.json"
aws ecs describe-services --cluster "$ECS_CLUSTER" --services "$ECS_SERVICE" \
  --region "$REGION" --output json > "$ARTIFACT_DIR/final-ecs.json"
printf '%s\n' "$STATE" > "$ARTIFACT_DIR/final-nonce-state.json"
unset RPC_HTTP_URL

echo "CANARY_PASSED evidence=$ARTIFACT_DIR"
```

A pass is not just four successful Lambda responses. It requires the exact-hash recovery,
unique concurrent nonces, terminal transaction rows with retained signed bytes and TTL,
a healthy watcher, and agreement among the chain nonce, `next_nonce`, `confirmed_nonce`,
and `pending_count`.

### 2.11 Verify dynamic fee replacement (when enabled)

Run this extension only after §2.10 is green. Repeat the identity/stack/wallet guards and
start from a fresh current nonce with `pending_count` zero. Preserve every resulting row in
the artifact directory.

The replacement Lambda takes speed-up intent from the active candidate's wallet-signed
bytes and refuses a family whose stored bytes do not hash to its active hash, so the test
must use a real stuck transaction rather than an injected family row. The simplest real one
is underpriced: an explicit `maxFeePerGas` below the current base fee is admitted to the
mempool but can never be included. No DynamoDB writes are injected anywhere in this
section. A working policy is `{"bumpEveryBlocks":5,"maxBumps":3,"onExhaust":"hold",
"maxFeePerGasWei":"50000000000","maxTotalFeeWei":"1050000000000000"}`.

1. Submit a zero-value self-transfer with `feeSpeed: "slow"`, that policy, and a unique
   idempotency key. Require a `family#<nonce>` row with `fee_speed=slow`,
   `active_generation=0`, cap >= tip, both below request/deployment ceilings; wait for
   `CONFIRMED` and pending count zero.
2. Read the latest block's `baseFeePerGas`. Submit a second zero-value self-transfer with
   the same policy and explicit fees below it (for example `maxFeePerGas: "2"`,
   `maxPriorityFeePerGas: "1"` when the base fee is in the tens of wei). Require
   `success: true` at the next nonce.
3. Immediately direct-invoke the replacement function with an SQS-shaped `cancel` message
   (`{"wallet":…,"nonce":…,"expectedGeneration":1,"action":"cancel"}` as the record body).
   With the stored hold policy it must fail `cancel is not authorized`; consistently read
   the family and require `active_generation=0`.
4. Within a few blocks of eligibility, require watcher log `Replacement request enqueued`,
   family generation 1 with a new active hash, the old row `replacement_active=false`, and
   the new candidate action `speedUp`. Decode both rows' `signed_raw_tx`: `to`, `value`,
   `data`, gas limit, nonce, and chain id must be identical, the new `maxFeePerGas` higher,
   and both must recover to the canary wallet. Send the same generation-1 message once more
   to the internal queue and require generation remains 1 (at-least-once delivery no-op).
5. Wait for the replacement candidate to reach `CONFIRMED`, then continue waiting through
   `requiredConfirmations + 20` blocks. This second wait is load-bearing: a 60-second cache
   refresh removes CONFIRMED rows from the active cache, so family finalization must use
   the reorg detector's durable wallet/nonce/hash identity. Require family state
   `CONFIRMED`, `winner_hash` equal to the replacement, and every losing row terminal
   (`REPLACED`, or `DROPPED` when the watcher first observes the nonce consumed by the
   winner).
6. Re-run §2.10 with the added nonce. Require replacement queue and DLQ visible/in-flight
   counts all zero; `ReplacementBroadcast` EMF exists; watcher/replacement logs contain no
   HTTP/WSS URL; and every original plus replacement alarm is `OK`.

A service restart between candidate confirmation and reorg finality invalidates that
specific finality test because the reorg detector is intentionally in memory. Start a
fresh controlled family after the service is stable; do not claim a restarted watcher
proved cache-independent finalization for a transaction it did not observe.

## 3. Failure handling

### Known failure signatures (seen on live runs)

| Symptom | Cause | Resolution |
|---|---|---|
| Every signing request returns `SIGNER_ERROR: ... HTTP client error: builder error` | The Lambda's inline CA is truncated, because `cdk --context` drops everything after the first newline of a multi-line value | Carry the CA base64 (`nitroCaCertB64`); the stack decodes it. Run the §2.4 TLS wiring check before signing |
| `http_server` container restart-looping; user_data log shows `ASN1_mbstring_ncopy:string too long` | Server cert CSR used the NLB DNS name as the CN; X.509 CNs cap at 64 chars | Fixed in user_data (constant CN; the SAN carries the DNS name). Verify with the §2.5 SAN check |
| `/health` connection reset (curl exit 7 or code 000) while TLS handshake succeeds | Health handler crashed on the enclave ping response shape | Fixed (ping response parsed). A 000/503 from `/health` is always the parent–enclave path, not the NLB |
| `finch push` fails `no basic auth credentials` after successful `finch login` | Push runs VM-side as root and cannot read the macOS keychain | §1.1.1: write the token to `/root/.docker/config.json` in the VM; use the `finch-cdk` wrapper for CDK |
| Lambda asset build fails `rosetta error: failed to open elf` | An x86_64-only pinned build tool ran on the arm64 BUILDPLATFORM | Dockerfile installs arch-aware pinned tools; keep both checksums pinned when bumping versions |
| Enclave image build fails resolving a Python pin that exists on your workstation | The enclave base is AL2023/python3.9; the pin has no 3.9 wheel | Resolve pins inside the exact base digest first (§1.5) |
| A chain deploy suddenly targets the Nitro stack | `.nitro-config` carries the Nitro stack's `STACK_NAME` and was sourced after the chain stack name was set | `deploy-chain.sh` now preserves the chain name across the source; in manual shells, always re-set `STACK_NAME` after `source .nitro-config` |
| Post-deploy discovery dies on `DescribeLoadBalancers ... ARN must be specified` | NLB name-prefix matching; CloudFormation truncates resource names | Fixed: discovery matches the DNS name from the stack output |
| `deploy-nitro-stack.sh: bad substitution` at start | `${VAR,,}` needs bash 4; macOS ships 3.2 | Fixed with `tr`. Keep new scripts bash-3.2-clean |
| Alarm fires (state ALARM) but nothing is delivered; action history says `not authorized to perform: SNS:Publish` | `enforceSSL` materializes a topic policy, which then *is* the authorization; the CloudWatch alarms principal has no implicit publish right once any resource policy exists | Topic policy grants `sns:Publish` to `cloudwatch.amazonaws.com` (SourceAccount + alarm SourceArn conditions). Always run the §2.10 delivery probe: alarm state alone cannot catch this |
| Fresh Nitro deploy: NLB targets stay `unhealthy`; `/var/log/user-data.log` shows `docker login … context deadline exceeded` | Instances booted before the new ECR VPC endpoints served traffic, and the image pull was not retried | Fixed in #19 (endpoint dependency, pull retries, ELB health checks). On older revisions, run `aws autoscaling start-instance-refresh` on the ASG |
| Replacement confirms but `family_state` stays `CONSUMED` after the +20-block window | Family finalization depended on a cached CONFIRMED row, but the periodic active-only refresh removed it before reorg finality | Fixed in 86c8ea7: finalize from the reorg detector's durable wallet/nonce/hash identity. Run a fresh §2.11 family without a watcher restart and require automatic `CONFIRMED` |


- Stop at the first failed assertion. Preserve the artifact directory and relevant Lambda,
  ECS, CloudFormation, and DynamoDB evidence before retrying.
- If the recovery injection transaction is canceled, do not remove its conditions or use
  unconditional updates. Restore watcher desired count to one, inspect the actual rows,
  and start a fresh canary run with new idempotency keys.
- If any command after scaling the watcher to zero fails, the trap restores desired count
  to one. Still run `aws ecs wait services-stable` and verify `[1, 1, 0]` explicitly.
- Do not classify a timeout as a failed transaction without checking DynamoDB and the exact
  transaction hash. Ambiguous sends are intentionally recovered from stored signed bytes.
- Never paste RPC URLs, Secrets Manager values, signed raw transactions from funded
  wallets, or temporary ECR credentials into issues or committed files.
