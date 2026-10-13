#!/usr/bin/env bash
#
# Deploy the Nitro Enclave signing stack and generate initial keys
#
# Usage:
#   ./scripts/deploy-nitro-stack.sh [environment] [region]
#
# Set NITRO_STACK_PREFIX to deploy another independently named stack while retaining the
# environment's security mode (for example staging attestation without colliding with an
# existing stagingNitroWalletEth stack).
#
# Examples:
#   ./scripts/deploy-nitro-stack.sh dev us-east-1
#   ./scripts/deploy-nitro-stack.sh prod us-west-2
#
# Set CDK_ENCLAVE_PCR0=<96 hex chars> to make the KMS key policy require that enclave
# measurement for kms:Decrypt. The measurement does not exist until the enclave image has
# been built, so the first deploy runs without it and denies decrypt to everyone; see
# Step 5 output for the redeploy.
#
#   CDK_ENCLAVE_PCR0=abc...123 ./scripts/deploy-nitro-stack.sh prod us-west-2
#
# Authentication (required — the signing service has no unauthenticated mode):
#   NITRO_AUTH_MODE          sigv4 (default) or mtls
#   NITRO_ALLOWED_PRINCIPALS extra IAM role ARNs allowed to request a signature, comma
#                            separated. The invoking Lambda's role is added automatically,
#                            so this is only for break-glass or additional callers.
#   NITRO_SECRET_ID          Secrets Manager id of the wallet this service may sign with.
#                            Callers cannot choose it. Defaults to nitro-wallet/$ENVIRONMENT.
#   NITRO_ALLOWED_CLIENTS    mtls only: client cert CN / DNS SAN values, comma separated.
#   NITRO_CLIENT_CA_PATH     mtls only: CA bundle path under /etc/pki/tls/certs.
#   NITRO_CLIENT_CRL_PATH    mtls, optional: CRL path under /etc/pki/tls/certs. Setting it
#                            enables revocation checking for the whole chain, which means a
#                            missing or expired CRL then rejects every client.
#   NITRO_SKIP_TLS_VERIFY   true only for dev/test stacks using the sample self-signed
#                           server certificate. Defaults false and is forbidden for prod.
#
# Container runtime: set CDK_DOCKER to the runtime CDK should shell out to if it is not
# `docker` (e.g. CDK_DOCKER=finch). Aliasing `docker` is not supported by CDK.
#

set -euo pipefail

ENVIRONMENT="${1:-dev}"
REGION="${2:-us-east-1}"
STACK_PREFIX="${NITRO_STACK_PREFIX:-$ENVIRONMENT}"
if [[ ! "$STACK_PREFIX" =~ ^[A-Za-z][A-Za-z0-9-]*$ ]]; then
    echo "Error: NITRO_STACK_PREFIX must start with a letter and contain only letters, digits, or hyphens." >&2
    exit 1
fi
STACK_NAME="${STACK_PREFIX}NitroWalletEth"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
NITRO_DIR="$ROOT_DIR/nitro_enclave_signer"
CDK_BIN="${CDK_BIN:-$ROOT_DIR/infra/node_modules/.bin/cdk}"
if [[ ! -x "$CDK_BIN" ]]; then
    echo "Error: pinned CDK CLI not installed at '$CDK_BIN'." >&2
    echo "Run: npm --prefix '$ROOT_DIR/infra' ci" >&2
    exit 1
fi

AUTH_MODE="${NITRO_AUTH_MODE:-sigv4}"
SECRET_ID="${NITRO_SECRET_ID:-nitro-wallet/$STACK_PREFIX}"
ALLOWED_PRINCIPALS="${NITRO_ALLOWED_PRINCIPALS:-}"
ALLOWED_CLIENTS="${NITRO_ALLOWED_CLIENTS:-}"
CLIENT_CA_PATH="${NITRO_CLIENT_CA_PATH:-}"
CLIENT_CRL_PATH="${NITRO_CLIENT_CRL_PATH:-}"
SKIP_TLS_VERIFY="${NITRO_SKIP_TLS_VERIFY:-false}"

case "$(printf '%s' "$SKIP_TLS_VERIFY" | tr '[:upper:]' '[:lower:]')" in
    true|1) SKIP_TLS_VERIFY=true ;;
    false|0) SKIP_TLS_VERIFY=false ;;
    *) echo "Error: NITRO_SKIP_TLS_VERIFY must be true or false." >&2; exit 1 ;;
esac
if [[ "$ENVIRONMENT" == "prod" && "$SKIP_TLS_VERIFY" == "true" ]]; then
    echo "Error: NITRO_SKIP_TLS_VERIFY=true is forbidden for prod." >&2
    exit 1
fi

# CDK shells out to $CDK_DOCKER, defaulting to `docker`. Check for whichever is configured
# rather than assuming Docker, so Finch and other drop-ins work.
CONTAINER_RUNTIME="${CDK_DOCKER:-docker}"

echo "=========================================="
echo "Nitro Enclave Stack Deployment"
echo "=========================================="
echo "Environment: $ENVIRONMENT"
echo "Stack:       $STACK_NAME"
echo "Region:      $REGION"
echo "Auth mode:   $AUTH_MODE"
echo "Wallet:      $SECRET_ID"
echo "Runtime:     $CONTAINER_RUNTIME"
echo ""

# Check prerequisites
command -v aws >/dev/null 2>&1 || { echo "Error: aws CLI not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Error: python3 not found"; exit 1; }
command -v "$CONTAINER_RUNTIME" >/dev/null 2>&1 || {
    echo "Error: container runtime '$CONTAINER_RUNTIME' not found."
    echo "Install it, or set CDK_DOCKER to the runtime you use (e.g. CDK_DOCKER=finch)."
    exit 1
}
command -v jq >/dev/null 2>&1 || { echo "Error: jq not found"; exit 1; }

if [[ "$AUTH_MODE" == "mtls" && ( -z "$ALLOWED_CLIENTS" || -z "$CLIENT_CA_PATH" ) ]]; then
    echo "Error: NITRO_AUTH_MODE=mtls requires NITRO_ALLOWED_CLIENTS and NITRO_CLIENT_CA_PATH."
    echo "The signing service refuses to start without a client allowlist and a CA bundle."
    exit 1
fi

# Get AWS account
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "AWS Account: $ACCOUNT_ID"
echo ""

# Deployment TLS CA. The Nitro NLB is TCP passthrough and instances are cattle behind an
# ASG, so there is no single ACM cert to attach. Instead a small private CA — created
# here, stored in Secrets Manager — signs a per-instance server cert at boot whose SAN is
# the NLB DNS name, and the broadcast Lambda pins this CA. This gives verified TLS with no
# external CA and no per-host manual work. dev may opt out via NITRO_SKIP_TLS_VERIFY=true.
TLS_CA_SECRET_NAME="${NITRO_TLS_CA_SECRET_NAME:-nitro-tls-ca/$STACK_PREFIX}"
TLS_CA_CERT_PEM=""
if [[ "$SKIP_TLS_VERIFY" == "true" ]]; then
    echo "TLS: skip-verify requested (dev only); not provisioning a deployment CA."
    TLS_CA_SECRET_NAME=""
else
    echo "Step 0: Ensuring deployment TLS CA ($TLS_CA_SECRET_NAME)..."
    if EXISTING=$(aws secretsmanager get-secret-value --region "$REGION" \
            --secret-id "$TLS_CA_SECRET_NAME" --query SecretString --output text 2>/dev/null); then
        echo "✓ CA already exists; reusing it (instances re-issue leaves from it)"
        TLS_CA_CERT_PEM=$(printf '%s' "$EXISTING" | jq -r '.cert')
    else
        echo "  Generating a new deployment CA (10y, RSA-4096)..."
        CA_TMP=$(mktemp -d)
        trap 'rm -rf "$CA_TMP"' EXIT
        openssl req -x509 -newkey rsa:4096 -nodes -days 3650 -sha256 \
            -keyout "$CA_TMP/ca.key" -out "$CA_TMP/ca.crt" \
            -subj "/CN=nitro-signer-deployment-ca-$STACK_PREFIX" \
            -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
            -addext "keyUsage=critical,keyCertSign,cRLSign"
        CA_SECRET_JSON=$(jq -n --rawfile cert "$CA_TMP/ca.crt" --rawfile key "$CA_TMP/ca.key" \
            '{cert: $cert, key: $key}')
        aws secretsmanager create-secret --region "$REGION" \
            --name "$TLS_CA_SECRET_NAME" \
            --description "Deployment TLS CA for the Nitro signing NLB ($STACK_PREFIX)" \
            --secret-string "$CA_SECRET_JSON" >/dev/null
        TLS_CA_CERT_PEM=$(cat "$CA_TMP/ca.crt")
        rm -rf "$CA_TMP"; trap - EXIT
        echo "✓ CA created and stored in Secrets Manager"
    fi
fi
TLS_CA_CERT_B64=""
if [ -n "$TLS_CA_CERT_PEM" ]; then
    TLS_CA_CERT_B64=$(printf '%s' "$TLS_CA_CERT_PEM" | base64 | tr -d '\n')
fi
echo ""

# Step 1: Build KMS tool
echo "Step 1: Building kmstool_enclave_cli..."
if [[ ! -f "$NITRO_DIR/application/eth1/enclave/kms/kmstool_enclave_cli" ]]; then
    (cd "$NITRO_DIR" && ./scripts/build_kmstool_enclave_cli.sh)
    echo "✓ KMS tool built"
else
    echo "✓ KMS tool already exists, skipping build"
fi
echo ""

# Step 2: Setup Python environment and deploy CDK
echo "Step 2: Deploying Nitro CDK stack..."
(
    cd "$NITRO_DIR"
    
    # Create venv if needed
    if [[ ! -d ".venv" ]]; then
        python3 -m venv .venv
    fi
    
    source .venv/bin/activate
    pip install -q -r requirements.txt
    
    # CDK_DEFAULT_* is used by `cdk bootstrap`; CDK_DEPLOY_* is read by app.py
    export CDK_DEFAULT_REGION="$REGION"
    export CDK_DEFAULT_ACCOUNT="$ACCOUNT_ID"
    export CDK_DEPLOY_REGION="$REGION"
    export CDK_DEPLOY_ACCOUNT="$ACCOUNT_ID"
    
    "$CDK_BIN" bootstrap "aws://$ACCOUNT_ID/$REGION" \
        --context deployment="$ENVIRONMENT" \
        --context prefix="$STACK_PREFIX" \
        --context authMode="$AUTH_MODE" \
        --context secretId="$SECRET_ID" \
        --context allowedPrincipals="$ALLOWED_PRINCIPALS" \
        --context allowedClients="$ALLOWED_CLIENTS" \
        --context clientCaPath="$CLIENT_CA_PATH" \
        --context clientCrlPath="$CLIENT_CRL_PATH" \
        --context nitroSkipTlsVerify="$SKIP_TLS_VERIFY" \
        --context tlsCaSecretName="$TLS_CA_SECRET_NAME" \
        --context tlsCaCertB64="$TLS_CA_CERT_B64"
    
    # Default to `broadening` for staging/prod so CDK prompts on IAM/SG widening.
    # `dev` skips the prompt since iteration is expected there.
    # Callers can override with CDK_REQUIRE_APPROVAL=<never|broadening|any-change>.
    if [ -n "${CDK_REQUIRE_APPROVAL:-}" ]; then
        APPROVAL="$CDK_REQUIRE_APPROVAL"
    elif [ "$ENVIRONMENT" = "dev" ]; then
        APPROVAL="never"
    else
        APPROVAL="broadening"
    fi

    # Deploy. The auth context is not optional: app.py rejects an unknown authMode and the
    # signing service will not start without an allowlist.
    "$CDK_BIN" deploy "$STACK_NAME" \
        --context deployment="$ENVIRONMENT" \
        --context prefix="$STACK_PREFIX" \
        --context authMode="$AUTH_MODE" \
        --context secretId="$SECRET_ID" \
        --context allowedPrincipals="$ALLOWED_PRINCIPALS" \
        --context allowedClients="$ALLOWED_CLIENTS" \
        --context clientCaPath="$CLIENT_CA_PATH" \
        --context clientCrlPath="$CLIENT_CRL_PATH" \
        --context nitroSkipTlsVerify="$SKIP_TLS_VERIFY" \
        --context tlsCaSecretName="$TLS_CA_SECRET_NAME" \
        --context tlsCaCertB64="$TLS_CA_CERT_B64" \
        --require-approval "$APPROVAL" \
        --outputs-file cdk-outputs.json
)
echo "✓ CDK stack deployed"
echo ""

# Step 3: Extract outputs
echo "Step 3: Extracting stack outputs..."
# Query CloudFormation for outputs
echo "Querying CloudFormation for outputs..."
OUTPUTS=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query 'Stacks[0].Outputs' --output json)
KMS_KEY_ID=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey == "KMSKeyID") | .OutputValue')
EC2_ROLE_ARN=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey == "EC2InstanceRoleARN") | .OutputValue')

# The signing-client role ARN is the stable identity that TX Manager broadcast Lambdas
# assume to authenticate. It must be present: without it deploy-chain.sh cannot grant
# sts:AssumeRole and the broadcast Lambda cannot reach the signing service. Fail closed
# rather than writing a config that silently omits it.
SIGNING_CLIENT_ROLE_ARN=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey == "SigningClientRoleArn") | .OutputValue')
if [[ -z "$SIGNING_CLIENT_ROLE_ARN" || "$SIGNING_CLIENT_ROLE_ARN" == "null" ]]; then
    echo "Error: stack output 'SigningClientRoleArn' is missing or null." >&2
    echo "The Nitro stack must export it so TX Manager deploys can grant sts:AssumeRole on" >&2
    echo "the signing-client role. Redeploy the Nitro stack with the current template." >&2
    exit 1
fi

# Get NLB DNS from output or query ELB directly
NLB_DNS=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey == "NLBDNS") | .OutputValue')
if [[ -z "$NLB_DNS" ]]; then
    NLB_DNS=$(aws elbv2 describe-load-balancers --region "$REGION" \
        --query "LoadBalancers[?contains(LoadBalancerName, '${STACK_PREFIX}Nit')].DNSName" \
        --output text)
fi

# Get VPC ID from the NLB. Match on the DNS name from the stack output — CloudFormation
# truncates resource names, so name-prefix matching (e.g. "stagingNit") is unreliable.
NITRO_VPC_ID=$(aws elbv2 describe-load-balancers --region "$REGION" \
    --query "LoadBalancers[?DNSName=='$NLB_DNS'].VpcId | [0]" \
    --output text)
if [[ -z "$NITRO_VPC_ID" || "$NITRO_VPC_ID" == "None" ]]; then
    echo "Error: could not resolve the NLB '$NLB_DNS' to a VPC." >&2
    exit 1
fi

# Get the Nitro instance security group. Match the exact CDK description within this stack:
# the stack's VPC-endpoint security groups carry descriptions like
# "<prefix>NitroWalletEth/ECREndpoint/SecurityGroup", so a substring match can return an
# endpoint group and deploy-chain.sh would then open the Lambda path on the wrong group.
NITRO_SECURITY_GROUP_ID=$(aws ec2 describe-security-groups --region "$REGION" \
    --filters "Name=vpc-id,Values=$NITRO_VPC_ID" \
              "Name=tag:aws:cloudformation:stack-name,Values=$STACK_NAME" \
              "Name=description,Values=Private SG for NitroWallet EC2 instance" \
    --query 'SecurityGroups[].GroupId' --output text 2>/dev/null)
if [[ -z "$NITRO_SECURITY_GROUP_ID" || "$NITRO_SECURITY_GROUP_ID" == "None" \
      || "$NITRO_SECURITY_GROUP_ID" =~ [[:space:]] ]]; then
    echo "Warning: Could not identify exactly one Nitro instance security group" \
         "('$NITRO_SECURITY_GROUP_ID'). Set NITRO_SECURITY_GROUP_ID manually."
    NITRO_SECURITY_GROUP_ID=""
fi

echo "NLB Endpoint:  https://$NLB_DNS"
echo "KMS Key ID:    $KMS_KEY_ID"
echo "EC2 Role ARN:  $EC2_ROLE_ARN"
echo "Signing Role:  $SIGNING_CLIENT_ROLE_ARN"
echo "VPC ID:        $NITRO_VPC_ID"
echo "Security Group: $NITRO_SECURITY_GROUP_ID"
echo ""

# Step 4: Instance initialization info
echo "Step 4: Instance Initialization"
echo ""
echo "The EC2 instances are initializing. This takes 5-10 minutes for:"
echo "  - Pulling Docker images from ECR"
echo "  - Building the enclave EIF file"
echo "  - Starting the enclave and HTTP server"
echo ""
echo "The NLB is internal (private subnets), so health checks must be run"
echo "from within the VPC (e.g., via SSM to an EC2 instance)."
echo ""

# Step 5: Enforce the enclave measurement on the KMS key
echo "Step 5: KMS Key Policy Configuration"
echo ""
if [[ -n "${CDK_ENCLAVE_PCR0:-}" ]]; then
    echo "✓ Deployed with PCR0 enforcement: ${CDK_ENCLAVE_PCR0}"
    echo ""
    echo "Confirm the deployed policy enforces exactly that measurement:"
    echo "  ./scripts/verify-kms-attestation.sh $CDK_ENCLAVE_PCR0"
else
    echo "IMPORTANT: signing is currently FAILING CLOSED. The key policy denies"
    echo "kms:Decrypt to every principal until you supply the enclave measurement."
    echo ""
    echo "1. Get PCR0 for the enclave image you built:"
    echo "     nitro-cli describe-eif --eif-path <path> | jq -r '.Measurements.PCR0'"
    echo "   Or, from a running instance via SSM (parent-reported, use only to spot a"
    echo "   stale policy — not to establish trust):"
    echo "     nitro-cli describe-enclaves | jq -r '.[0].Measurements.PCR0'"
    echo ""
    echo "2. Redeploy with it. CDK owns the key policy, so this is a deploy-time input;"
    echo "   editing the policy by hand is reverted by the next deploy:"
    echo "     NITRO_STACK_PREFIX=$STACK_PREFIX CDK_ENCLAVE_PCR0=<PCR0> ./scripts/deploy-nitro-stack.sh $ENVIRONMENT $REGION"
    echo ""
    echo "3. Verify (no argument reports what is enforced; an argument asserts a match):"
    echo "     ./scripts/verify-kms-attestation.sh <PCR0>"
    echo ""
    echo "Note: --context deployment=dev builds the enclave in debug mode, which zeroes"
    echo "PCR0. A debug enclave cannot satisfy an attestation condition; use staging/prod"
    echo "wherever the enclave boundary must actually hold."
fi
echo ""

# Step 6: Output configuration for TX Manager
echo "=========================================="
echo "Deployment Complete"
echo "=========================================="
echo ""
echo "Use these values when deploying TX Manager stacks:"
echo ""
echo "  NITRO_ENDPOINT=https://$NLB_DNS"
echo "  KMS_KEY_ID=$KMS_KEY_ID"
echo "  NITRO_AUTH_ROLE_ARN=$SIGNING_CLIENT_ROLE_ARN"
echo ""
echo "To generate a new signing key (only works once PCR0 enforcement is deployed):"
echo ""
echo "  aws lambda invoke --region $REGION \\"
echo "    --function-name \$(aws cloudformation describe-stack-resources \\"
echo "      --stack-name $STACK_NAME --region $REGION \\"
echo "      --query \"StackResources[?ResourceType=='AWS::Lambda::Function'].PhysicalResourceId\" \\"
echo "      --output text) \\"
echo "    --payload '{\"operation\":\"generate_key\",\"secret_name\":\"nitro-wallet/my-wallet\"}' \\"
echo "    --cli-binary-format raw-in-base64-out /dev/stdout"
echo ""
echo "Invoke through the Lambda, not curl. The signing service requires a signed"
echo "GetCallerIdentity proof that curl cannot produce by hand, and only principals in"
echo "the deployed allowlist are accepted. The Lambda builds that proof for you."
echo ""

# Save outputs for later use. TLS verification is skipped only when the caller made the
# explicit, validated dev/test choice above; it is never inferred from an environment name.
cat > "$ROOT_DIR/.nitro-config" <<EOF
NITRO_ENDPOINT=https://$NLB_DNS
NITRO_KMS_KEY_ID=$KMS_KEY_ID
NITRO_EC2_ROLE_ARN=$EC2_ROLE_ARN
NITRO_AUTH_ROLE_ARN=$SIGNING_CLIENT_ROLE_ARN
NITRO_SECRET_ID=$SECRET_ID
NITRO_SKIP_TLS_VERIFY=$SKIP_TLS_VERIFY
NITRO_TLS_CA_SECRET_NAME=$TLS_CA_SECRET_NAME
NITRO_CA_CERT_B64=$TLS_CA_CERT_B64
NITRO_VPC_ID=$NITRO_VPC_ID
NITRO_SECURITY_GROUP_ID=$NITRO_SECURITY_GROUP_ID
REGION=$REGION
STACK_NAME=$STACK_NAME
EOF
chmod 600 "$ROOT_DIR/.nitro-config"

echo "Configuration saved to .nitro-config"
