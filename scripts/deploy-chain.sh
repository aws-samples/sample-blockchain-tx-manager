#!/bin/bash
set -euo pipefail

CHAIN=$1
ENVIRONMENT=${2:-prod}

if [ -z "$CHAIN" ]; then
  echo "Usage: $0 <chain> [environment]"
  echo "  Mainnets: ethereum, polygon, arbitrum, base, optimism"
  echo "  Testnets: sepolia, amoy, arbitrum-sepolia, base-sepolia, optimism-sepolia"
  echo "  environment: prod (default), staging, dev"
  exit 1
fi

# Production keeps provider RPC URLs (which embed the provider API key) in Secrets Manager:
#   aws secretsmanager create-secret --name tx-manager/<chain>/rpc \
#     --secret-string '{"rpcUrl":"https://...","wsRpcUrl":"wss://..."}'
#   export RPC_SECRET_ARN=<arn>
# When RPC_SECRET_ARN is set the per-chain *_RPC_URL/*_WS_URL variables are not required
# and are not passed to the stack. The CDK stack refuses plaintext URLs for environment=prod.
RPC_SECRET_ARN="${RPC_SECRET_ARN:-}"
if [ -n "$RPC_SECRET_ARN" ]; then
  # Satisfy the per-chain `:?` guards below without requiring the plaintext URLs.
  for v in ETH SEPOLIA POLYGON AMOY ARBITRUM ARBITRUM_SEPOLIA OPTIMISM OPTIMISM_SEPOLIA BASE BASE_SEPOLIA; do
    eval ": \"\${${v}_RPC_URL:=secret}\""
    eval ": \"\${${v}_WS_URL:=secret}\""
  done
fi

case $CHAIN in
  ethereum)
    CHAIN_ID=1
    CONFIRMATIONS=12
    RPC_URL=${ETH_RPC_URL:?ETH_RPC_URL not set}
    WS_URL=${ETH_WS_URL:?ETH_WS_URL not set}
    ;;
  sepolia)
    CHAIN_ID=11155111
    CONFIRMATIONS=3
    RPC_URL=${SEPOLIA_RPC_URL:?SEPOLIA_RPC_URL not set}
    WS_URL=${SEPOLIA_WS_URL:?SEPOLIA_WS_URL not set}
    ;;
  polygon)
    CHAIN_ID=137
    CONFIRMATIONS=128
    RPC_URL=${POLYGON_RPC_URL:?POLYGON_RPC_URL not set}
    WS_URL=${POLYGON_WS_URL:?POLYGON_WS_URL not set}
    ;;
  amoy)
    CHAIN_ID=80002
    CONFIRMATIONS=5
    RPC_URL=${AMOY_RPC_URL:?AMOY_RPC_URL not set}
    WS_URL=${AMOY_WS_URL:?AMOY_WS_URL not set}
    ;;
  arbitrum)
    CHAIN_ID=42161
    CONFIRMATIONS=1
    RPC_URL=${ARBITRUM_RPC_URL:?ARBITRUM_RPC_URL not set}
    WS_URL=${ARBITRUM_WS_URL:?ARBITRUM_WS_URL not set}
    ;;
  arbitrum-sepolia)
    CHAIN_ID=421614
    CONFIRMATIONS=1
    RPC_URL=${ARBITRUM_SEPOLIA_RPC_URL:?ARBITRUM_SEPOLIA_RPC_URL not set}
    WS_URL=${ARBITRUM_SEPOLIA_WS_URL:?ARBITRUM_SEPOLIA_WS_URL not set}
    ;;
  base)
    CHAIN_ID=8453
    CONFIRMATIONS=1
    RPC_URL=${BASE_RPC_URL:?BASE_RPC_URL not set}
    WS_URL=${BASE_WS_URL:?BASE_WS_URL not set}
    ;;
  base-sepolia)
    CHAIN_ID=84532
    CONFIRMATIONS=1
    RPC_URL=${BASE_SEPOLIA_RPC_URL:?BASE_SEPOLIA_RPC_URL not set}
    WS_URL=${BASE_SEPOLIA_WS_URL:?BASE_SEPOLIA_WS_URL not set}
    ;;
  optimism)
    CHAIN_ID=10
    CONFIRMATIONS=1
    RPC_URL=${OPTIMISM_RPC_URL:?OPTIMISM_RPC_URL not set}
    WS_URL=${OPTIMISM_WS_URL:?OPTIMISM_WS_URL not set}
    ;;
  optimism-sepolia)
    CHAIN_ID=11155420
    CONFIRMATIONS=1
    RPC_URL=${OPTIMISM_SEPOLIA_RPC_URL:?OPTIMISM_SEPOLIA_RPC_URL not set}
    WS_URL=${OPTIMISM_SEPOLIA_WS_URL:?OPTIMISM_SEPOLIA_WS_URL not set}
    ;;
  *)
    echo "Unknown chain: $CHAIN"
    echo "Mainnets: ethereum, polygon, arbitrum, base, optimism"
    echo "Testnets: sepolia, amoy, arbitrum-sepolia, base-sepolia, optimism-sepolia"
    exit 1
    ;;
esac

# Capitalize first letter for stack name
CHAIN_CAP="$(tr '[:lower:]' '[:upper:]' <<< ${CHAIN:0:1})${CHAIN:1}"
ENV_CAP="$(tr '[:lower:]' '[:upper:]' <<< ${ENVIRONMENT:0:1})${ENVIRONMENT:1}"

STACK_NAME="${STACK_NAME:-TxManager-${CHAIN_CAP}-${ENV_CAP}}"
RESOURCE_PREFIX="${CHAIN}-${ENVIRONMENT}"

echo "Deploying $STACK_NAME (chain_id: $CHAIN_ID, confirmations: $CONFIRMATIONS)"

# Validate URLs are not empty or localhost (plaintext path only)
if [ -n "$RPC_SECRET_ARN" ]; then
  echo "RPC endpoints: Secrets Manager ($RPC_SECRET_ARN)"
  RPC_CONTEXT="--context rpcSecretArn=$RPC_SECRET_ARN"
else
  if [ -z "$RPC_URL" ] || [[ "$RPC_URL" == *"localhost"* ]]; then
    echo "Error: RPC_URL is empty or contains localhost: '$RPC_URL'"
    exit 1
  fi
  if [ -z "$WS_URL" ] || [[ "$WS_URL" == *"localhost"* ]]; then
    echo "Error: WS_URL is empty or contains localhost: '$WS_URL'"
    exit 1
  fi
  if [ "$ENVIRONMENT" = "prod" ]; then
    echo "Error: environment=prod requires RPC_SECRET_ARN (RPC URLs carry the provider API key)."
    exit 1
  fi
  echo "Warning: RPC URLs will be deployed as plaintext environment variables (non-prod only)."
  RPC_CONTEXT="--context rpcUrl=$RPC_URL --context wsRpcUrl=$WS_URL"
fi

# Optional inputs. Declared here so `set -u` treats "not provided" as empty rather than
# aborting; .nitro-config (sourced below) or the environment may fill them in.
NITRO_ENDPOINT="${NITRO_ENDPOINT:-}"
NITRO_VPC_ID="${NITRO_VPC_ID:-}"
NITRO_SECURITY_GROUP_ID="${NITRO_SECURITY_GROUP_ID:-}"
NITRO_AUTH_ROLE_ARN="${NITRO_AUTH_ROLE_ARN:-}"
NITRO_SECRET_ID="${NITRO_SECRET_ID:-}"
NITRO_CA_CERT_B64="${NITRO_CA_CERT_B64:-}"
NITRO_SKIP_TLS_VERIFY="${NITRO_SKIP_TLS_VERIFY:-false}"
VPC_ID="${VPC_ID:-}"
REGION="${REGION:-}"
NITRO_CONTEXT=()

# Auto-source .nitro-config if it exists (provides NITRO_ENDPOINT, NITRO_VPC_ID, etc.)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NITRO_CONFIG="$(dirname "$SCRIPT_DIR")/.nitro-config"
if [ -f "$NITRO_CONFIG" ]; then
  echo "Loading Nitro config from .nitro-config"
  # .nitro-config carries the NITRO stack's STACK_NAME; sourcing it must not repoint
  # this deploy at the Nitro stack (updating stagingNitroWalletEth with the chain
  # template would destroy the signer). Preserve the chain stack name across the source.
  CHAIN_STACK_NAME="$STACK_NAME"
  source "$NITRO_CONFIG"
  STACK_NAME="$CHAIN_STACK_NAME"
  if [ -n "$REGION" ]; then
    # AWS CLI reads AWS_DEFAULT_REGION, AWS SDKs read AWS_REGION, CDK reads CDK_DEFAULT_REGION
    export AWS_REGION="$REGION"
    export AWS_DEFAULT_REGION="$REGION"
    export CDK_DEFAULT_REGION="$REGION"
  fi
fi

# Use VPC_ID from env, or fall back to NITRO_VPC_ID from .nitro-config
if [ -z "$VPC_ID" ] && [ -n "$NITRO_VPC_ID" ]; then
  VPC_ID="$NITRO_VPC_ID"
fi

# VPC_ID is required — each chain deploys into the existing Nitro Enclave signer VPC
if [ -z "$VPC_ID" ]; then
  echo "Error: VPC_ID environment variable is required."
  echo "Set it to the Nitro Enclave signer VPC ID, or place it in .nitro-config."
  echo "  export VPC_ID=vpc-..."
  exit 1
fi
echo "Using VPC: $VPC_ID"

# Optional: Nitro Enclave signing
NITRO_CONTEXT=()
if [ -n "$NITRO_ENDPOINT" ]; then
  NITRO_CONTEXT+=(--context "nitroEndpoint=$NITRO_ENDPOINT")
  echo "Using Nitro Enclave: $NITRO_ENDPOINT"

  if [ -z "$NITRO_SECRET_ID" ]; then
    echo "Error: NITRO_ENDPOINT is set but NITRO_SECRET_ID is not."
    echo "Set NITRO_SECRET_ID to the secret name used with generate-nitro-key.sh"
    echo "  e.g.: export NITRO_SECRET_ID=nitro-wallet/sepolia-dev"
    exit 1
  fi
  # Ensure nitro-wallet/ prefix
  if [[ "$NITRO_SECRET_ID" != nitro-wallet/* ]]; then
    NITRO_SECRET_ID="nitro-wallet/$NITRO_SECRET_ID"
  fi
  NITRO_CONTEXT+=(--context "nitroSecretId=$NITRO_SECRET_ID")
  echo "Nitro Secret ID: $NITRO_SECRET_ID"

  if [ -z "$NITRO_SECURITY_GROUP_ID" ]; then
    echo "Warning: NITRO_SECURITY_GROUP_ID is not set. Lambda may not be able to reach the Nitro NLB."
    echo "Set it from .nitro-config or pass it explicitly."
  else
    NITRO_CONTEXT+=(--context "nitroSecurityGroupId=$NITRO_SECURITY_GROUP_ID")
    echo "Nitro Security Group: $NITRO_SECURITY_GROUP_ID"
  fi

  # The broadcast Lambda authenticates to the signing service by assuming this stable,
  # zero-permission role (the Nitro stack's SigningClientRoleArn output, written to
  # .nitro-config as NITRO_AUTH_ROLE_ARN). Without it the Lambda has no identity the
  # allowlist recognizes, so signing fails closed — treat a missing value as fatal.
  if [ -z "$NITRO_AUTH_ROLE_ARN" ]; then
    echo "Error: NITRO_ENDPOINT is set but NITRO_AUTH_ROLE_ARN is not."
    echo "It is written to .nitro-config by deploy-nitro-stack.sh (SigningClientRoleArn output)."
    echo "Re-run the Nitro stack deploy to regenerate .nitro-config, or set NITRO_AUTH_ROLE_ARN"
    echo "explicitly to the Nitro stack's signing-client role ARN."
    exit 1
  fi
  NITRO_CONTEXT+=(--context "nitroAuthRoleArn=$NITRO_AUTH_ROLE_ARN")
  echo "Nitro Auth Role ARN: $NITRO_AUTH_ROLE_ARN"

  if [[ "$NITRO_SKIP_TLS_VERIFY" == "true" ]]; then
    NITRO_CONTEXT+=(--context nitroSkipTlsVerify=true)
    echo "Nitro TLS verification: SKIPPED (explicit dev/test setting)"
  elif [ -n "$NITRO_CA_CERT_B64" ]; then
    # Pin the deployment CA so the Lambda verifies the NLB cert (SAN = NLB DNS). The
    # cert stays base64 (one token): `cdk --context` drops everything after the first
    # newline of a multi-line value, so the PEM is decoded inside the stack.
    NITRO_CONTEXT+=(--context "nitroCaCertB64=$NITRO_CA_CERT_B64")
    echo "Nitro TLS verification: enabled (pinned deployment CA)"
  elif [ "$ENVIRONMENT" = "prod" ]; then
    echo "Error: prod Nitro deployment requires a pinned CA. Re-run deploy-nitro-stack.sh" >&2
    echo "to regenerate .nitro-config with NITRO_CA_CERT_B64, or set NITRO_SKIP_TLS_VERIFY only for dev." >&2
    exit 1
  else
    echo "Warning: no pinned CA and not skipping verification; the Lambda will use the system trust store."
  fi
fi

cd "$(dirname "$0")/../infra"

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

npx cdk deploy "$STACK_NAME" \
  --context stackName="$STACK_NAME" \
  --context resourcePrefix="$RESOURCE_PREFIX" \
  --context chainId="$CHAIN_ID" \
  $RPC_CONTEXT \
  --context requiredConfirmations="$CONFIRMATIONS" \
  --context environment="$ENVIRONMENT" \
  --context replacementEnabled="${REPLACEMENT_ENABLED:-true}" \
  --context defaultMaxFeePerGasWei="${DEFAULT_MAX_FEE_PER_GAS_WEI:-150000000000}" \
  --context hardMaxFeePerGasWei="${HARD_MAX_FEE_PER_GAS_WEI:-500000000000}" \
  --context defaultMaxTotalFeeWei="${DEFAULT_MAX_TOTAL_FEE_WEI:-20000000000000000}" \
  --context hardMaxTotalFeeWei="${HARD_MAX_TOTAL_FEE_WEI:-100000000000000000}" \
  --context maxReplacementAttempts="${MAX_REPLACEMENT_ATTEMPTS:-3}" \
  --context feeTipFloorWei="${FEE_TIP_FLOOR_WEI:-100000000}" \
  --context createDynamoDbKmsKey="${CREATE_DYNAMODB_KMS_KEY:-false}" \
  ${DYNAMODB_KMS_KEY_ARN:+--context dynamoDbKmsKeyArn="$DYNAMODB_KMS_KEY_ARN"} \
  ${ALARM_EMAIL:+--context alarmEmail="$ALARM_EMAIL"} \
  ${ALARM_TOPIC_ARN:+--context alarmTopicArn="$ALARM_TOPIC_ARN"} \
  --context destroyOnRemoval="${DESTROY_ON_REMOVAL:-false}" \
  --context vpcId="$VPC_ID" \
  "${NITRO_CONTEXT[@]}" \
  --require-approval "$APPROVAL"

echo "✓ Deployed $STACK_NAME"

# Show caller integration endpoints
echo ""
echo "=========================================="
echo "Caller Integration"
echo "=========================================="
LAMBDA_ARN=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
  --query 'Stacks[0].Outputs[?OutputKey==`BroadcastFunctionArn`].OutputValue' --output text 2>/dev/null)
QUEUE_URL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
  --query 'Stacks[0].Outputs[?OutputKey==`QueueUrl`].OutputValue' --output text 2>/dev/null)

echo "Lambda ARN (sync broadcast + sign-hash): $LAMBDA_ARN"
echo "SQS Queue URL (async broadcast):         $QUEUE_URL"
echo ""
echo "Sync invoke example:"
echo "  aws lambda invoke --function-name ${RESOURCE_PREFIX}-broadcast \\"
echo "    --cli-binary-format raw-in-base64-out \\"
echo "    --payload '{\"from\":\"0x...\",\"to\":\"0x...\",\"value\":\"0\"}' /dev/stdout"
