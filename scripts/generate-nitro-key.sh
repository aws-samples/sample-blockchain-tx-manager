#!/usr/bin/env bash
#
# Generate a new Ethereum key inside the Nitro Enclave
#
# Usage:
#   ./scripts/generate-nitro-key.sh <secret_name>
#
# Examples:
#   ./scripts/generate-nitro-key.sh sepolia-personal
#   ./scripts/generate-nitro-key.sh treasury
#
# Keys are stored under nitro-wallet/ prefix in Secrets Manager (auto-added).
#
# This invokes the signing service through its Lambda rather than calling the service
# directly. The service authenticates every request against an allowlist of IAM principals,
# and the Lambda's role is the principal on that list; a direct `curl` from the instance is
# rejected and cannot be made to work by hand. The Lambda also writes the secret itself, so
# the encrypted key never transits this machine.
#
# You need permission to invoke that Lambda. The wallet's address is printed once, here —
# record it, because nothing else stores the mapping from secret name to address.
#

set -euo pipefail

SECRET_NAME="${1:-}"

if [[ -z "$SECRET_NAME" ]]; then
    echo "Usage: $0 <secret_name>"
    echo ""
    echo "Example: $0 sepolia-personal"
    echo ""
    echo "Keys are stored under the nitro-wallet/ prefix in Secrets Manager."
    echo "The prefix is added automatically if not already present."
    exit 1
fi

# Ensure nitro-wallet/ prefix (required by IAM policy)
if [[ "$SECRET_NAME" != nitro-wallet/* ]]; then
    SECRET_NAME="nitro-wallet/$SECRET_NAME"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

command -v aws >/dev/null 2>&1 || { echo "Error: aws CLI not found"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq not found"; exit 1; }

# Load config
if [[ -f "$ROOT_DIR/.nitro-config" ]]; then
    source "$ROOT_DIR/.nitro-config"
else
    echo "Error: .nitro-config not found. Run deploy-nitro-stack.sh first."
    exit 1
fi

STACK_NAME="${STACK_NAME:-devNitroWalletEth}"
REGION="${REGION:-us-east-1}"

echo "Generating key in Nitro Enclave..."
echo "Secret name: $SECRET_NAME"
echo ""

# The Lambda refuses to overwrite an existing secret, since it may hold the only copy of a
# funded wallet's key. Checking here too turns that into a clear message before the invoke.
if aws secretsmanager describe-secret --secret-id "$SECRET_NAME" --region "$REGION" \
    >/dev/null 2>&1; then
    echo "Error: secret '$SECRET_NAME' already exists."
    echo ""
    echo "Refusing to continue. This secret may hold the only copy of a funded wallet's"
    echo "encrypted key, and overwriting it would make those funds permanently"
    echo "inaccessible. There is no rotate-in-place path: a wallet's address is derived"
    echo "from its key, so a new key means a new address. Choose a different name."
    exit 1
fi

echo "Resolving the signing Lambda..."
FUNCTION_NAME=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`LambdaFunctionName`].OutputValue' --output text)

if [[ -z "$FUNCTION_NAME" || "$FUNCTION_NAME" == "None" ]]; then
    echo "Error: stack '$STACK_NAME' has no LambdaFunctionName output."
    echo "Redeploy with scripts/deploy-nitro-stack.sh to publish it."
    exit 1
fi

echo "Invoking $FUNCTION_NAME..."

RESPONSE_FILE=$(mktemp)
trap 'rm -f "$RESPONSE_FILE"' EXIT

# --cli-binary-format is required for a raw JSON payload on AWS CLI v2.
STATUS=$(aws lambda invoke \
    --region "$REGION" \
    --function-name "$FUNCTION_NAME" \
    --cli-binary-format raw-in-base64-out \
    --payload "$(jq -nc --arg name "$SECRET_NAME" \
        '{operation: "generate_key", secret_name: $name}')" \
    --query 'FunctionError' --output text \
    "$RESPONSE_FILE")

RESPONSE=$(cat "$RESPONSE_FILE")

# A Lambda that raises still returns HTTP 200 with FunctionError set, so the exit status of
# the invoke says nothing about whether the key was generated.
if [[ "$STATUS" != "None" ]]; then
    echo "Error: key generation failed."
    echo "$RESPONSE" | jq -r '.errorMessage // .' 2>/dev/null || echo "$RESPONSE"
    exit 1
fi

ADDRESS=$(echo "$RESPONSE" | jq -r '.address // empty')

if [[ -z "$ADDRESS" ]]; then
    echo "Error: unexpected response from the Lambda:"
    echo "$RESPONSE"
    exit 1
fi

echo ""
echo "=========================================="
echo "Key Generated Successfully"
echo "=========================================="
echo ""
echo "Address:     $ADDRESS"
echo "Secret Name: $SECRET_NAME"
echo ""
echo "Record the address. The encrypted key is in Secrets Manager, but nothing stores"
echo "which address it belongs to, and it cannot be recovered from the ciphertext"
echo "outside the enclave."
echo ""
echo "To sign with this wallet, deploy the signing service with"
echo "NITRO_SECRET_ID=$SECRET_NAME. The service signs with one configured wallet;"
echo "callers do not choose it per request."
