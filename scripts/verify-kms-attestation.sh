#!/usr/bin/env bash
#
# Verify that the KMS key policy enforces enclave attestation.
#
# The key policy is owned by CDK (nitro_wallet_stack.py::_grant_enclave_only_decrypt),
# not by this script. Attestation is enforced by a Deny statement, and an out-of-band
# `aws kms put-key-policy` would be silently reverted by the next `cdk deploy` — which is
# exactly the false-assurance failure this script used to have. So this script no longer
# mutates anything. It reads the deployed state and tells you whether the enclave boundary
# is actually enforced.
#
# To change the enforced measurement, redeploy with the PCR0 as context:
#   cdk deploy <stack> --context deployment=dev --context pcr0=<96-hex-chars>
#
# Usage:
#   ./scripts/verify-kms-attestation.sh            # report enforced state, print PCR0 from the enclave
#   ./scripts/verify-kms-attestation.sh <pcr0>     # additionally assert the policy enforces <pcr0>
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

ATTESTATION_KEY="kms:RecipientAttestation:ImageSha384"

# Source .nitro-config for REGION and stack info
if [[ -f "$ROOT_DIR/.nitro-config" ]]; then
    # shellcheck source=/dev/null
    source "$ROOT_DIR/.nitro-config"
else
    echo "Error: .nitro-config not found. Run deploy-nitro-stack.sh first." >&2
    exit 1
fi

STACK_NAME="${STACK_NAME:-devNitroWalletEth}"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"

echo "Fetching stack outputs..."
OUTPUTS=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query 'Stacks[0].Outputs' --output json)
KMS_KEY_ID=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey == "KMSKeyID") | .OutputValue')
EC2_ROLE_ARN=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey == "EC2InstanceRoleARN") | .OutputValue')

if [[ -z "$KMS_KEY_ID" || "$KMS_KEY_ID" == "null" ]]; then
    echo "Error: Could not get KMS Key ID from stack $STACK_NAME" >&2
    exit 1
fi

echo "KMS Key ID:   $KMS_KEY_ID"
echo "EC2 Role ARN: $EC2_ROLE_ARN"
echo ""

CURRENT_POLICY=$(aws kms get-key-policy --key-id "$KMS_KEY_ID" --region "$REGION" --policy-name default --query 'Policy' --output text)

# --- Check 1: the Deny that actually enforces attestation must be present. -------------
# With PCR0, the Deny has StringNotEqualsIfExists and permits only an exact attested
# match to fall through. Before PCR0 exists, CDK deliberately emits an unconditional
# Deny on Decrypt + GenerateDataKey: nobody (including an enclave) can create/decrypt a
# wallet. That bootstrap state is fail-closed and must be reported distinctly.
DENY=$(echo "$CURRENT_POLICY" | jq -r --arg k "$ATTESTATION_KEY" '
    [ .Statement[]
      | select(.Effect == "Deny")
      | select((.Action | if type == "array" then . else [.] end) | index("kms:Decrypt"))
      | select(.Condition."StringNotEqualsIfExists"[$k] != null)
    ] | first // empty
')
BOOTSTRAP_DENY=$(echo "$CURRENT_POLICY" | jq -r '
    [ .Statement[]
      | select(.Effect == "Deny")
      | select(.Condition == null)
      | select((.Action | if type == "array" then . else [.] end) | index("kms:Decrypt"))
      | select((.Action | if type == "array" then . else [.] end) | index("kms:GenerateDataKey"))
    ] | first // empty
')

if [[ -z "$DENY" && -z "$BOOTSTRAP_DENY" ]]; then
    echo "FAIL: no attestation/bootstrap Deny found on the key policy." >&2
    echo "Redeploy the Nitro stack from the current template before generating a wallet." >&2
    exit 1
fi

EXPECTED_PCR0="${1:-}"
if [[ -z "$DENY" ]]; then
    echo "Bootstrap state: unconditional Deny on kms:Decrypt and kms:GenerateDataKey."
    echo "No wallet can be generated or decrypted until the measured PCR0 is redeployed."
    if [[ -n "$EXPECTED_PCR0" ]]; then
        echo "FAIL: expected PCR0 $EXPECTED_PCR0, but the policy is still bootstrap-deny-all." >&2
        exit 1
    fi
    echo ""
    echo "✓ Unmeasured Nitro deployment fails closed."
    exit 0
fi

ENFORCED_PCR0=$(echo "$DENY" | jq -r --arg k "$ATTESTATION_KEY" '.Condition."StringNotEqualsIfExists"[$k]')
echo "Enforced measurement (from Deny): $ENFORCED_PCR0"

# --- Check 2: no unconditioned Allow may grant decrypt. --------------------------------
# A Deny wins over any Allow, so an unconditioned Allow cannot defeat the control above.
# It is still reported: it means someone re-added the grant this fix removed, the intent
# is now contradictory, and the next policy edit may drop the Deny and leave the Allow.
UNCONDITIONED=$(echo "$CURRENT_POLICY" | jq -r --arg k "$ATTESTATION_KEY" '
    [ .Statement[]
      | select(.Effect == "Allow")
      | select((.Action | if type == "array" then . else [.] end)
               | any(. == "kms:Decrypt" or . == "kms:*" or . == "*"))
      | select(.Condition == null or .Condition."StringEqualsIgnoreCase"[$k] == null)
      # CDK default key-administration statement: account root, kms:*. Expected, and
      # overridden by the Deny for decrypt; only report grants to other principals.
      | select((.Principal.AWS // "" | if type == "array" then . else [.] end)
               | all(test(":root$")) | not)
      | .Sid // "(no Sid)"
    ] | join(", ")
')

if [[ -n "$UNCONDITIONED" ]]; then
    echo ""
    echo "WARNING: unconditioned decrypt Allow present: $UNCONDITIONED"
    echo "  The Deny above still takes precedence, so decrypt is enforced today. But this"
    echo "  grant contradicts it and should be removed — check for a reintroduced"
    echo "  encryption_key.grant(role, \"kms:Decrypt\") in nitro_wallet_stack.py."
fi

# --- Check 3: compare against the measurement the enclave actually reports. ------------
if [[ -z "$EXPECTED_PCR0" ]]; then
    echo ""
    echo "Fetching PCR0 from the running enclave for comparison..."
    ASG_NAME=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey == "ASGGroupName") | .OutputValue')
    INSTANCE_ID=$(aws autoscaling describe-auto-scaling-groups \
        --region "$REGION" \
        --auto-scaling-group-names "$ASG_NAME" \
        --query 'AutoScalingGroups[0].Instances[0].InstanceId' \
        --output text)

    echo "Instance: $INSTANCE_ID"
    COMMAND_ID=$(aws ssm send-command \
        --region "$REGION" \
        --instance-ids "$INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters 'commands=["nitro-cli describe-enclaves | jq -r \".[0].Measurements.PCR0\""]' \
        --query 'Command.CommandId' \
        --output text)

    sleep 3
    REPORTED_PCR0=$(aws ssm get-command-invocation \
        --region "$REGION" \
        --command-id "$COMMAND_ID" \
        --instance-id "$INSTANCE_ID" \
        --query 'StandardOutputContent' \
        --output text | tr -d '\n' | tr '[:upper:]' '[:lower:]')

    # The parent instance is untrusted, so a value it reports is an aid for spotting a
    # stale policy after an enclave rebuild — never evidence that the enclave is genuine.
    echo "Reported by parent instance:      ${REPORTED_PCR0:-<none>}"
    echo ""
    echo "NOTE: that value came from the parent instance, which this architecture treats"
    echo "      as untrusted. Use it to notice a stale policy, not to establish trust."
    echo "      Derive the authoritative value from the EIF you built:"
    echo "        nitro-cli describe-eif --eif-path <path> | jq -r .Measurements.PCR0"
    EXPECTED_PCR0="$REPORTED_PCR0"
fi

if [[ -n "$EXPECTED_PCR0" && "$EXPECTED_PCR0" != "null" ]]; then
    if [[ "$(echo "$EXPECTED_PCR0" | tr '[:upper:]' '[:lower:]')" != "$(echo "$ENFORCED_PCR0" | tr '[:upper:]' '[:lower:]')" ]]; then
        echo ""
        echo "FAIL: policy enforces a different measurement than expected." >&2
        echo "  enforced: $ENFORCED_PCR0" >&2
        echo "  expected: $EXPECTED_PCR0" >&2
        echo "" >&2
        echo "  Signing will fail closed (AccessDenied) until these agree. Redeploy with:" >&2
        echo "    cdk deploy $STACK_NAME --context deployment=<env> --context pcr0=$EXPECTED_PCR0" >&2
        exit 1
    fi
    echo ""
    echo "✓ Enforced measurement matches."
fi

echo ""
echo "✓ Attestation is enforced by an explicit Deny on kms:Decrypt."
echo ""
echo "Confirm from the parent instance — this must fail with AccessDenied:"
echo "  aws kms decrypt --key-id $KMS_KEY_ID --region $REGION \\"
echo "    --ciphertext-blob fileb://<(printf 'not-a-real-ciphertext') 2>&1 | head -1"
echo ""
echo "An AccessDenied that cites the explicit Deny is the passing result. An"
echo "InvalidCiphertextException means the call was AUTHORIZED and only the payload was"
echo "rejected — that is a failure: it proves the parent can decrypt outside the enclave."
