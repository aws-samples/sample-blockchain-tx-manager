#!/bin/bash
# Test concurrent transaction submission to verify nonce management and watcher
# Usage: ./scripts/test_concurrent_txs.sh <lambda_function_name> <from_address> <dynamodb_table> [num_txs]

set -e

LAMBDA_FUNCTION=${1:?Usage: $0 <lambda_function_name> <from_address> <dynamodb_table> [num_txs]}
FROM_ADDRESS=${2:?Usage: $0 <lambda_function_name> <from_address> <dynamodb_table> [num_txs]}
DYNAMODB_TABLE=${3:?Usage: $0 <lambda_function_name> <from_address> <dynamodb_table> [num_txs]}
NUM_TXS=${4:-5}

echo "Testing $NUM_TXS concurrent transactions from $FROM_ADDRESS"
echo "Lambda Function: $LAMBDA_FUNCTION"
echo "DynamoDB Table: $DYNAMODB_TABLE"
echo ""

# Create temp directory for results
RESULTS_DIR=$(mktemp -d)
echo "Results directory: $RESULTS_DIR"
echo ""

# Send transactions concurrently
echo "Sending $NUM_TXS transactions concurrently..."
for i in $(seq 1 $NUM_TXS); do
  (
    # Small value transfer to self (0.0001 ETH = 100000000000000 wei)
    aws lambda invoke \
      --function-name "$LAMBDA_FUNCTION" \
      --cli-binary-format raw-in-base64-out \
      --payload "{
        \"from\": \"$FROM_ADDRESS\",
        \"to\": \"$FROM_ADDRESS\",
        \"value\": \"100000000000000\"
      }" \
      "$RESULTS_DIR/tx_$i.json" > /dev/null
    RESPONSE=$(cat "$RESULTS_DIR/tx_$i.json")
    echo "TX $i: $RESPONSE"
  ) &
done

# Wait for all requests to complete
wait
echo ""
echo "All requests completed."
echo ""

# Analyze results
echo "=== Results Summary ==="
SUCCESS=0
FAILED=0
TX_HASHES=()
NONCES=()

for i in $(seq 1 $NUM_TXS); do
  RESULT=$(cat "$RESULTS_DIR/tx_$i.json")

  IS_SUCCESS=$(echo "$RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('success', False))" 2>/dev/null || echo "false")

  if [ "$IS_SUCCESS" = "True" ] || [ "$IS_SUCCESS" = "true" ]; then
    SUCCESS=$((SUCCESS + 1))
    TX_HASH=$(echo "$RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('txHash', 'unknown'))" 2>/dev/null)
    NONCE=$(echo "$RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('nonce', -1))" 2>/dev/null)
    TX_HASHES+=("$TX_HASH")
    NONCES+=("$NONCE")
    echo "TX $i: SUCCESS - nonce=$NONCE hash=$TX_HASH"
  else
    FAILED=$((FAILED + 1))
    ERROR=$(echo "$RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('error', 'unknown'))" 2>/dev/null || echo "$RESULT")
    echo "TX $i: FAILED - $ERROR"
  fi
done

echo ""
echo "=== Summary ==="
echo "Total: $NUM_TXS"
echo "Success: $SUCCESS"
echo "Failed: $FAILED"

# Check for duplicate nonces
if [ $SUCCESS -gt 0 ]; then
  echo ""
  echo "=== Nonce Analysis ==="
  mapfile -t SORTED_NONCES < <(printf '%s\n' "${NONCES[@]}" | sort -n)
  mapfile -t UNIQUE_NONCES < <(printf '%s\n' "${NONCES[@]}" | sort -n | uniq)

  if [ ${#SORTED_NONCES[@]} -eq ${#UNIQUE_NONCES[@]} ]; then
    echo "✓ All nonces are unique (no duplicates)"
  else
    echo "✗ DUPLICATE NONCES DETECTED!"
    printf '%s\n' "${SORTED_NONCES[@]}" | uniq -d
  fi

  # Check for sequential nonces
  EXPECTED_NONCE=${SORTED_NONCES[0]}
  SEQUENTIAL=true
  for n in "${SORTED_NONCES[@]}"; do
    if [ "$n" != "$EXPECTED_NONCE" ]; then
      SEQUENTIAL=false
      break
    fi
    EXPECTED_NONCE=$((EXPECTED_NONCE + 1))
  done

  if [ "$SEQUENTIAL" = true ]; then
    echo "✓ Nonces are sequential: ${SORTED_NONCES[0]} to $((EXPECTED_NONCE - 1))"
  else
    echo "✗ Nonces have gaps: ${SORTED_NONCES[*]}"
  fi
fi

# Check DynamoDB state
echo ""
echo "=== DynamoDB State Check ==="
echo "Checking transaction records in $DYNAMODB_TABLE..."

# Convert address to lowercase for DynamoDB lookup
FROM_ADDRESS_LOWER=$(echo "$FROM_ADDRESS" | tr '[:upper:]' '[:lower:]')

for hash in "${TX_HASHES[@]}"; do
  HASH_LOWER=$(echo "$hash" | tr '[:upper:]' '[:lower:]')
  RECORD=$(aws dynamodb get-item \
    --table-name "$DYNAMODB_TABLE" \
    --key "{\"wallet\": {\"S\": \"$FROM_ADDRESS_LOWER\"}, \"tx_hash\": {\"S\": \"$HASH_LOWER\"}}" \
    --query "Item" \
    --output json 2>/dev/null)

  if [ "$RECORD" != "null" ] && [ -n "$RECORD" ]; then
    STATUS=$(echo "$RECORD" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('status', {}).get('S', 'unknown'))" 2>/dev/null)
    NONCE=$(echo "$RECORD" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('nonce', {}).get('N', 'unknown'))" 2>/dev/null)
    echo "  $hash: status=$STATUS nonce=$NONCE"
  else
    echo "  $hash: NOT FOUND in DynamoDB"
  fi
done

# Wait for watcher to process and check state transitions
echo ""
echo "=== Watcher State Transition Test ==="
echo "Waiting 30 seconds for watcher to process transactions..."
sleep 30

echo "Checking final transaction states..."
PENDING=0
MINED=0
CONFIRMED=0
OTHER=0

for hash in "${TX_HASHES[@]}"; do
  HASH_LOWER=$(echo "$hash" | tr '[:upper:]' '[:lower:]')
  RECORD=$(aws dynamodb get-item \
    --table-name "$DYNAMODB_TABLE" \
    --key "{\"wallet\": {\"S\": \"$FROM_ADDRESS_LOWER\"}, \"tx_hash\": {\"S\": \"$HASH_LOWER\"}}" \
    --query "Item" \
    --output json 2>/dev/null)

  if [ "$RECORD" != "null" ] && [ -n "$RECORD" ]; then
    STATUS=$(echo "$RECORD" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('status', {}).get('S', 'unknown'))" 2>/dev/null)
    BLOCK=$(echo "$RECORD" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('block_number', {}).get('N', 'none'))" 2>/dev/null)
    CONFS=$(echo "$RECORD" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('confirmations', {}).get('N', '0'))" 2>/dev/null)

    case "$STATUS" in
      pending|PENDING) PENDING=$((PENDING + 1)) ;;
      mined|MINED) MINED=$((MINED + 1)) ;;
      confirmed|CONFIRMED) CONFIRMED=$((CONFIRMED + 1)) ;;
      *) OTHER=$((OTHER + 1)) ;;
    esac

    echo "  $hash: status=$STATUS block=$BLOCK confirmations=$CONFS"
  fi
done

echo ""
echo "=== State Transition Summary ==="
echo "Pending: $PENDING"
echo "Mined: $MINED"
echo "Confirmed: $CONFIRMED"
echo "Other: $OTHER"

if [ $MINED -gt 0 ] || [ $CONFIRMED -gt 0 ]; then
  echo "✓ Watcher is processing transactions (state transitions detected)"
else
  echo "⚠ No state transitions detected - watcher may not be running or transactions not yet mined"
fi

# Cleanup
rm -rf "$RESULTS_DIR"

echo ""
echo "Done. Check transactions on Etherscan:"
for hash in "${TX_HASHES[@]}"; do
  echo "  https://sepolia.etherscan.io/tx/$hash"
done
