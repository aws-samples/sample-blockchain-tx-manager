# Dynamic EIP-1559 Fees and Same-Nonce Replacement

Status: **implemented and Sepolia-canary validated** (2026-09-14). This is a reference
implementation; customers must set and validate their own fee, replacement, cancellation,
and risk policy.

## 1. Problem and invariants

A `PENDING` transaction whose cap falls below the live base fee can never be mined.
Exact-byte re-injection handles mempool eviction, but cannot change its economics; the
wallet remains blocked at that nonce until a replacement is mined.

The replacement path must preserve these invariants:

1. DynamoDB remains the sole nonce/lifecycle authority; one nonce family consumes one
   pending slot regardless of candidate count.
2. The watcher never obtains signing permission. It may request the next policy-authorized
   generation, but cannot choose transaction content or fees.
3. A speed-up preserves chain ID, nonce, destination, value, calldata, access list, and gas
   limit. A cancel is always a zero-value self-transfer at the same nonce.
4. Every replacement is receipt- and nonce-gated, idempotent per generation, and bounded by
   deployment hard limits fixed before signing.
5. All candidate hashes remain tracked because an earlier candidate may still win.

## 2. Evidence and industry alignment

The design was checked against current authoritative and production-facing sources:

- [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559): the cap must cover the current
  base fee; wallets are expected to estimate base and priority fees automatically.
- [Alchemy `eth_feeHistory`](https://www.alchemy.com/docs/chains/ethereum/ethereum-api-endpoints/eth-fee-history):
  live base fees and gas-weighted priority-fee percentiles.
- [Geth transaction-pool options](https://geth.ethereum.org/docs/fundamentals/command-line-options):
  `txpool.pricebump` defaults to 10%.
- [MetaMask replacement guidance](https://support.metamask.io/manage-crypto/transactions/how-to-speed-up-or-cancel-a-pending-transaction/):
  explicit speed-up/cancel; priority fee at least 10% higher and max fee about 30% higher.
- [OpenZeppelin Relayer v1.5](https://docs.openzeppelin.com/relayer/1.5.x/evm) and its
  [replace API](https://docs.openzeppelin.com/relayer/1.5.x/api/replaceTransaction): live
  network pricing, speed tiers, dynamic replacement, protected signers, and gas-price caps.
- [Fireblocks Boost Transactions](https://developers.fireblocks.com/reference/boost-transactions):
  dynamic same-nonce RBF by stuck transaction, with Drop as a separate explicit operation.

Documented industry practice supports live estimation, dynamic just-in-time replacement,
increasing both EIP-1559 fields, explicit cancellation, protected signers, and operator fee
caps. The SQS/Lambda split, hold-and-alarm default, and total-fee cap are repository-specific
least-privilege/safety choices. Percentiles and block cadence are tunable product defaults,
not Ethereum standards.

## 3. Request and deployment policy

A caller may provide either explicit EIP-1559 fees or a speed tier:

```json
{
  "feeSpeed": "slow | standard | fast",
  "replacementPolicy": {
    "bumpEveryBlocks": 5,
    "maxBumps": 3,
    "onExhaust": "hold | cancel",
    "maxFeePerGasWei": "150000000000",
    "maxTotalFeeWei": "15000000000000000"
  }
}
```

- `feeSpeed` and an explicit fee pair are alternatives for initial pricing. Live-tier
  requests are replacement-managed by default. An explicit-fee request must also supply
  `replacementPolicy` to opt in; omission preserves its exact fee intent and creates no
  family.
- Per-request `signerCredentials` cannot opt into replacement until signer routing can be
  reproduced safely by the internal worker; such a request is otherwise broadcast-only.
- The replacement policy is immutable after the nonce is reserved.
- Request ceilings may override defaults in either direction but must not exceed deployment
  hard maxima.
- Production deploys require hard per-gas and total-fee maxima. Any initial transaction that
  cannot be admissible under both is rejected before nonce reservation.

Deployment policy:

```text
defaultMaxFeePerGasWei
defaultMaxTotalFeeWei
hardMaxFeePerGasWei
hardMaxTotalFeeWei
maxReplacementAttempts
replacementEnabled
```

## 4. Initial fee estimation

All tiers are immediately admissible; below-base scheduling is deliberately out of scope.
Scheduling before nonce reservation is a separate future feature.

Query `eth_feeHistory` over the latest 20 blocks with reward percentiles `[25, 50, 75]`.
Use the median non-zero reward at the tier's percentile, subject to a configurable per-chain
tip floor. If fee history is unavailable, use `eth_maxPriorityFeePerGas`; failure of both
fails the request before reservation.

| Speed | Priority percentile | Base-fee headroom | Default bump cadence |
|---|---:|---:|---:|
| `slow` | 25th | 1.00x | 20 blocks |
| `standard` | 50th | 1.25x | 5 blocks |
| `fast` | 75th | 1.50x | 3 blocks |

```text
priority = max(livePercentileTip, chainTipFloor)
maxFee   = ceil(pendingBaseFee * headroomMultiplier) + priority
```

The percentiles, floors, multipliers, and cadence are configuration defaults to tune from
inclusion-latency metrics; they are not claimed as universal industry constants.

## 5. Dynamic replacement calculation

The watcher may request generation `g + 1` only when all are true:

- the active family has no canonical receipt;
- the chain's latest nonce has not passed the family nonce;
- `currentBlock >= nextEligibleReplacementBlock`;
- the family has no replacement generation currently claimed;
- `g < maxBumps` (otherwise apply exhaustion policy).

The replacement Lambda queries live fee data and calculates:

```text
newPriority = max(
  ceil(previousPriority * 1.125),
  current percentile tip for the stored speed tier,
  chain tip floor
)

newMaxFee = max(
  ceil(previousMaxFee * 1.30),
  ceil(currentPendingBaseFee * stored headroom multiplier) + newPriority
)
```

Before signing:

```text
newMaxFee <= effectiveRequestPerGasCeiling <= deploymentHardPerGasCeiling
gasLimit * newMaxFee <= effectiveRequestTotalCeiling <= deploymentHardTotalCeiling
```

A ceiling failure does not mutate the active candidate. The family becomes
`REPLACEMENT_EXHAUSTED`, emits a metric/alarm, and follows `onExhaust`.

## 6. Architecture and authorization

```text
Watcher
  -> conditional DynamoDB claim for (family, next generation, eligible block)
  -> internal replacement SQS queue
  -> dedicated replacement Lambda
  -> reload immutable family + active candidate
  -> re-check receipt, nonce, generation, cadence, and ceilings
  -> estimate live fees
  -> reconstruct, simulate (speed-up only), sign through Nitro
  -> atomically append candidate + advance active generation
  -> broadcast and classify send outcome
```

Security boundaries:

- The watcher role may send only to the internal replacement queue; it cannot assume the
  Nitro client role or invoke the replacement function directly.
- Queue messages contain only family identity, expected generation, and requested action.
- Only the replacement Lambda may consume the queue and assume the Nitro client role.
- The Lambda ignores caller-supplied transaction content/fees and reconstructs from DynamoDB.
- The DynamoDB conditional claim, not the watcher clock, enforces generation and cadence.
- The queue has its own DLQ, bounded retries, age/depth alarms, and batch size one.

## 7. Family state and atomicity

One transaction-family control row is keyed by wallet and `family#<nonce>`. It stores the
immutable unsigned intent and policy, active generation/hash, previous fees, next eligible
block, claim state, and terminal outcome. Candidate transaction rows remain keyed by their
real hash and carry `family_id` and `replacement_generation`.

Only the active candidate carries `status=PENDING`/`SIGNED` and appears in the sparse status
GSI. On successful replacement activation, one DynamoDB transaction:

1. conditionally advances the family generation and active hash;
2. marks the previous candidate inactive while retaining its active status for receipt
   tracking (an earlier hash may still win);
3. writes the new `SIGNED` candidate with exact signed bytes.

At the existing reorg-finality boundary, the winner terminalizes the family and every
still-active losing sibling becomes `REPLACED` with TTL and leaves the GSI.

The first canonical receipt among any family candidate wins. Receipt finalization advances
the nonce once, marks the winner `MINED`/`CONFIRMED`, and terminates all siblings. A foreign
hash consuming the nonce marks the whole family `DROPPED`. `pending_count` is decremented
exactly once for the family.

A queue redelivery is safe: the family generation/claim condition makes an already-created
candidate a no-op and returns its stored hash.

## 8. Exhaustion and cancellation

Default `onExhaust` is `hold`:

- no more signatures are created;
- the latest exact bytes may continue rate-limited re-injection;
- receipt/nonce tracking continues;
- `ReplacementPolicyExhausted` is emitted and alarmed;
- the nonce and pending slot are never released merely because the policy exhausted.

Cancellation is opt-in either in the immutable initial policy or through a separately
authorized operator request. It creates a dynamic same-nonce zero-value self-transfer to the
wallet with gas limit 21,000 and the same hard ceilings. Cancellation is only an attempt: an
earlier candidate may mine first, and a ceiling below the live base fee can prevent it.

If a cancel wins, its row becomes `CONFIRMED`, the original intent is reported
`REPLACED_BY_CANCEL`, and the nonce family finalizes once.

## 9. Observability and rollout gates

Emit at minimum:

- `ReplacementRequested`, `ReplacementBroadcast`, `ReplacementConfirmed`;
- `ReplacementUnderpriced`, `ReplacementPolicyExhausted`, `ReplacementQueueDlqDepth`;
- dimensions: chain ID, speed tier, action, generation (no wallet/hash dimensions).

Canary acceptance:

1. live speed estimates are admissible and remain within both hard limits;
2. a controlled unbroadcast `PENDING` candidate is dynamically replaced at the same nonce;
3. replacement changes only fees/hash and preserves the immutable intent;
4. duplicate queue delivery creates no second generation;
5. replacement confirms and final nonce/confirmed/pending invariants hold;
6. exhaustion at a deliberately low ceiling signs nothing and alarms;
7. default hold never creates a cancel; explicit cancel uses self/zero/21,000;
8. watcher remains unable to assume the Nitro role; logs contain no RPC URLs.
