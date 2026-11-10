//! Main request handler

use crate::config::LambdaConfig;
use crate::error::{LambdaError, Result};
use crate::fees::estimate_live_fees;
use crate::idempotency::{ClaimOutcome, IdempotencyClaim};
use crate::signing::SignerProvider;
use crate::tx::{
    TxParams, build_unsigned_tx, compute_local_tx_hash, encode_signed_tx, get_signing_hash,
};
use crate::types::{SignHashRequest, SignHashResponse, TxRequest, TxResponse};
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use aws_sdk_dynamodb::Client as DynamoClient;
use nonce_manager::{
    DynamoNonceManager, ExhaustionAction, FeeSpeed, NonceManagerConfig, ReplacementFamilyInit,
    ResolvedReplacementPolicy, SendRejection, classify_send_error,
};
use once_cell::sync::OnceCell;
use std::sync::Arc;
use tokio::sync::OnceCell as TokioOnceCell;
use tracing::{debug, error, info, warn};

static CONFIG: TokioOnceCell<LambdaConfig> = TokioOnceCell::const_new();
static DYNAMO: TokioOnceCell<DynamoClient> = TokioOnceCell::const_new();
static SIGNER_PROVIDER: TokioOnceCell<SignerProvider> = TokioOnceCell::const_new();
static RPC_PROVIDER: OnceCell<Arc<DynProvider>> = OnceCell::new();

pub(crate) async fn get_config() -> Result<&'static LambdaConfig> {
    CONFIG
        .get_or_try_init(|| async { LambdaConfig::load().await.map_err(LambdaError::Config) })
        .await
}

/// Process-wide RPC provider. The RPC URL is fixed for the life of the process, so the
/// HTTP client (connection pool, TLS session) is built once and reused across warm
/// invocations instead of paying a fresh TCP+TLS handshake on every request.
pub(crate) fn get_rpc_provider(config: &LambdaConfig) -> Result<Arc<DynProvider>> {
    RPC_PROVIDER
        .get_or_try_init(|| {
            let rpc_url = config
                .eth_rpc_url
                .parse()
                .map_err(|e| LambdaError::Config(format!("Invalid RPC URL: {}", e)))?;
            Ok(Arc::new(
                ProviderBuilder::new().connect_http(rpc_url).erased(),
            ))
        })
        .cloned()
}

pub(crate) async fn get_dynamo() -> Result<&'static DynamoClient> {
    DYNAMO
        .get_or_try_init(|| async {
            let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            Ok(DynamoClient::new(&aws_config))
        })
        .await
        .map_err(|e: LambdaError| e)
}

pub(crate) async fn get_signer_provider() -> Result<&'static SignerProvider> {
    SIGNER_PROVIDER
        .get_or_try_init(|| async {
            SignerProvider::from_env()
                .await
                .map_err(|e| LambdaError::Signer(e.to_string()))
        })
        .await
        .map_err(|e: LambdaError| e)
}

/// Handle a transaction request
pub async fn handle_request(request: TxRequest) -> Result<TxResponse> {
    let config = get_config().await?;

    // Request-boundary validation runs before any DynamoDB, idempotency, or nonce work.
    // A rejection here is a non-retryable INVALID_REQUEST response, never a panic.
    let idempotency_key = match validate_broadcast_request(&request, config) {
        Ok(key) => key,
        Err(response) => return Ok(response),
    };

    info!(from = ?request.from, to = ?request.to, value = %request.value, "Processing TX");

    let dynamo = get_dynamo().await?;

    // Claim the idempotency key before any nonce reservation so an at-least-once
    // redelivery can never reserve a second nonce and double-broadcast.
    let claim = idempotency_claim(&request, idempotency_key, config, dynamo);
    match claim.claim(config.ttl_days).await? {
        ClaimOutcome::Claimed => debug!("Idempotency key claimed"),
        ClaimOutcome::Duplicate(resp) => {
            info!(from = ?request.from, "Duplicate request short-circuited by idempotency key");
            return Ok(resp);
        }
    }

    // Run the broadcast pipeline, then settle the claim from a single place so
    // every exit path (including early `?` errors) finalizes or releases it.
    let result = broadcast_pipeline(&request, config, dynamo, &claim).await;
    settle_claim(&claim, &result).await;
    result
}

/// Reserve a nonce, simulate, sign, durably record, then broadcast the transaction.
///
/// The flow is strictly ordered around a single durable handoff:
///
/// ```text
/// reserve (lazy-seeds wallet state) -> simulate -> build/sign/encode
///   -> local_hash = keccak256(exact EIP-2718 signed bytes)
///   -> record_signed(exact bytes/hash/fees)      [DURABLE SIGNED HANDOFF]
///   -> send_raw_transaction(exact same bytes)
///   -> mark_broadcast
/// ```
///
/// Any failure **before** `record_signed` succeeds releases the reservation (guarded:
/// only a still-`RESERVED` reservation is recycled). Once `record_signed` succeeds the
/// reservation is `SIGNED`, the exact bytes are durable, and this request never releases
/// or signs again — every later outcome returns an accepted response (or a hash-mismatch
/// error) and leaves recovery to the watcher, which rebroadcasts the identical bytes.
///
/// Returns `Ok(accepted)` for the durable-handoff-complete paths; pre-handoff failures
/// return either `Ok(pre_broadcast_error)` or `Err`, both of which are safe for
/// [`settle_claim`] to release.
async fn broadcast_pipeline(
    request: &TxRequest,
    config: &LambdaConfig,
    dynamo: &DynamoClient,
    claim: &IdempotencyClaim<'_>,
) -> Result<TxResponse> {
    // Resolve signer via the unified SignerProvider
    let credentials = request.signer_credentials.clone();
    let signer_provider = get_signer_provider().await?;
    let signer = signer_provider
        .get_signer_with_credentials(request.from, credentials.as_ref())
        .await
        .map_err(|e| LambdaError::Signer(e.to_string()))?;

    info!(backend = %signer.info().backend, "Using signing backend");

    // Process-cached provider without wallet — all backends use raw tx broadcast.
    let provider = get_rpc_provider(config)?;

    // Chain pinning: the deployment's configured chain is authoritative. Any request
    // `chainId` was already validated to be absent or equal at the request boundary, so
    // the manager and the signed transaction are always built with `config.chain_id`.
    let chain_id = config.chain_id;

    // Build the DynamoDB-backed nonce authority from the existing Dynamo client + the
    // per-chain tracker table. DynamoDB is the sole nonce authority (no Redis).
    let manager = DynamoNonceManager::new(
        dynamo.clone(),
        config.dynamodb_table.as_str(),
        provider.clone(),
        chain_id,
        NonceManagerConfig::default(),
    );

    // Wallet nonce state is seeded lazily: `reserve_nonce` initializes from the chain
    // only when the nonce-state row is missing. There is deliberately no per-request
    // chain reconcile here — it cost two RPCs plus several DynamoDB writes on every
    // broadcast, and raising `confirmed_nonce` past in-flight reservations from the
    // hot path is what once leaked `pending_count`. Reconciliation belongs to the
    // watcher's recovery sweep and to the explicit `force_sync` operation.

    // Resolve gas up front so a gas failure never strands a reservation. A gas
    // short-circuit is a pre-broadcast error the claim may release cleanly.
    let gas = match resolve_gas_params(provider.as_ref(), request, config).await? {
        GasOutcome::Ready(gas) => gas,
        GasOutcome::ShortCircuit(resp) => return Ok(resp),
    };

    // Step 1: reserve a nonce atomically (seeds wallet state from chain if missing).
    let nonce = match manager.reserve_nonce(request.from).await {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "Nonce reservation failed");
            return Ok(TxResponse::error_with_code(
                e.to_string(),
                "NONCE_EXHAUSTED",
                true,
            ));
        }
    };
    debug!(wallet = ?request.from, nonce, "Nonce reserved");

    // Step 2: simulate via eth_call. This precedes signing, so a revert releases the
    // reservation (guarded) and returns a pre-broadcast error.
    let sim_tx = TransactionRequest::default()
        .from(request.from)
        .to(request.to)
        .value(request.value)
        .nonce(nonce)
        .input(request.data.clone().into());
    if let Err(e) = provider.call(sim_tx).await {
        let e = redact_urls(&e.to_string());
        warn!(nonce, error = %e, "Simulation reverted");
        release_reserved(&manager, request.from, nonce).await;
        return Ok(TxResponse::error_with_code(
            format!("Simulation reverted: {e}"),
            "SIMULATION_FAILED",
            false,
        ));
    }
    debug!(nonce, "Simulation passed");

    // Step 3: build the unsigned EIP-1559 tx, sign its signing hash, encode signed bytes.
    let tx_params = TxParams {
        chain_id,
        nonce,
        to: request.to,
        value: request.value,
        data: request.data.clone(),
        gas_limit: gas.gas_limit,
        max_fee_per_gas: gas.max_fee,
        max_priority_fee_per_gas: gas.max_priority_fee,
    };
    let unsigned_tx = build_unsigned_tx(&tx_params);
    let signing_hash = get_signing_hash(&unsigned_tx);
    debug!(hash = ?signing_hash, "Signing hash computed");

    let signature = match signer.sign_hash(signing_hash).await {
        Ok(sig) => match verify_signature(&sig, signing_hash, request.from) {
            Ok(sig) => sig,
            Err(e) => {
                error!(nonce, error = %e, backend = %signer.info().backend, "Signature verification failed");
                release_reserved(&manager, request.from, nonce).await;
                return Err(LambdaError::Signer(e));
            }
        },
        Err(e) => {
            warn!(nonce, error = %e, "Signing failed");
            release_reserved(&manager, request.from, nonce).await;
            return Err(LambdaError::Signer(e.to_string()));
        }
    };
    let signed_tx_bytes = encode_signed_tx(&unsigned_tx, &signature);
    debug!(tx_len = signed_tx_bytes.len(), "Signed transaction encoded");

    // Step 4: compute the local tx hash from the EXACT bytes we will broadcast.
    let local_hash = compute_local_tx_hash(&signed_tx_bytes);

    // Step 5: durably record the signed tx BEFORE any send. This is the recovery
    // handoff. `record_signed` is a single atomic TransactWriteItems, so a failure
    // leaves no durable row and the reservation still RESERVED — release (guarded) and
    // let a redelivery retry cleanly.
    let record_result = if let (Some(policy), Some(current_block)) =
        (gas.replacement_policy.clone(), gas.current_block)
    {
        let family = ReplacementFamilyInit {
            to: request.to,
            value: request.value,
            data: request.data.clone(),
            gas_limit: gas.gas_limit,
            policy,
            current_block,
            max_fee_per_gas: gas.max_fee,
            max_priority_fee_per_gas: gas.max_priority_fee,
        };
        manager
            .record_signed_with_family(
                request.from,
                nonce,
                local_hash,
                &signed_tx_bytes,
                U256::from(gas.max_fee),
                U256::from(gas.max_priority_fee),
                &family,
            )
            .await
    } else {
        manager
            .record_signed(
                request.from,
                nonce,
                local_hash,
                &signed_tx_bytes,
                None,
                Some(U256::from(gas.max_fee)),
                Some(U256::from(gas.max_priority_fee)),
            )
            .await
    };
    if let Err(e) = record_result {
        error!(nonce, tx_hash = ?local_hash, error = %e, "Failed to durably record signed tx before broadcast");
        release_reserved(&manager, request.from, nonce).await;
        return Err(LambdaError::NonceManager(e));
    }
    info!(nonce, tx_hash = ?local_hash, "Signed tx durably recorded (SIGNED); broadcasting");

    // ---- DURABLE SIGNED HANDOFF COMPLETE ----
    // Never release the reservation or sign another tx for this request from here on.

    // Fix the caller-visible result on the idempotency claim now. If this invocation
    // dies anywhere below, a redelivery finds HANDED_OFF and returns the same accepted
    // response instead of retrying into the DLQ. Best effort: on failure the claim stays
    // IN_PROGRESS, which is the previous (retry) behaviour.
    if let Err(e) = claim.record_handoff(local_hash, nonce).await {
        warn!(nonce, tx_hash = ?local_hash, error = %e, "Failed to record idempotency handoff");
    }

    // Step 6: broadcast the EXACT same bytes. No in-invocation retry — exact-byte
    // rebroadcast is the watcher's job.
    let send_result: std::result::Result<B256, String> = provider
        .send_raw_transaction(&signed_tx_bytes)
        .await
        .map(|pending| *pending.tx_hash())
        .map_err(|e| redact_urls(&e.to_string()));

    match classify_send_outcome(local_hash, &send_result) {
        PostSend::Accepted { mark_broadcast } => {
            if let Err(e) = &send_result {
                // Recoverable: the exact signed bytes are durable. Do NOT retry here;
                // the watcher rebroadcasts the identical bytes from the SIGNED row.
                warn!(
                    nonce,
                    tx_hash = ?local_hash,
                    error = %e,
                    mark_broadcast,
                    "Broadcast send did not ack after durable signing; watcher will recover \
                     from the durable row"
                );
            }
            // Step 7: mark broadcast. A failure here is still accepted: the SIGNED row is
            // durable and mark_broadcast is idempotent for the watcher to replay.
            if mark_broadcast
                && let Err(e) = manager
                    .mark_broadcast(request.from, nonce, local_hash)
                    .await
            {
                error!(
                    nonce,
                    tx_hash = ?local_hash,
                    error = %e,
                    "Failed to mark broadcast after send; returning accepted (SIGNED recovery is safe)"
                );
            }
            info!(nonce, tx_hash = ?local_hash, "Transaction accepted");
            Ok(TxResponse::success(local_hash, nonce))
        }
        PostSend::Rejected { reason } => {
            // The node refused admission for a reason intrinsic to these bytes (fees,
            // funds, gas, encoding). This was the FIRST send of bytes that never left
            // this process, so nothing is in any mempool: retire the SIGNED reservation,
            // recycle the nonce, and tell the caller the truth. If the retire is refused
            // (row no longer SIGNED — a concurrent watcher pass moved it) or fails, fall
            // back to the fail-closed ambiguous path so nothing is double-spent.
            let ttl = chrono::Utc::now().timestamp() + config.ttl_days * 86_400;
            match manager
                .reject_signed(request.from, nonce, local_hash, &reason, ttl)
                .await
            {
                Ok(true) => {
                    warn!(nonce, tx_hash = ?local_hash, reason = %reason, "Node rejected transaction; nonce recycled");
                    Ok(TxResponse::error_with_code(
                        format!("Node rejected transaction: {reason}"),
                        "NODE_REJECTED",
                        false,
                    ))
                }
                Ok(false) => {
                    warn!(
                        nonce,
                        tx_hash = ?local_hash,
                        reason = %reason,
                        "Node rejected send but the row is no longer SIGNED; leaving to the watcher"
                    );
                    Ok(TxResponse::success(local_hash, nonce))
                }
                Err(e) => {
                    error!(
                        nonce,
                        tx_hash = ?local_hash,
                        reason = %reason,
                        error = %e,
                        "Node rejected send and retiring the SIGNED row failed; leaving SIGNED for the watcher"
                    );
                    Ok(TxResponse::success(local_hash, nonce))
                }
            }
        }
        PostSend::HashMismatch { node_hash } => {
            // The node acked a different hash than the bytes we signed — impossible for
            // identical bytes. Surface it as an error but leave the SIGNED row durable
            // for recovery (never release, never re-sign).
            error!(
                nonce,
                local = ?local_hash,
                node = ?node_hash,
                "Node returned a tx hash that disagrees with the signed bytes"
            );
            Ok(TxResponse::error_with_code(
                format!(
                    "Node tx hash {node_hash:?} disagrees with locally computed {local_hash:?}"
                ),
                "HASH_MISMATCH",
                false,
            ))
        }
    }
}

/// Replace every `http(s)://…` token in an error string with `<redacted-url>`.
///
/// Transport-level provider errors embed the request URL, and the RPC URL carries the
/// provider API key (`…/v2/<KEY>`). These strings are logged and, for simulation and gas
/// failures, returned to the caller, so the URL must never pass through verbatim.
pub(crate) fn redact_urls(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    loop {
        let Some(start) = ["https://", "http://", "wss://", "ws://"]
            .iter()
            .filter_map(|p| rest.find(p))
            .min()
        else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..start]);
        out.push_str("<redacted-url>");
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, ')' | '"' | '\'' | ',' | ';'))
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
}

/// Backend-agnostic acceptance check for a signature returned by any `TransactionSigner`.
///
/// Every remote backend (Nitro, Coinbase) returns bytes produced somewhere else; before
/// those bytes are encoded into a transaction or handed to a caller they must (1) be in
/// canonical low-`s` form — EIP-2 nodes refuse high-`s` at admission and a malleable
/// signature is a hazard for sign-hash consumers — and (2) recover to the address the
/// request claims to sign for. Checking here, once, covers every backend uniformly
/// instead of relying on each implementation to remember.
pub(crate) fn verify_signature(
    sig: &alloy::signers::Signature,
    hash: B256,
    expected: Address,
) -> std::result::Result<alloy::signers::Signature, String> {
    // Normalizing flips parity when s is high; recovery below is checked on the result.
    let sig = sig.normalized_s();
    let recovered = sig
        .recover_address_from_prehash(&hash)
        .map_err(|e| format!("signature recovery failed: {e}"))?;
    if recovered != expected {
        return Err(format!(
            "signature recovers to {recovered:?} but the request is for {expected:?}"
        ));
    }
    Ok(sig)
}

/// Release a still-`RESERVED` reservation after a pre-signing failure.
///
/// `release_nonce` self-guards: it recycles the nonce to the gap pool only while the
/// reservation is `RESERVED`, and is a no-op (`Ok(false)`) once `SIGNED`/`BROADCAST`.
/// That guard is exactly requirement (3) — a failure "before durable signed handoff
/// releases only if reservation is still RESERVED" — so this is safe to call on any
/// pre-`record_signed` failure without a separate state check.
async fn release_reserved<P>(manager: &DynamoNonceManager<P>, address: Address, nonce: u64)
where
    P: Provider + Clone,
{
    match manager.release_nonce(address, nonce).await {
        Ok(true) => debug!(nonce, "Reserved nonce released to gap pool"),
        Ok(false) => debug!(nonce, "Reservation no longer RESERVED; nothing released"),
        Err(e) => warn!(nonce, error = %e, "Failed to release reserved nonce"),
    }
}

/// Post-send disposition, evaluated only after the durable signed handoff.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PostSend {
    /// The send acked with the expected hash (or the node already held the bytes), or
    /// failed ambiguously (timeout/network/occupancy/`nonce too low`). Return an accepted
    /// response. `mark_broadcast` is true only when the bytes are known to be in the
    /// mempool — an ambiguous send leaves the tracker `SIGNED` for the watcher.
    Accepted { mark_broadcast: bool },
    /// The node definitively refused admission (fees/funds/gas/encoding) on this first
    /// send. The bytes never entered a mempool: retire the reservation, recycle the
    /// nonce, and return a non-retryable error carrying the node's reason.
    Rejected { reason: String },
    /// The node acked a hash that disagrees with the locally computed hash.
    HashMismatch { node_hash: B256 },
}

/// Classify the outcome of `send_raw_transaction` against the local hash. Pure so it is
/// unit-testable without a node: the accepted-on-ambiguous rule, the definitive-rejection
/// rule, and the hash-verification rule live here, not in the async plumbing.
pub(crate) fn classify_send_outcome(
    local_hash: B256,
    result: &std::result::Result<B256, String>,
) -> PostSend {
    match result {
        Ok(node_hash) if *node_hash == local_hash => PostSend::Accepted {
            mark_broadcast: true,
        },
        Ok(node_hash) => PostSend::HashMismatch {
            node_hash: *node_hash,
        },
        Err(e) => match classify_send_error(e) {
            // The node already holds these exact bytes: an earlier attempt landed.
            SendRejection::AlreadyKnown => PostSend::Accepted {
                mark_broadcast: true,
            },
            SendRejection::Definitive => PostSend::Rejected { reason: e.clone() },
            // `nonce too low` on a first send means someone else spent the nonce, or an
            // earlier ambiguous attempt mined; only the watcher's receipt check can tell.
            // Anything unrecognised is ambiguous: the signed bytes are durable, so accept
            // and let the watcher rebroadcast. Do not mark_broadcast.
            SendRejection::NonceTooLow | SendRejection::Ambiguous => PostSend::Accepted {
                mark_broadcast: false,
            },
        },
    }
}

/// Deterministic digest of a transaction request, binding an idempotency key to the
/// exact request it was first used with.
///
/// Covers every field that defines the transaction's intent. Variable-length `data` is
/// length-prefixed and every optional field carries a presence byte, so no two distinct
/// requests can collide by field-boundary ambiguity. Signer credentials are excluded —
/// they select a backend for the same `from`, not a different transaction.
///
/// The chain is folded in as the **effective** (config) chain id rather than the raw
/// request field, so an absent `chainId` and one that equals the deployment chain
/// produce the same digest — they are the same transaction after chain pinning.
fn request_digest(req: &TxRequest, effective_chain_id: u64) -> String {
    fn push_opt_u64(buf: &mut Vec<u8>, v: Option<u64>) {
        buf.push(v.is_some() as u8);
        buf.extend_from_slice(&v.unwrap_or(0).to_be_bytes());
    }
    fn push_opt_u256(buf: &mut Vec<u8>, v: Option<U256>) {
        buf.push(v.is_some() as u8);
        buf.extend_from_slice(&v.unwrap_or(U256::ZERO).to_be_bytes::<32>());
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(req.from.as_slice());
    buf.extend_from_slice(req.to.as_slice());
    buf.extend_from_slice(&req.value.to_be_bytes::<32>());
    buf.extend_from_slice(&(req.data.len() as u64).to_be_bytes());
    buf.extend_from_slice(&req.data);
    // Effective (pinned) chain, not the raw request field: absent == equal.
    buf.extend_from_slice(&effective_chain_id.to_be_bytes());
    push_opt_u64(&mut buf, req.gas_limit);
    push_opt_u256(&mut buf, req.max_fee_per_gas);
    push_opt_u256(&mut buf, req.max_priority_fee_per_gas);
    push_opt_u256(&mut buf, req.gas_price);
    buf.push(req.fee_speed.is_some() as u8);
    if let Some(speed) = req.fee_speed {
        buf.extend_from_slice(speed.as_str().as_bytes());
        buf.push(0);
    }
    buf.push(req.replacement_policy.is_some() as u8);
    if let Some(policy) = &req.replacement_policy {
        push_opt_u64(&mut buf, policy.bump_every_blocks);
        push_opt_u64(&mut buf, policy.max_bumps.map(u64::from));
        buf.push(policy.on_exhaust.is_some() as u8);
        if let Some(action) = policy.on_exhaust {
            buf.extend_from_slice(action.as_str().as_bytes());
            buf.push(0);
        }
        push_opt_u256(&mut buf, policy.max_fee_per_gas_wei);
        push_opt_u256(&mut buf, policy.max_total_fee_wei);
    }

    format!("0x{:x}", keccak256(&buf))
}

/// Build an idempotency claim for the request using the validated idempotency key.
fn idempotency_claim<'a>(
    request: &TxRequest,
    key: &str,
    config: &'a LambdaConfig,
    dynamo: &'a DynamoClient,
) -> IdempotencyClaim<'a> {
    let wallet = format!("{:?}", request.from);
    IdempotencyClaim::new(
        dynamo,
        &config.dynamodb_table,
        &wallet,
        key,
        request_digest(request, config.chain_id),
    )
}

/// Finalize an idempotency claim based on the broadcast outcome.
///
/// Releases the claim only when nothing could have reached the mempool (a
/// pre-broadcast setup error, a simulation revert, or a failed nonce
/// reservation). After a broadcast attempt with an ambiguous result
/// (`BROADCAST_FAILED`), the claim is retained — failing closed so that an
/// at-least-once redelivery cannot broadcast a second transaction for a request
/// that may already be in the mempool.
async fn settle_claim(claim: &IdempotencyClaim<'_>, result: &Result<TxResponse>) {
    match result {
        Ok(resp) if resp.success => match (resp.tx_hash, resp.nonce) {
            (Some(tx_hash), Some(nonce)) => {
                if let Err(e) = claim.complete(tx_hash, nonce).await {
                    warn!(error = %e, "Failed to record idempotency completion");
                }
            }
            _ => warn!("Accepted response missing tx_hash/nonce; retaining claim"),
        },
        Ok(resp) if is_pre_broadcast_failure(resp.error_code.as_deref()) => {
            release_claim(claim).await;
        }
        Err(_) => release_claim(claim).await,

        Ok(_) => warn!(
            "Broadcast outcome ambiguous; retaining idempotency claim to prevent double-broadcast"
        ),
    }
}

/// Whether an error code denotes a failure that provably preceded any mempool admission.
/// `NODE_REJECTED` qualifies: it is only returned after `reject_signed` succeeded, which
/// means the first (and only) send was refused and the reservation was retired.
fn is_pre_broadcast_failure(code: Option<&str>) -> bool {
    matches!(
        code,
        Some(
            "SIMULATION_FAILED"
                | "NONCE_EXHAUSTED"
                | "GAS_ESTIMATION_FAILED"
                | "INVALID_REQUEST"
                | "NODE_REJECTED"
        )
    )
}

async fn release_claim(claim: &IdempotencyClaim<'_>) {
    if let Err(e) = claim.release().await {
        warn!(error = %e, "Failed to release idempotency claim");
    }
}

fn default_bump_blocks(speed: FeeSpeed) -> u64 {
    match speed {
        FeeSpeed::Slow => 20,
        FeeSpeed::Standard => 5,
        FeeSpeed::Fast => 3,
    }
}

fn resolve_replacement_policy(
    request: &TxRequest,
    config: &LambdaConfig,
    gas_limit: u64,
    initial_max_fee: u128,
    fee_speed: FeeSpeed,
) -> std::result::Result<Option<ResolvedReplacementPolicy>, TxResponse> {
    // Explicit-fee callers that omit replacementPolicy retain their exact fee intent;
    // never silently expand a deliberate low cap to the deployment default. Live-tier
    // requests are auto-managed by default.
    if request.replacement_policy.is_none() && request.max_fee_per_gas.is_some() {
        return Ok(None);
    }
    // Per-request signer routing is not persisted in family state. Fail closed rather
    // than later asking the deployment signer to sign for a different tenant wallet.
    if request.signer_credentials.is_some() {
        return if request.replacement_policy.is_some() {
            Err(invalid_request(
                "replacementPolicy is not supported with per-request signerCredentials",
            ))
        } else {
            Ok(None)
        };
    }
    if !config.replacement_enabled {
        return if request.replacement_policy.is_some() {
            Err(invalid_request(
                "replacementPolicy is disabled for this deployment",
            ))
        } else {
            Ok(None)
        };
    }
    let requested = request.replacement_policy.as_ref();
    let bump_every_blocks = requested
        .and_then(|p| p.bump_every_blocks)
        .unwrap_or_else(|| default_bump_blocks(fee_speed));
    if !(1..=10_000).contains(&bump_every_blocks) {
        return Err(invalid_request(
            "bumpEveryBlocks must be between 1 and 10000",
        ));
    }
    let max_bumps = requested
        .and_then(|p| p.max_bumps)
        .unwrap_or(config.max_replacement_attempts);
    if max_bumps > config.max_replacement_attempts {
        return Err(invalid_request(&format!(
            "maxBumps {max_bumps} exceeds deployment maximum {}",
            config.max_replacement_attempts
        )));
    }
    let on_exhaust = requested
        .and_then(|p| p.on_exhaust)
        .unwrap_or(ExhaustionAction::Hold);
    let max_fee_per_gas_wei = match requested.and_then(|p| p.max_fee_per_gas_wei) {
        Some(v) => {
            u256_to_u128(v, "replacementPolicy.maxFeePerGasWei").map_err(|e| invalid_request(&e))?
        }
        None => config.default_max_fee_per_gas_wei,
    };
    let max_total_fee_wei = requested
        .and_then(|p| p.max_total_fee_wei)
        .unwrap_or(config.default_max_total_fee_wei);
    if max_fee_per_gas_wei > config.hard_max_fee_per_gas_wei {
        return Err(invalid_request(
            "replacementPolicy.maxFeePerGasWei exceeds the deployment hard maximum",
        ));
    }
    if max_total_fee_wei > config.hard_max_total_fee_wei {
        return Err(invalid_request(
            "replacementPolicy.maxTotalFeeWei exceeds the deployment hard maximum",
        ));
    }
    if initial_max_fee > max_fee_per_gas_wei {
        return Err(invalid_request(
            "initial maxFeePerGas exceeds the effective replacement per-gas ceiling",
        ));
    }
    let initial_total = U256::from(gas_limit) * U256::from(initial_max_fee);
    if initial_total > max_total_fee_wei {
        return Err(invalid_request(
            "gasLimit * maxFeePerGas exceeds the effective replacement total-fee ceiling",
        ));
    }
    if max_bumps == 0 {
        return Ok(None);
    }
    Ok(Some(ResolvedReplacementPolicy {
        fee_speed,
        bump_every_blocks,
        max_bumps,
        on_exhaust,
        max_fee_per_gas_wei,
        max_total_fee_wei,
    }))
}

/// Gas parameters resolved for a transaction.
struct GasParams {
    gas_limit: u64,
    max_fee: u128,
    max_priority_fee: u128,
    replacement_policy: Option<ResolvedReplacementPolicy>,
    current_block: Option<u64>,
}

/// Either resolved gas parameters or a short-circuit response to return as-is.
enum GasOutcome {
    Ready(GasParams),
    ShortCircuit(TxResponse),
}

/// Resolve gas limit and EIP-1559 fees, estimating any values not supplied.
async fn resolve_gas_params<P: alloy::providers::Provider>(
    provider: &P,
    request: &TxRequest,
    config: &LambdaConfig,
) -> Result<GasOutcome> {
    let gas_limit = match request.gas_limit {
        Some(limit) => limit,
        None => {
            let tx = TransactionRequest::default()
                .from(request.from)
                .to(request.to)
                .value(request.value)
                .input(request.data.clone().into());

            match provider.estimate_gas(tx).await {
                Ok(estimate) => estimate * (100 + config.gas_buffer_percentage) / 100,
                Err(e) => {
                    let e = redact_urls(&e.to_string());
                    if !request.data.is_empty() {
                        warn!(error = %e, "Gas estimation failed for contract call");
                        return Ok(GasOutcome::ShortCircuit(TxResponse::error_with_code(
                            format!("Gas estimation failed: {}", e),
                            "GAS_ESTIMATION_FAILED",
                            true,
                        )));
                    }
                    warn!(error = %e, "Gas estimation failed, using default for simple transfer");
                    config.default_gas_limit
                }
            }
        }
    };

    let fee_speed = request.fee_speed.unwrap_or(FeeSpeed::Standard);
    let (max_fee, max_priority_fee): (u128, u128) =
        match parse_fee_overrides(request.max_fee_per_gas, request.max_priority_fee_per_gas) {
            Ok(Some(fees)) => (fees.max_fee, fees.max_priority_fee),
            Ok(None) => {
                let quote = estimate_live_fees(provider, fee_speed, config.fee_tip_floor_wei)
                    .await
                    .map_err(|e| LambdaError::GasEstimationFailed(redact_urls(&e.to_string())))?;
                (quote.max_fee_per_gas, quote.max_priority_fee_per_gas)
            }
            Err(msg) => {
                return Ok(GasOutcome::ShortCircuit(TxResponse::error_with_code(
                    msg,
                    "INVALID_REQUEST",
                    false,
                )));
            }
        };

    // Deployment hard caps bound every signature this Lambda produces, including the
    // first broadcast of a request that carries explicit fees and no replacement policy.
    // Without this check those requests would bypass the ceilings entirely, because the
    // replacement-policy path (below) is the only other place the caps are consulted.
    if let Some(response) = check_hard_fee_caps(request, config, gas_limit, max_fee) {
        return Ok(GasOutcome::ShortCircuit(response));
    }

    let replacement_policy =
        match resolve_replacement_policy(request, config, gas_limit, max_fee, fee_speed) {
            Ok(policy) => policy,
            Err(response) => return Ok(GasOutcome::ShortCircuit(response)),
        };
    let current_block = if replacement_policy.is_some() {
        Some(
            provider
                .get_block_number()
                .await
                .map_err(|e| LambdaError::GasEstimationFailed(redact_urls(&e.to_string())))?,
        )
    } else {
        None
    };

    Ok(GasOutcome::Ready(GasParams {
        gas_limit,
        max_fee,
        max_priority_fee,
        replacement_policy,
        current_block,
    }))
}

/// Enforce the deployment hard caps on the fees about to be signed.
///
/// Returns `None` when both the per-gas fee and the `gasLimit × maxFeePerGas` budget are
/// within `HARD_MAX_*`. Explicit caller fees over the cap are a non-retryable
/// `INVALID_REQUEST`; a live quote over the cap is retryable (`GAS_ESTIMATION_FAILED`)
/// because the market may fall back under the ceiling. Both are pre-broadcast failures.
fn check_hard_fee_caps(
    request: &TxRequest,
    config: &LambdaConfig,
    gas_limit: u64,
    max_fee: u128,
) -> Option<TxResponse> {
    let explicit = request.max_fee_per_gas.is_some();
    let reject = |msg: String| {
        let (code, retryable) = if explicit {
            ("INVALID_REQUEST", false)
        } else {
            ("GAS_ESTIMATION_FAILED", true)
        };
        Some(TxResponse::error_with_code(msg, code, retryable))
    };
    if max_fee > config.hard_max_fee_per_gas_wei {
        return reject(format!(
            "maxFeePerGas {max_fee} exceeds the deployment hard maximum {}",
            config.hard_max_fee_per_gas_wei
        ));
    }
    let total = U256::from(gas_limit) * U256::from(max_fee);
    if total > config.hard_max_total_fee_wei {
        return reject(format!(
            "gasLimit * maxFeePerGas ({total}) exceeds the deployment hard total-fee maximum {}",
            config.hard_max_total_fee_wei
        ));
    }
    None
}

/// Explicit EIP-1559 fee overrides supplied in a request, validated and range-checked.
#[derive(Debug, PartialEq, Eq)]
struct FeeOverrides {
    max_fee: u128,
    max_priority_fee: u128,
}

/// Validate and convert request-supplied EIP-1559 fees.
///
/// - Neither supplied -> `Ok(None)`: fees are estimated downstream (unchanged fallback).
/// - Both supplied -> validate each fits `u128` and that priority <= max -> `Ok(Some(..))`.
/// - Exactly one supplied -> `Err`: the pair must be supplied together, otherwise the
///   missing half would be silently estimated and could invert `priority <= max`.
///
/// Values exceeding `u128::MAX` are rejected here, *before* any `.to::<u128>()`, so a
/// caller-supplied U256 can never panic the conversion.
fn parse_fee_overrides(
    max_fee: Option<U256>,
    max_priority_fee: Option<U256>,
) -> std::result::Result<Option<FeeOverrides>, String> {
    match (max_fee, max_priority_fee) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            Err("maxFeePerGas and maxPriorityFeePerGas must be supplied together".to_string())
        }
        (Some(mf), Some(pf)) => {
            let max_fee = u256_to_u128(mf, "maxFeePerGas")?;
            let max_priority_fee = u256_to_u128(pf, "maxPriorityFeePerGas")?;
            if max_priority_fee > max_fee {
                return Err(format!(
                    "maxPriorityFeePerGas ({max_priority_fee}) exceeds maxFeePerGas ({max_fee})"
                ));
            }
            Ok(Some(FeeOverrides {
                max_fee,
                max_priority_fee,
            }))
        }
    }
}

/// Convert a `U256` fee to `u128`, rejecting anything above `u128::MAX` before the
/// conversion so it can never panic.
fn u256_to_u128(value: U256, field: &str) -> std::result::Result<u128, String> {
    if value > U256::from(u128::MAX) {
        return Err(format!("{field} exceeds the u128 maximum"));
    }
    Ok(value.to::<u128>())
}

/// Trim an idempotency key and return it only if non-empty after trimming.
///
/// Both a missing key and a blank/whitespace-only key collapse to `None`.
pub(crate) fn normalize_idempotency_key(key: Option<&str>) -> Option<&str> {
    let trimmed = key?.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Resolve the effective idempotency key for an SQS-delivered request: the request's own
/// key when present and non-blank, otherwise fall back to the SQS `messageId`.
///
/// Pure so the fallback rule (missing OR blank -> messageId) is unit-testable without a
/// live SQS event.
pub(crate) fn sqs_idempotency_key(
    body_key: Option<&str>,
    message_id: Option<&str>,
) -> Option<String> {
    normalize_idempotency_key(body_key)
        .or_else(|| normalize_idempotency_key(message_id))
        .map(str::to_string)
}

/// Validate a broadcast request at the trust boundary, before any DynamoDB, idempotency,
/// or nonce work. On success returns the trimmed idempotency key. On failure returns a
/// non-retryable `INVALID_REQUEST` response (never a panic).
fn validate_broadcast_request<'a>(
    request: &'a TxRequest,
    config: &LambdaConfig,
) -> std::result::Result<&'a str, TxResponse> {
    if request.from == Address::ZERO {
        return Err(invalid_request("from address is zero"));
    }
    if request.to == Address::ZERO {
        return Err(invalid_request("to address is zero"));
    }
    // Chain pinning: config.chain_id is authoritative. A request may omit chainId or
    // supply the matching value; any other value is a mismatch and is rejected here,
    // before any Dynamo/idempotency/nonce work.
    if let Some(requested) = request.chain_id
        && requested != config.chain_id
    {
        return Err(invalid_request(&format!(
            "chainId {requested} does not match the deployment chain {}",
            config.chain_id
        )));
    }
    // Size and gas bounds are request data too. Reject before any nonce/RPC work so an
    // oversized or absurd request cannot spend a reservation, an eth_call, and a
    // signature only to be refused by the node (or by record_signed's size cap).
    if request.data.len() > MAX_CALLDATA_BYTES {
        return Err(invalid_request(&format!(
            "data is {} bytes; maximum is {MAX_CALLDATA_BYTES}",
            request.data.len()
        )));
    }
    match request.gas_limit {
        Some(0) => return Err(invalid_request("gasLimit must be greater than zero")),
        Some(limit) if limit > MAX_GAS_LIMIT => {
            return Err(invalid_request(&format!(
                "gasLimit {limit} exceeds maximum {MAX_GAS_LIMIT}"
            )));
        }
        _ => {}
    }
    // Fee overrides are pure request data. Validate their pair, ordering, and u128
    // bounds here so malformed input is rejected before an idempotency claim, wallet
    // initialization, or any RPC call. resolve_gas_params parses the already-validated
    // pair again only to obtain the converted values.
    if let Err(message) =
        parse_fee_overrides(request.max_fee_per_gas, request.max_priority_fee_per_gas)
    {
        return Err(invalid_request(&message));
    }
    // Direct-path idempotency: every broadcast reaching the handler must carry a
    // non-empty, trimmed idempotency key. The SQS path fills this from the messageId
    // upstream, so a blank key here is a direct-invocation client error.
    normalize_idempotency_key(request.idempotency_key.as_deref())
        .ok_or_else(|| invalid_request("idempotencyKey is required and must be non-empty"))
}

/// Upper bound on request calldata. Geth's default `txpool` limit is 128 KiB per
/// transaction; anything larger is refused at admission on mainstream nodes, and the
/// signed encoding must also fit the nonce authority's stored-bytes cap.
const MAX_CALLDATA_BYTES: usize = 120 * 1024;

/// Upper bound on a caller-supplied gas limit. Mainnet's block gas limit is ~36M as of
/// 2025 and no supported chain accepts a single transaction above 100M; anything larger
/// is refused at admission (`exceeds block gas limit`) and would otherwise burn a nonce
/// cycle before that refusal.
const MAX_GAS_LIMIT: u64 = 100_000_000;

/// Build a non-retryable INVALID_REQUEST response. The message identifies the invalid
/// request; it never echoes signer credentials.
fn invalid_request(message: &str) -> TxResponse {
    TxResponse::error_with_code(message.to_string(), "INVALID_REQUEST", false)
}

/// Handle a sign-hash request (raw hash or EIP-712 typed data)
pub async fn handle_sign_hash(
    request: SignHashRequest,
    request_context: Option<&serde_json::Value>,
) -> Result<SignHashResponse> {
    if let Some(ctx) = request_context
        && let Some(identity) = ctx.pointer("/identity/caller")
    {
        info!(caller = %identity, from = ?request.from, "Sign-hash request from authorized caller");
    }

    if request.from == Address::ZERO {
        return Err(LambdaError::InvalidRequest("from address is zero".into()));
    }

    // A disabled sign-hash path refuses before resolving a signer. Broadcast callers are
    // then bounded by the nonce authority, simulation, and fee caps rather than holding
    // raw signing authority over arbitrary digests.
    if !get_config().await?.sign_hash_enabled {
        return Err(LambdaError::InvalidRequest(
            "sign-hash is disabled for this deployment (SIGN_HASH_ENABLED=false)".into(),
        ));
    }

    // Determine the hash to sign — three modes
    let hash = match (
        &request.hash,
        &request.domain_separator,
        &request.struct_hash,
        &request.typed_data,
    ) {
        // Mode 1: raw hash
        (Some(h), None, None, None) => *h,
        // Mode 2: pre-computed EIP-712 hashes
        (None, Some(ds), Some(sh), None) => {
            let mut data = Vec::with_capacity(66);
            data.extend_from_slice(&[0x19, 0x01]);
            data.extend_from_slice(ds.as_slice());
            data.extend_from_slice(sh.as_slice());
            keccak256(&data)
        }
        // Mode 3: full EIP-712 typed data
        (None, None, None, Some(typed_data)) => crate::eip712::hash_typed_data(typed_data)
            .map_err(|e| LambdaError::InvalidRequest(format!("EIP-712 encoding error: {}", e)))?,
        _ => {
            return Err(LambdaError::InvalidRequest(
                "Provide one of: 'hash', 'domainSeparator'+'structHash', or 'typedData'".into(),
            ));
        }
    };

    let signer_provider = get_signer_provider().await?;
    let signer = signer_provider
        .get_signer_with_credentials(request.from, request.signer_credentials.as_ref())
        .await
        .map_err(|e| LambdaError::Signer(e.to_string()))?;

    info!(backend = %signer.info().backend, hash = ?hash, "Signing hash");

    let signature = signer
        .sign_hash(hash)
        .await
        .map_err(|e| LambdaError::Signer(format!("sign_hash failed: {}", e)))?;
    let signature =
        verify_signature(&signature, hash, request.from).map_err(LambdaError::Signer)?;

    Ok(SignHashResponse {
        success: true,
        r: Some(format!("0x{:064x}", signature.r())),
        s: Some(format!("0x{:064x}", signature.s())),
        v: Some(if signature.v() { 28 } else { 27 }),
        signature: Some(format!("0x{}", hex::encode(signature.as_bytes()))),
        ..Default::default()
    })
}

/// Handle a transaction request with optional caller context
///
/// This is the entry point called by the Lambda handler. The request_context
/// is reserved for future use (e.g., caller identity from IAM authorizer).
/// The caller ARN is logged for audit purposes; authorization enforcement
/// can be layered on top of this logging infrastructure later.
pub async fn handle_request_with_context(
    request: TxRequest,
    request_context: Option<&serde_json::Value>,
) -> Result<TxResponse> {
    // Log caller identity if provided
    if let Some(ctx) = request_context
        && let Some(identity) = ctx.pointer("/identity/caller")
    {
        info!(caller = %identity, from = ?request.from, "Transaction request from authorized caller");
    }
    handle_request(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Effective (pinned) chain id used across digest tests.
    const TEST_CHAIN: u64 = 11155111;

    /// A test config pinned to [`TEST_CHAIN`].
    fn test_config() -> LambdaConfig {
        LambdaConfig {
            eth_rpc_url: "http://localhost:8545".to_string(),
            chain_id: TEST_CHAIN,
            dynamodb_table: "tx_tracker".to_string(),
            ttl_days: 7,
            max_retries: 3,
            rpc_timeout: Duration::from_secs(30),
            default_gas_limit: 21_000,
            gas_buffer_percentage: 20,
            replacement_enabled: true,
            sign_hash_enabled: true,
            default_max_fee_per_gas_wei: 150_000_000_000,
            hard_max_fee_per_gas_wei: 500_000_000_000,
            default_max_total_fee_wei: U256::from(20_000_000_000_000_000u64),
            hard_max_total_fee_wei: U256::from(100_000_000_000_000_000u64),
            max_replacement_attempts: 3,
            fee_tip_floor_wei: 100_000_000,
        }
    }

    /// A minimal, fully-specified request for digest tests. Every optional field is set
    /// so individual-field mutations in the tests are unambiguous.
    fn tx_request() -> TxRequest {
        TxRequest {
            from: Address::repeat_byte(0x01),
            to: Address::repeat_byte(0x02),
            value: U256::from(1_000_000u64),
            data: vec![0x01, 0x02, 0x03].into(),
            gas_limit: Some(21_000),
            max_fee_per_gas: Some(U256::from(50u64)),
            max_priority_fee_per_gas: Some(U256::from(2u64)),
            gas_price: None,
            chain_id: Some(TEST_CHAIN),
            idempotency_key: Some("key-1".to_string()),
            fee_speed: Some(FeeSpeed::Standard),
            replacement_policy: None,
            signer_credentials: None,
        }
    }

    #[test]
    fn hard_fee_caps_bound_the_initial_broadcast() {
        let config = test_config();
        let mut request = tx_request();

        // Within both caps: nothing to reject.
        assert!(check_hard_fee_caps(&request, &config, 21_000, 50).is_none());

        // Explicit per-gas fee over HARD_MAX_FEE_PER_GAS_WEI: a caller mistake, not retryable.
        let resp = check_hard_fee_caps(
            &request,
            &config,
            21_000,
            config.hard_max_fee_per_gas_wei + 1,
        )
        .expect("over-cap fee must be rejected");
        assert_eq!(resp.error_code.as_deref(), Some("INVALID_REQUEST"));
        assert!(!resp.retryable);

        // Explicit fee under the per-gas cap but gasLimit * fee over the total budget.
        let resp = check_hard_fee_caps(
            &request,
            &config,
            30_000_000,
            config.hard_max_fee_per_gas_wei,
        )
        .expect("over-budget total must be rejected");
        assert_eq!(resp.error_code.as_deref(), Some("INVALID_REQUEST"));

        // The same breach from a live quote is retryable: the market may fall back under.
        request.max_fee_per_gas = None;
        request.max_priority_fee_per_gas = None;
        let resp = check_hard_fee_caps(
            &request,
            &config,
            21_000,
            config.hard_max_fee_per_gas_wei + 1,
        )
        .expect("over-cap live quote must be rejected");
        assert_eq!(resp.error_code.as_deref(), Some("GAS_ESTIMATION_FAILED"));
        assert!(resp.retryable);
        // Every cap rejection is a pre-broadcast failure, so the idempotency claim is released.
        assert!(is_pre_broadcast_failure(resp.error_code.as_deref()));
    }

    #[test]
    fn pre_broadcast_codes_release_the_claim() {
        // These outcomes provably precede any broadcast, so the claim is safe to release
        // for a clean retry on redelivery. INVALID_REQUEST is included: a rejected
        // request never reaches the mempool.
        for code in [
            "SIMULATION_FAILED",
            "NONCE_EXHAUSTED",
            "GAS_ESTIMATION_FAILED",
            "INVALID_REQUEST",
            "NODE_REJECTED",
        ] {
            assert!(
                is_pre_broadcast_failure(Some(code)),
                "{code} should be treated as pre-broadcast"
            );
        }
    }

    #[test]
    fn replacement_policy_defaults_are_bounded_and_hold() {
        let mut request = tx_request();
        request.max_fee_per_gas = None;
        request.max_priority_fee_per_gas = None;
        let policy =
            resolve_replacement_policy(&request, &test_config(), 21_000, 50, FeeSpeed::Standard)
                .unwrap()
                .unwrap();
        assert_eq!(policy.bump_every_blocks, 5);
        assert_eq!(policy.max_bumps, 3);
        assert_eq!(policy.on_exhaust, ExhaustionAction::Hold);
        assert_eq!(policy.max_fee_per_gas_wei, 150_000_000_000);
    }

    #[test]
    fn explicit_fees_require_explicit_replacement_opt_in() {
        let request = tx_request();
        assert!(
            resolve_replacement_policy(&request, &test_config(), 21_000, 50, FeeSpeed::Standard,)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn per_request_signer_cannot_create_unreproducible_family() {
        let mut request = tx_request();
        request.replacement_policy = Some(crate::types::ReplacementPolicyRequest {
            bump_every_blocks: None,
            max_bumps: None,
            on_exhaust: None,
            max_fee_per_gas_wei: None,
            max_total_fee_wei: None,
        });
        request.signer_credentials = Some(crate::types::SignerCredentials {
            backend: "coinbase".into(),
            wallet_secret_name: None,
            #[cfg(debug_assertions)]
            wallet_secret: None,
            wallet_secret_arn: None,
        });
        assert!(
            resolve_replacement_policy(&request, &test_config(), 21_000, 50, FeeSpeed::Standard,)
                .is_err()
        );
    }

    #[test]
    fn replacement_request_cannot_exceed_deployment_hard_limits() {
        let mut request = tx_request();
        request.replacement_policy = Some(crate::types::ReplacementPolicyRequest {
            bump_every_blocks: Some(1),
            max_bumps: Some(3),
            on_exhaust: Some(ExhaustionAction::Cancel),
            max_fee_per_gas_wei: Some(U256::from(500_000_000_001u64)),
            max_total_fee_wei: None,
        });
        assert!(
            resolve_replacement_policy(&request, &test_config(), 21_000, 50, FeeSpeed::Fast,)
                .is_err()
        );
    }

    #[test]
    fn initial_total_fee_must_fit_immutable_family_budget() {
        let mut request = tx_request();
        request.replacement_policy = Some(crate::types::ReplacementPolicyRequest {
            bump_every_blocks: None,
            max_bumps: None,
            on_exhaust: None,
            max_fee_per_gas_wei: Some(U256::from(100u64)),
            max_total_fee_wei: Some(U256::from(999u64)),
        });
        assert!(
            resolve_replacement_policy(&request, &test_config(), 21_000, 50, FeeSpeed::Standard,)
                .is_err()
        );
    }

    #[test]
    fn ambiguous_and_unknown_codes_retain_the_claim() {
        // BROADCAST_FAILED may have reached the mempool; unknown/None codes are
        // not provably pre-broadcast. All must fail closed (retain the claim).
        for code in [
            Some("BROADCAST_FAILED"),
            Some("UNKNOWN_ERROR"),
            Some(""),
            None,
        ] {
            assert!(
                !is_pre_broadcast_failure(code),
                "{code:?} must not be treated as pre-broadcast"
            );
        }
    }

    #[test]
    fn request_digest_is_deterministic_for_identical_requests() {
        // The same logical request must always hash to the same digest so a genuine
        // retry (same key, same body) is recognized as a duplicate, not a conflict.
        let a = tx_request();
        let b = tx_request();
        assert_eq!(
            request_digest(&a, TEST_CHAIN),
            request_digest(&b, TEST_CHAIN)
        );
        // And it is stable across repeated evaluation of the same value.
        assert_eq!(
            request_digest(&a, TEST_CHAIN),
            request_digest(&a, TEST_CHAIN)
        );
    }

    #[test]
    fn request_digest_differs_when_any_intent_field_changes() {
        // Any change to a transaction-defining field must change the digest so that
        // reusing an idempotency key for a different transaction is detected as a
        // conflict rather than collapsed onto the first result.
        let base = tx_request();
        let base_digest = request_digest(&base, TEST_CHAIN);

        let mut to_changed = tx_request();
        to_changed.to = Address::repeat_byte(0x11);
        assert_ne!(
            request_digest(&to_changed, TEST_CHAIN),
            base_digest,
            "to must matter"
        );

        let mut value_changed = tx_request();
        value_changed.value = U256::from(1u64);
        assert_ne!(
            request_digest(&value_changed, TEST_CHAIN),
            base_digest,
            "value must matter"
        );

        let mut data_changed = tx_request();
        data_changed.data = vec![0xde, 0xad].into();
        assert_ne!(
            request_digest(&data_changed, TEST_CHAIN),
            base_digest,
            "data must matter"
        );

        let mut fee_changed = tx_request();
        fee_changed.max_fee_per_gas = Some(U256::from(7u64));
        assert_ne!(
            request_digest(&fee_changed, TEST_CHAIN),
            base_digest,
            "max_fee_per_gas must matter"
        );
    }

    #[test]
    fn request_digest_folds_in_effective_chain_not_request_field() {
        // The digest is keyed on the effective (pinned) chain, so it changes with the
        // effective chain even when the request field is identical...
        let req = tx_request();
        assert_ne!(
            request_digest(&req, 1),
            request_digest(&req, 42161),
            "effective chain must matter"
        );
    }

    #[test]
    fn request_digest_absent_and_equal_chain_are_equivalent() {
        // Requirement 1: an absent chainId and one equal to the effective chain are the
        // same transaction, so they must produce the same digest.
        let mut absent = tx_request();
        absent.chain_id = None;
        let mut equal = tx_request();
        equal.chain_id = Some(TEST_CHAIN);
        assert_eq!(
            request_digest(&absent, TEST_CHAIN),
            request_digest(&equal, TEST_CHAIN),
            "absent and equal chainId must be equivalent under a pinned chain"
        );
    }

    #[test]
    fn request_digest_distinguishes_absent_from_zero() {
        // A present-but-zero optional and an absent optional are different requests;
        // the presence byte must keep their digests distinct.
        let mut absent = tx_request();
        absent.gas_limit = None;
        let mut zero = tx_request();
        zero.gas_limit = Some(0);
        assert_ne!(
            request_digest(&absent, TEST_CHAIN),
            request_digest(&zero, TEST_CHAIN)
        );
    }

    // ---- Requirement 1: chain pinning at the boundary ----

    #[test]
    fn boundary_rejects_chain_mismatch() {
        let config = test_config();
        let mut req = tx_request();
        req.chain_id = Some(TEST_CHAIN + 1);
        let err = validate_broadcast_request(&req, &config)
            .expect_err("mismatched chainId must be rejected");
        assert!(!err.success);
        assert_eq!(err.error_code.as_deref(), Some("INVALID_REQUEST"));
        assert!(!err.retryable);
    }

    #[test]
    fn boundary_accepts_equal_chain() {
        let config = test_config();
        let mut req = tx_request();
        req.chain_id = Some(TEST_CHAIN);
        assert_eq!(
            validate_broadcast_request(&req, &config).unwrap(),
            "key-1",
            "equal chainId must pass and return the trimmed key"
        );
    }

    #[test]
    fn boundary_accepts_absent_chain() {
        let config = test_config();
        let mut req = tx_request();
        req.chain_id = None;
        assert_eq!(
            validate_broadcast_request(&req, &config).unwrap(),
            "key-1",
            "absent chainId must pass (deployment chain is authoritative)"
        );
    }

    #[test]
    fn boundary_rejects_invalid_fee_overrides_before_pipeline() {
        let config = test_config();

        let mut missing_pair = tx_request();
        missing_pair.max_priority_fee_per_gas = None;
        let err = validate_broadcast_request(&missing_pair, &config)
            .expect_err("an incomplete fee pair must fail boundary validation");
        assert_eq!(err.error_code.as_deref(), Some("INVALID_REQUEST"));
        assert!(!err.retryable);

        let mut overflow = tx_request();
        overflow.max_fee_per_gas = Some(U256::MAX);
        let err = validate_broadcast_request(&overflow, &config)
            .expect_err("fee overflow must fail boundary validation");
        assert_eq!(err.error_code.as_deref(), Some("INVALID_REQUEST"));
    }

    // ---- Requirement 2: direct-path idempotency ----

    #[test]
    fn boundary_rejects_missing_idempotency_key() {
        let config = test_config();
        let mut req = tx_request();
        req.idempotency_key = None;
        let err =
            validate_broadcast_request(&req, &config).expect_err("missing key must be rejected");
        assert_eq!(err.error_code.as_deref(), Some("INVALID_REQUEST"));
        assert!(!err.retryable);
    }

    #[test]
    fn boundary_rejects_blank_idempotency_key() {
        let config = test_config();
        for blank in ["", "   ", "\t\n"] {
            let mut req = tx_request();
            req.idempotency_key = Some(blank.to_string());
            let err =
                validate_broadcast_request(&req, &config).expect_err("blank key must be rejected");
            assert_eq!(err.error_code.as_deref(), Some("INVALID_REQUEST"));
        }
    }

    #[test]
    fn boundary_trims_idempotency_key() {
        let config = test_config();
        let mut req = tx_request();
        req.idempotency_key = Some("  padded-key  ".to_string());
        assert_eq!(
            validate_broadcast_request(&req, &config).unwrap(),
            "padded-key",
            "the returned key must be trimmed"
        );
    }

    #[test]
    fn normalize_idempotency_key_rules() {
        assert_eq!(normalize_idempotency_key(Some("abc")), Some("abc"));
        assert_eq!(normalize_idempotency_key(Some("  abc  ")), Some("abc"));
        assert_eq!(normalize_idempotency_key(Some("   ")), None);
        assert_eq!(normalize_idempotency_key(Some("")), None);
        assert_eq!(normalize_idempotency_key(None), None);
    }

    #[test]
    fn sqs_idempotency_key_falls_back_to_message_id() {
        // Present, non-blank body key wins.
        assert_eq!(
            sqs_idempotency_key(Some("body-key"), Some("msg-1")),
            Some("body-key".to_string())
        );
        // Missing body key -> messageId.
        assert_eq!(
            sqs_idempotency_key(None, Some("msg-1")),
            Some("msg-1".to_string())
        );
        // Blank body key -> messageId (treated as absent).
        assert_eq!(
            sqs_idempotency_key(Some("   "), Some("msg-1")),
            Some("msg-1".to_string())
        );
        // Body key is trimmed when used.
        assert_eq!(
            sqs_idempotency_key(Some("  body  "), Some("msg-1")),
            Some("body".to_string())
        );
        // Nothing usable -> None (handler then rejects with INVALID_REQUEST).
        assert_eq!(sqs_idempotency_key(None, None), None);
    }

    // ---- Requirement 3: fee safety ----

    #[test]
    fn fee_overrides_none_estimates_downstream() {
        assert_eq!(parse_fee_overrides(None, None), Ok(None));
    }

    #[test]
    fn fee_overrides_require_both_when_one_supplied() {
        assert!(
            parse_fee_overrides(Some(U256::from(100u64)), None).is_err(),
            "max without priority must be rejected"
        );
        assert!(
            parse_fee_overrides(None, Some(U256::from(1u64))).is_err(),
            "priority without max must be rejected"
        );
    }

    #[test]
    fn fee_overrides_reject_priority_above_max() {
        let err = parse_fee_overrides(Some(U256::from(10u64)), Some(U256::from(11u64)))
            .expect_err("priority > max must be rejected");
        assert!(err.contains("exceeds"));
    }

    #[test]
    fn fee_overrides_reject_u256_above_u128_max() {
        // U256::MAX cannot fit u128 and must be rejected before any .to::<u128>().
        assert!(parse_fee_overrides(Some(U256::MAX), Some(U256::from(1u64))).is_err());
        assert!(parse_fee_overrides(Some(U256::MAX), Some(U256::MAX)).is_err());
        // Priority alone over u128::MAX (with a valid-shaped max) is also rejected.
        let just_over = U256::from(u128::MAX) + U256::from(1u64);
        assert!(parse_fee_overrides(Some(just_over), Some(U256::from(1u64))).is_err());
    }

    #[test]
    fn fee_overrides_accept_u128_max_boundary() {
        // Exactly u128::MAX is representable and must be accepted (mutation-effective:
        // the > comparison, not >=, is what allows the boundary).
        let max = U256::from(u128::MAX);
        assert_eq!(
            parse_fee_overrides(Some(max), Some(max)),
            Ok(Some(FeeOverrides {
                max_fee: u128::MAX,
                max_priority_fee: u128::MAX,
            }))
        );
    }

    #[test]
    fn fee_overrides_accept_valid_pair() {
        assert_eq!(
            parse_fee_overrides(Some(U256::from(50u64)), Some(U256::from(2u64))),
            Ok(Some(FeeOverrides {
                max_fee: 50,
                max_priority_fee: 2,
            }))
        );
        // Equal priority == max is allowed (not a strict inversion).
        assert_eq!(
            parse_fee_overrides(Some(U256::from(7u64)), Some(U256::from(7u64))),
            Ok(Some(FeeOverrides {
                max_fee: 7,
                max_priority_fee: 7,
            }))
        );
    }

    #[test]
    fn u256_to_u128_boundary() {
        assert_eq!(u256_to_u128(U256::from(u128::MAX), "f").unwrap(), u128::MAX);
        assert!(u256_to_u128(U256::from(u128::MAX) + U256::from(1u64), "f").is_err());
        assert_eq!(u256_to_u128(U256::ZERO, "f").unwrap(), 0u128);
    }

    #[test]
    fn boundary_rejects_oversized_calldata_and_absurd_gas_limit() {
        let config = test_config();
        let mut big = tx_request();
        big.data = alloy::primitives::Bytes::from(vec![0u8; MAX_CALLDATA_BYTES + 1]);
        let err = validate_broadcast_request(&big, &config).unwrap_err();
        assert_eq!(err.error_code.as_deref(), Some("INVALID_REQUEST"));
        assert!(err.error.as_deref().unwrap_or("").contains("data is"));

        let mut at_cap = tx_request();
        at_cap.data = alloy::primitives::Bytes::from(vec![0u8; MAX_CALLDATA_BYTES]);
        assert!(
            validate_broadcast_request(&at_cap, &config).is_ok(),
            "cap is inclusive"
        );

        let mut zero_gas = tx_request();
        zero_gas.gas_limit = Some(0);
        let err = validate_broadcast_request(&zero_gas, &config).unwrap_err();
        assert!(err.error.as_deref().unwrap_or("").contains("gasLimit"));

        let mut huge_gas = tx_request();
        huge_gas.gas_limit = Some(MAX_GAS_LIMIT + 1);
        let err = validate_broadcast_request(&huge_gas, &config).unwrap_err();
        assert!(
            err.error
                .as_deref()
                .unwrap_or("")
                .contains("exceeds maximum")
        );

        let mut max_gas = tx_request();
        max_gas.gas_limit = Some(MAX_GAS_LIMIT);
        assert!(validate_broadcast_request(&max_gas, &config).is_ok());
    }

    #[test]
    fn verify_signature_accepts_low_s_from_the_right_key_and_rejects_the_wrong_key() {
        use alloy::signers::{SignerSync, local::PrivateKeySigner};
        let signer = PrivateKeySigner::random();
        let other = PrivateKeySigner::random();
        let hash = B256::repeat_byte(0x42);
        let sig = signer.sign_hash_sync(&hash).unwrap();

        let ok = verify_signature(&sig, hash, signer.address()).expect("valid");
        assert_eq!(ok, sig, "already-canonical signature is returned unchanged");

        let err = verify_signature(&sig, hash, other.address()).unwrap_err();
        assert!(err.contains("recovers to"), "{err}");
    }

    #[test]
    fn verify_signature_canonicalizes_high_s() {
        use alloy::primitives::U256;
        use alloy::signers::{Signature, SignerSync, local::PrivateKeySigner};
        // secp256k1 group order.
        let n = U256::from_str_radix(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .unwrap();
        let signer = PrivateKeySigner::random();
        let hash = B256::repeat_byte(0x07);
        let low = signer.sign_hash_sync(&hash).unwrap();
        // Forge the malleable twin: s' = n - s, parity flipped. Still recovers to the key.
        let high = Signature::new(low.r(), n - low.s(), !low.v());
        assert!(high.s() > n >> 1, "test setup: twin must be high-s");

        let out = verify_signature(&high, hash, signer.address()).expect("high-s is canonicalized");
        assert_eq!(out.s(), low.s(), "s normalized to the low half");
        assert_eq!(out.v(), low.v(), "parity flipped back");
    }

    #[test]
    fn redact_urls_strips_provider_keys_but_keeps_the_message() {
        let msg = "error sending request for url (https://eth-mainnet.g.alchemy.com/v2/SECRETKEY): timed out";
        assert_eq!(
            redact_urls(msg),
            "error sending request for url (<redacted-url>): timed out"
        );
        assert_eq!(
            redact_urls("ws wss://x.example/v2/K failed and http://y/z too"),
            "ws <redacted-url> failed and <redacted-url> too"
        );
        // Node-side JSON-RPC messages have no URL and pass through untouched.
        let node = "server returned an error response: error code 3: execution reverted";
        assert_eq!(redact_urls(node), node);
        assert_eq!(redact_urls(""), "");
    }

    #[test]
    fn send_ack_with_matching_hash_is_accepted_and_marks_broadcast() {
        // The node acked the exact hash we signed: advance the tracker to BROADCAST.
        let local = B256::repeat_byte(0xaa);
        let outcome = classify_send_outcome(local, &Ok(local));
        assert_eq!(
            outcome,
            PostSend::Accepted {
                mark_broadcast: true
            }
        );
    }

    #[test]
    fn ambiguous_send_error_is_accepted_without_marking_broadcast() {
        // Requirement 4: a send timeout/error is recoverable, not a fresh retry. The
        // signed bytes are durable, so we accept and leave the tracker SIGNED (do NOT
        // mark broadcast) for the watcher to rebroadcast identical bytes.
        let local = B256::repeat_byte(0xbb);
        let outcome = classify_send_outcome(local, &Err("connection reset".to_string()));
        assert_eq!(
            outcome,
            PostSend::Accepted {
                mark_broadcast: false
            }
        );
    }

    #[test]
    fn already_known_send_error_is_accepted_and_marks_broadcast() {
        // The node already holds these exact bytes: an earlier attempt landed, so the
        // tracker advances to PENDING exactly as if this send had acked.
        let local = B256::repeat_byte(0xee);
        let outcome = classify_send_outcome(
            local,
            &Err("server returned an error response: error code -32000: already known".into()),
        );
        assert_eq!(
            outcome,
            PostSend::Accepted {
                mark_broadcast: true
            }
        );
    }

    #[test]
    fn definitive_node_rejection_is_rejected_not_accepted() {
        // N-H1: a refusal intrinsic to the bytes (funds/fees/gas/encoding) must never be
        // reported as success; the reason is carried so the caller sees the node's text.
        let local = B256::repeat_byte(0x11);
        for reason in [
            "insufficient funds for gas * price + value: have 0 want 21000",
            "max fee per gas less than block base fee",
            "intrinsic gas too low",
            "exceeds block gas limit",
        ] {
            let outcome = classify_send_outcome(local, &Err(reason.to_string()));
            assert_eq!(
                outcome,
                PostSend::Rejected {
                    reason: reason.to_string()
                },
                "{reason}"
            );
        }
    }

    #[test]
    fn nonce_too_low_and_occupancy_errors_stay_ambiguous() {
        // These are not definitive: the nonce may have been consumed by our own earlier
        // bytes, or the slot is occupied. Leave SIGNED for the watcher; never recycle.
        let local = B256::repeat_byte(0x12);
        for reason in [
            "nonce too low",
            "replacement transaction underpriced",
            "txpool is full",
            "nonce too high",
        ] {
            let outcome = classify_send_outcome(local, &Err(reason.to_string()));
            assert_eq!(
                outcome,
                PostSend::Accepted {
                    mark_broadcast: false
                },
                "{reason}"
            );
        }
    }

    #[test]
    fn send_ack_with_mismatched_hash_is_a_hash_mismatch() {
        // A node hash that disagrees with our local hash is an error, but the SIGNED
        // row stays durable for recovery — never released, never re-signed.
        let local = B256::repeat_byte(0xcc);
        let node = B256::repeat_byte(0xdd);
        let outcome = classify_send_outcome(local, &Ok(node));
        assert_eq!(outcome, PostSend::HashMismatch { node_hash: node });
    }
}
