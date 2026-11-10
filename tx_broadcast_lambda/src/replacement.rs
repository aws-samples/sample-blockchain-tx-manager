//! Dedicated internal replacement-worker path.
//!
//! The event contains identity + expected generation only. Policy and ceilings are reloaded
//! from DynamoDB and re-clamped against the deployment hard caps. Transaction intent for a
//! speed-up is taken from the active candidate's own signed bytes (decoded and
//! signer-recovered) and must agree with the family row, so a table writer such as the
//! watcher can never choose bytes, fees, or destination.

use crate::error::{LambdaError, Result};
use crate::fees::{estimate_live_fees, replacement_quote};
use crate::handler::{
    PostSend, classify_send_outcome, get_config, get_dynamo, get_rpc_provider, get_signer_provider,
    redact_urls, verify_signature,
};
use crate::tx::{
    TxParams, build_unsigned_tx, compute_local_tx_hash, encode_signed_tx, get_signing_hash,
};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::Provider;
use nonce_manager::{DynamoNonceManager, ExhaustionAction, NonceManagerConfig, ReplacementFamily};
use serde::Deserialize;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReplacementAction {
    SpeedUp,
    Cancel,
    Exhaust,
}

impl ReplacementAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::SpeedUp => "speedUp",
            Self::Cancel => "cancel",
            Self::Exhaust => "exhaust",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplacementMessage {
    pub wallet: Address,
    pub nonce: u64,
    pub expected_generation: u32,
    pub action: ReplacementAction,
}

pub async fn handle_sqs_event(
    payload: &serde_json::Value,
) -> std::result::Result<serde_json::Value, lambda_runtime::Error> {
    let records = payload
        .get("Records")
        .and_then(|v| v.as_array())
        .ok_or_else(|| lambda_runtime::Error::from("replacement worker requires an SQS event"))?;
    if records.len() != 1 {
        return Err(lambda_runtime::Error::from(format!(
            "replacement SQS event has {} records; batchSize=1 is required",
            records.len()
        )));
    }
    let body = records[0]
        .get("body")
        .and_then(|v| v.as_str())
        .ok_or_else(|| lambda_runtime::Error::from("replacement SQS record has no body"))?;
    let message: ReplacementMessage = serde_json::from_str(body)
        .map_err(|e| lambda_runtime::Error::from(format!("invalid replacement message: {e}")))?;
    process(message)
        .await
        .map_err(|e| lambda_runtime::Error::from(e.to_string()))?;
    Ok(serde_json::json!({"success": true}))
}

async fn process(message: ReplacementMessage) -> Result<()> {
    let config = get_config().await?;
    if !config.replacement_enabled {
        return Err(LambdaError::Config("replacement worker is disabled".into()));
    }
    let dynamo = get_dynamo().await?;
    let provider = get_rpc_provider(config)?;
    let manager = DynamoNonceManager::new(
        dynamo.clone(),
        config.dynamodb_table.as_str(),
        provider.clone(),
        config.chain_id,
        NonceManagerConfig::default(),
    );
    let Some(family) = manager
        .get_replacement_family(message.wallet, message.nonce)
        .await?
    else {
        warn!(wallet=?message.wallet, nonce=message.nonce, "Replacement family no longer exists");
        return Ok(());
    };

    if family.chain_id != config.chain_id
        || family.active_generation.saturating_add(1) != message.expected_generation
        || family.state != "ACTIVE"
    {
        info!(
            wallet=?message.wallet,
            nonce=message.nonce,
            expected_generation=message.expected_generation,
            active_generation=family.active_generation,
            state=%family.state,
            "Stale replacement message ignored"
        );
        return Ok(());
    }
    validate_action(&family, message.action)?;
    if message.action == ReplacementAction::Exhaust {
        manager
            .mark_replacement_exhausted(&family, "maximum replacement generations reached")
            .await?;
        emit_metric("ReplacementPolicyExhausted", &family, message.action);
        info!(
            nonce = family.nonce,
            "Replacement family exhausted under hold policy; no signature created"
        );
        return Ok(());
    }

    // Re-check chain truth immediately before signing. A queued request may be stale.
    if provider
        .get_transaction_receipt(family.active_hash)
        .await
        .map_err(|e| LambdaError::GasEstimationFailed(redact_urls(&e.to_string())))?
        .is_some()
    {
        manager
            .release_replacement_claim(family.wallet, family.nonce, message.expected_generation)
            .await?;
        info!(nonce=family.nonce, tx_hash=?family.active_hash, "Active candidate already has a receipt; replacement skipped");
        return Ok(());
    }
    let chain_nonce = provider
        .get_transaction_count(family.wallet)
        .block_id(BlockNumberOrTag::Latest.into())
        .await
        .map_err(|e| LambdaError::GasEstimationFailed(redact_urls(&e.to_string())))?;
    if chain_nonce > family.nonce {
        manager
            .release_replacement_claim(family.wallet, family.nonce, message.expected_generation)
            .await?;
        info!(
            nonce = family.nonce,
            chain_nonce, "Family nonce already consumed; replacement skipped"
        );
        return Ok(());
    }
    let current_block = provider
        .get_block_number()
        .await
        .map_err(|e| LambdaError::GasEstimationFailed(redact_urls(&e.to_string())))?;
    if current_block < family.next_eligible_block {
        manager
            .release_replacement_claim(family.wallet, family.nonce, message.expected_generation)
            .await?;
        info!(
            current_block,
            eligible = family.next_eligible_block,
            "Replacement message arrived before eligibility; skipped"
        );
        return Ok(());
    }

    let live = estimate_live_fees(
        provider.as_ref(),
        family.policy.fee_speed,
        config.fee_tip_floor_wei,
    )
    .await?;
    let quote = replacement_quote(
        family.policy.fee_speed,
        family.active_max_fee_per_gas,
        family.active_max_priority_fee_per_gas,
        live,
    );
    let (to, value, data, gas_limit) = match message.action {
        ReplacementAction::SpeedUp => {
            // Take the intent from the active candidate's own signed bytes, not from the
            // family row. The family row is writable by the watcher (table read/write for
            // nonce lifecycle), so a tampered `to`/`value`/`data` there would otherwise be
            // signed with the wallet's real key. The signed bytes cannot be forged without
            // that key: decoding them and recovering the signer authenticates the intent.
            let bytes = manager
                .get_signed_raw_tx(family.wallet, family.active_hash)
                .await?
                .ok_or_else(|| {
                    LambdaError::InvalidRequest(
                        "active replacement candidate has no signed bytes; refusing to sign".into(),
                    )
                })?;
            let intent = authenticate_intent(&bytes, &family).map_err(|reason| {
                error!(
                    nonce = family.nonce,
                    tx_hash = ?family.active_hash,
                    reason,
                    "Active candidate bytes do not authenticate the family intent; refusing to sign"
                );
                LambdaError::InvalidRequest(format!(
                    "replacement intent not authenticated: {reason}"
                ))
            })?;
            (intent.to, intent.value, intent.data, intent.gas_limit)
        }
        ReplacementAction::Cancel => (family.wallet, U256::ZERO, Bytes::new(), 21_000),
        ReplacementAction::Exhaust => unreachable!("handled before transaction construction"),
    };
    // Re-clamp stored policy against deployment hard limits at every signature.
    // The watcher has table write access for nonce lifecycle operations; a tampered
    // family row must never widen what this signer will authorize.
    if !within_effective_budget(
        quote.max_fee_per_gas,
        gas_limit,
        family.policy.max_fee_per_gas_wei,
        family.policy.max_total_fee_wei,
        config.hard_max_fee_per_gas_wei,
        config.hard_max_total_fee_wei,
    ) {
        let reason = "live replacement fees exceed the immutable family ceiling";
        manager.mark_replacement_exhausted(&family, reason).await?;
        emit_metric("ReplacementPolicyExhausted", &family, message.action);
        warn!(
            nonce = family.nonce,
            generation = message.expected_generation,
            reason,
            "Replacement policy exhausted before signing"
        );
        return Ok(());
    }

    let tx = build_unsigned_tx(&TxParams {
        chain_id: family.chain_id,
        nonce: family.nonce,
        to,
        value,
        data,
        gas_limit,
        max_fee_per_gas: quote.max_fee_per_gas,
        max_priority_fee_per_gas: quote.max_priority_fee_per_gas,
    });
    let signing_hash = get_signing_hash(&tx);
    let signer = get_signer_provider()
        .await?
        .get_signer_with_credentials(family.wallet, None)
        .await
        .map_err(|e| LambdaError::Signer(e.to_string()))?;
    let signature = signer
        .sign_hash(signing_hash)
        .await
        .map_err(|e| LambdaError::Signer(e.to_string()))?;
    let signature =
        verify_signature(&signature, signing_hash, family.wallet).map_err(LambdaError::Signer)?;
    let signed = encode_signed_tx(&tx, &signature);
    let new_hash = compute_local_tx_hash(&signed);

    if !manager
        .activate_replacement(
            &family,
            new_hash,
            &signed,
            quote.max_fee_per_gas,
            quote.max_priority_fee_per_gas,
            current_block,
            message.action.as_str(),
        )
        .await?
    {
        info!(
            nonce = family.nonce,
            generation = message.expected_generation,
            "Replacement generation already advanced; duplicate ignored"
        );
        return Ok(());
    }

    let send_result: std::result::Result<B256, String> = provider
        .send_raw_transaction(&signed)
        .await
        .map(|pending| *pending.tx_hash())
        .map_err(|e| redact_urls(&e.to_string()));
    match classify_send_outcome(new_hash, &send_result) {
        PostSend::Accepted { mark_broadcast } => {
            if mark_broadcast {
                manager
                    .mark_broadcast(family.wallet, family.nonce, new_hash)
                    .await?;
            }
        }
        PostSend::Rejected { reason } => {
            // Never recycle a replacement nonce: an earlier candidate may still mine.
            // Leave the new exact bytes durable and let the watcher request another
            // generation at the next eligible block.
            warn!(nonce=family.nonce, tx_hash=?new_hash, %reason, "Replacement send refused; family remains recoverable");
        }
        PostSend::HashMismatch { node_hash } => {
            error!(nonce=family.nonce, local=?new_hash, node=?node_hash, "Replacement node hash mismatch; exact bytes remain SIGNED");
        }
    }
    emit_metric("ReplacementBroadcast", &family, message.action);
    info!(
        nonce=family.nonce,
        generation=message.expected_generation,
        tx_hash=?new_hash,
        action=message.action.as_str(),
        "Dynamic replacement signed and submitted"
    );
    Ok(())
}

/// Transaction intent recovered from a candidate's signed bytes.
#[derive(Debug, PartialEq, Eq)]
struct AuthenticatedIntent {
    to: Address,
    value: U256,
    data: Bytes,
    gas_limit: u64,
}

/// Decode the active candidate's signed bytes and prove they carry the family's intent.
///
/// Checks, in order: the bytes hash to `family.active_hash`; they decode as an EIP-1559
/// transaction; the recovered signer is `family.wallet`; nonce and chain id match the
/// family; the call target is a plain address; and the decoded `to`/`value`/`data`/
/// `gas_limit` equal what the family row claims. The last check turns a tampered family
/// row into a refusal instead of a silently different transaction.
fn authenticate_intent(
    bytes: &[u8],
    family: &ReplacementFamily,
) -> std::result::Result<AuthenticatedIntent, String> {
    use alloy::consensus::{Transaction, TxEnvelope};
    use alloy::eips::eip2718::Decodable2718;
    use alloy::primitives::TxKind;

    if compute_local_tx_hash(bytes) != family.active_hash {
        return Err("signed bytes do not hash to the active candidate".into());
    }
    let envelope = TxEnvelope::decode_2718(&mut &bytes[..])
        .map_err(|e| format!("signed bytes do not decode: {e}"))?;
    let TxEnvelope::Eip1559(signed) = envelope else {
        return Err("active candidate is not an EIP-1559 transaction".into());
    };
    let signer = signed
        .recover_signer()
        .map_err(|e| format!("signer recovery failed: {e}"))?;
    if signer != family.wallet {
        return Err("signed bytes were not produced by the family wallet".into());
    }
    let tx = signed.tx();
    if tx.nonce != family.nonce {
        return Err("signed bytes carry a different nonce".into());
    }
    if tx.chain_id != family.chain_id {
        return Err("signed bytes carry a different chain id".into());
    }
    let TxKind::Call(to) = tx.to else {
        return Err("active candidate is a contract creation".into());
    };
    let intent = AuthenticatedIntent {
        to,
        value: tx.value,
        data: tx.input.clone(),
        gas_limit: tx.gas_limit(),
    };
    let claimed = AuthenticatedIntent {
        to: family.to,
        value: family.value,
        data: family.data.clone(),
        gas_limit: family.gas_limit,
    };
    if intent != claimed {
        return Err("family row intent differs from the signed candidate".into());
    }
    Ok(intent)
}

fn within_effective_budget(
    max_fee_per_gas: u128,
    gas_limit: u64,
    stored_per_gas_ceiling: u128,
    stored_total_ceiling: U256,
    deployment_per_gas_ceiling: u128,
    deployment_total_ceiling: U256,
) -> bool {
    max_fee_per_gas <= stored_per_gas_ceiling.min(deployment_per_gas_ceiling)
        && U256::from(gas_limit) * U256::from(max_fee_per_gas)
            <= stored_total_ceiling.min(deployment_total_ceiling)
}

fn validate_action(family: &ReplacementFamily, action: ReplacementAction) -> Result<()> {
    match action {
        ReplacementAction::SpeedUp if family.active_generation >= family.policy.max_bumps => Err(
            LambdaError::InvalidRequest("speed-up generation exceeds immutable maxBumps".into()),
        ),
        ReplacementAction::Cancel
            if family.policy.on_exhaust != ExhaustionAction::Cancel
                || family.active_generation < family.policy.max_bumps =>
        {
            Err(LambdaError::InvalidRequest(
                "cancel is not authorized by the immutable exhaustion policy".into(),
            ))
        }
        _ => Ok(()),
    }
}

fn emit_metric(name: &str, family: &ReplacementFamily, action: ReplacementAction) {
    println!(
        "{}",
        serde_json::json!({
            "_aws": {
                "Timestamp": chrono::Utc::now().timestamp_millis(),
                "CloudWatchMetrics": [{
                    "Namespace": "TxManager/Replacement",
                    "Dimensions": [["ChainId"]],
                    "Metrics": [{"Name": name, "Unit": "Count"}]
                }]
            },
            "ChainId": family.chain_id.to_string(),
            "Action": action.as_str(),
            "Generation": family.active_generation.saturating_add(1),
            name: 1
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use nonce_manager::{FeeSpeed, ResolvedReplacementPolicy};

    fn family(generation: u32, max_bumps: u32, on_exhaust: ExhaustionAction) -> ReplacementFamily {
        ReplacementFamily {
            wallet: Address::repeat_byte(1),
            nonce: 7,
            chain_id: 1,
            to: Address::repeat_byte(2),
            value: U256::from(3),
            data: Bytes::new(),
            gas_limit: 21_000,
            policy: ResolvedReplacementPolicy {
                fee_speed: FeeSpeed::Standard,
                bump_every_blocks: 5,
                max_bumps,
                on_exhaust,
                max_fee_per_gas_wei: 1_000,
                max_total_fee_wei: U256::from(21_000_000u64),
            },
            active_generation: generation,
            active_hash: B256::repeat_byte(3),
            active_max_fee_per_gas: 100,
            active_max_priority_fee_per_gas: 10,
            next_eligible_block: 100,
            state: "ACTIVE".into(),
        }
    }

    /// Sign a real EIP-1559 transaction with a throwaway key and return the family that
    /// legitimately describes it, plus the signed bytes.
    fn signed_family() -> (ReplacementFamily, Vec<u8>) {
        use crate::tx::{TxParams, build_unsigned_tx, encode_signed_tx, get_signing_hash};
        use alloy::signers::SignerSync;
        use alloy::signers::local::PrivateKeySigner;

        let key = PrivateKeySigner::random();
        let mut fam = family(0, 3, ExhaustionAction::Hold);
        fam.wallet = key.address();
        let tx = build_unsigned_tx(&TxParams {
            chain_id: fam.chain_id,
            nonce: fam.nonce,
            to: fam.to,
            value: fam.value,
            data: fam.data.clone(),
            gas_limit: fam.gas_limit,
            max_fee_per_gas: fam.active_max_fee_per_gas,
            max_priority_fee_per_gas: fam.active_max_priority_fee_per_gas,
        });
        let sig = key.sign_hash_sync(&get_signing_hash(&tx)).unwrap();
        let bytes = encode_signed_tx(&tx, &sig).to_vec();
        fam.active_hash = compute_local_tx_hash(&bytes);
        (fam, bytes)
    }

    #[test]
    fn authenticated_intent_matches_the_signed_candidate() {
        let (fam, bytes) = signed_family();
        let intent = authenticate_intent(&bytes, &fam).expect("legitimate family authenticates");
        assert_eq!(intent.to, fam.to);
        assert_eq!(intent.value, fam.value);
        assert_eq!(intent.gas_limit, fam.gas_limit);
    }

    #[test]
    fn tampered_family_row_is_refused() {
        // A table writer rewrites the family's destination and amount. The signed bytes
        // still describe the original transfer, so the mismatch must refuse to sign.
        let (mut fam, bytes) = signed_family();
        fam.to = Address::repeat_byte(0xee);
        fam.value = U256::from(1_000_000_000_000_000_000u128);
        let err = authenticate_intent(&bytes, &fam).unwrap_err();
        assert!(err.contains("differs from the signed candidate"), "{err}");
    }

    #[test]
    fn candidate_signed_by_another_key_is_refused() {
        let (mut fam, _) = signed_family();
        let (other, other_bytes) = signed_family();
        // Point the family at bytes that hash correctly but were signed by a different wallet.
        fam.active_hash = other.active_hash;
        let err = authenticate_intent(&other_bytes, &fam).unwrap_err();
        assert!(err.contains("not produced by the family wallet"), "{err}");
    }

    #[test]
    fn bytes_that_do_not_hash_to_the_active_candidate_are_refused() {
        let (fam, mut bytes) = signed_family();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let err = authenticate_intent(&bytes, &fam).unwrap_err();
        assert!(err.contains("do not hash"), "{err}");
    }

    #[test]
    fn speedup_stops_at_max_bumps() {
        assert!(
            validate_action(
                &family(2, 3, ExhaustionAction::Hold),
                ReplacementAction::SpeedUp
            )
            .is_ok()
        );
        assert!(
            validate_action(
                &family(3, 3, ExhaustionAction::Hold),
                ReplacementAction::SpeedUp
            )
            .is_err()
        );
    }

    #[test]
    fn cancel_requires_explicit_policy_and_exhaustion() {
        assert!(
            validate_action(
                &family(3, 3, ExhaustionAction::Cancel),
                ReplacementAction::Cancel
            )
            .is_ok()
        );
        assert!(
            validate_action(
                &family(2, 3, ExhaustionAction::Cancel),
                ReplacementAction::Cancel
            )
            .is_err()
        );
        assert!(
            validate_action(
                &family(3, 3, ExhaustionAction::Hold),
                ReplacementAction::Cancel
            )
            .is_err()
        );
    }

    #[test]
    fn deployment_hard_caps_rebind_even_if_family_row_is_widened() {
        assert!(!within_effective_budget(
            501,
            21_000,
            10_000,
            U256::from(1_000_000_000u64),
            500,
            U256::from(1_000_000_000u64),
        ));
        assert!(!within_effective_budget(
            100,
            21_000,
            10_000,
            U256::from(1_000_000_000u64),
            500,
            U256::from(2_000_000u64),
        ));
        assert!(within_effective_budget(
            100,
            21_000,
            10_000,
            U256::from(1_000_000_000u64),
            500,
            U256::from(3_000_000u64),
        ));
    }

    #[test]
    fn message_rejects_untrusted_extra_fields() {
        let json = r#"{"wallet":"0x0101010101010101010101010101010101010101","nonce":1,"expectedGeneration":1,"action":"speedUp","to":"0x0202020202020202020202020202020202020202"}"#;
        assert!(serde_json::from_str::<ReplacementMessage>(json).is_err());
    }
}
