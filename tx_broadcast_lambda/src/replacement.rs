//! Dedicated internal replacement-worker path.
//!
//! The event contains identity + expected generation only. Transaction content, policy,
//! and ceilings are reloaded from DynamoDB; the watcher can never choose bytes or fees.

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
        ReplacementAction::SpeedUp => (
            family.to,
            family.value,
            family.data.clone(),
            family.gas_limit,
        ),
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
